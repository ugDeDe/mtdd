// Masking relay target selection (automatic SNI fronting), in priority
// order:
//   1. Explicitly configured destination (fallback_host/fallback_port) —
//      byte relay there, preserving the historical behavior for deployments
//      that pin a fixed backend.
//   2. Otherwise: a probe whose SNI matches the configured FakeTLS domain
//      (or a subdomain of it) is relayed to the real server of that name on
//      443, so active probes receive a genuine certificate for the covered
//      name.
//   3. Otherwise the probe is closed.
// This is deliberately a byte relay, not a TLS/HTTP implementation.
#include "internal.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace mtdd {

namespace {

std::string to_lower(std::string_view text) {
    std::string out(text);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool sni_domain_matches(std::string_view sni, std::string_view domain) {
    auto name = to_lower(sni);
    auto covered = to_lower(domain);
    if (!name.empty() && name.back() == '.') name.pop_back();
    if (!covered.empty() && covered.back() == '.') covered.pop_back();
    if (covered.empty()) return false;
    return name == covered ||
           (name.size() > covered.size() &&
            name.compare(name.size() - covered.size() - 1, covered.size() + 1,
                         "." + covered) == 0);
}

}  // namespace

bool Runtime::Impl::fallback_enabled() const noexcept { return config_.fallback_port != 0; }

bool Runtime::Impl::masking_enabled() const noexcept {
    // Explicit fixed target also arms the probe path, even with auto-SNI off.
    return config_.masking || fallback_enabled();
}

bool Runtime::Impl::append_fallback_bytes(Client& client, io::ByteQueue& queue,
                                          std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return true;
    if (bytes.size() > queue.max_bytes() - queue.bytes()) return false;
    const auto status = queue.append(bytes);
    if (status != io::AppendStatus::ok) {
        const bool c2b = client.c2b && &queue == &*client.c2b;
        stats_.add_backpressure(c2b ? control::Direction::client_to_server
                                    : control::Direction::server_to_client);
        reaccount(client);
        close_client(client.token);
        return false;
    }
    reaccount(client);
    return true;
}

std::string Runtime::Impl::ensure_fallback_address(Time now, std::string_view host) {
    // Literal addresses (the historical loopback backend) bypass DNS entirely.
    if (io::is_numeric_address(host)) return std::string(host);
    const bool fresh = fallback_cache_host_ == host && !fallback_address_.empty() &&
                       now - fallback_resolved_at_ < detail::kFallbackResolveTtl;
    if (!fresh) {
        const auto resolved = io::resolve_numeric_host(host);
        if (!resolved) return {};
        fallback_cache_host_ = std::string(host);
        fallback_address_ = *resolved;
        fallback_resolved_at_ = now;
    }
    return fallback_address_;
}

bool Runtime::Impl::start_fallback(Client& client, std::span<const std::uint8_t> prefetched,
                                   Time now) {
    if (!masking_enabled()) return false;
    if (client.phase == Client::Phase::fallback) return true;

    const std::size_t c2b_capacity =
        std::max(config_.connection_queue_bytes, protocol::kFakeTlsMaxClientHello + 64U);
    if (!client.c2b) {
        client.c2b.emplace(c2b_capacity);
    }
    if (!prefetched.empty()) {
        if (!budget_allows(prefetched.size() + 1024U) ||
            prefetched.size() > client.c2b->max_bytes()) {
            close_client(client.token);
            return true;
        }
        const auto status = client.c2b->append(prefetched);
        if (status != io::AppendStatus::ok) {
            reaccount(client);
            close_client(client.token);
            return true;
        }
    }
    reaccount(client); // account the c2b capacity before any failure close
    client.phase = Client::Phase::fallback;
    client.last_activity = now;
    // Fallback is not a FakeTLS success and never creates a user session. It
    // does release the bounded handshake slot exactly once.
    record_handshake(client, control::HandshakeResult::failure);
    client.hello.clear();
    client.hello.shrink_to_fit();
    reaccount(client);

    client.backend_token = add_target(Target{Kind::fallback_backend, nullptr, client.token});
    std::vector<std::pair<std::string, std::uint16_t>> targets;
    if (fallback_enabled()) {
        targets.emplace_back(ensure_fallback_address(now, config_.fallback_host),
                             config_.fallback_port);
    } else if (config_.masking) {
        const auto sni = protocol::client_hello_sni(prefetched);
        if (sni && sni_domain_matches(*sni, config_.tls_domain)) {
            targets.emplace_back(*sni, 443U);
            if (to_lower(*sni) != to_lower(config_.tls_domain)) {
                targets.emplace_back(config_.tls_domain, 443U);
            }
        }
    }
    if (targets.empty()) {
        if (client.watched) watch_log(client, "masking", "target=none");
        close_client(client.token);
        return true;
    }
    auto connected = io::FdResult{};
    bool dialled = false;
    for (const auto& [host, port] : targets) {
        const std::string address = ensure_fallback_address(now, host);
        if (address.empty()) continue;
        auto attempt = io::connect_tcp(address, port);
        if (client.watched) {
            watch_log(client, "masking", "target=" + host + ":" + std::to_string(port) +
                                             (attempt.ok() ? "" : " connect_failed"));
        }
        if (attempt.ok()) {
            connected = std::move(attempt);
            dialled = true;
            break;
        }
    }
    if (!dialled) {
        close_client(client.token);
        return true;
    }
    client.backend = std::move(connected.fd);
    client.backend_connecting = true;
    client.deadline_kind = Client::DeadlineKind::fallback_connect;
    deadlines_.set(client.backend_token, now + config_.handshake_timeout);
    client.fallback_tracked = true;
    fallback_clients_.push_back(client.token);
    reaccount(client);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
    if (!connected.in_progress) on_fallback_connected(client, now);
    return true;
}

void Runtime::Impl::update_fallback_client_interest(Client& client) {
    if (client.token == 0 || !client.fd.valid()) return;
    std::uint32_t desired = 0;
    const bool source_room = client.c2b && client.c2b->bytes() < client.c2b->max_bytes();
    if (!client.read_eof && !client.draining && !client.budget_paused &&
        !client.close_requested && source_room) {
        desired |= EPOLLIN;
    }
    if (!client.fin_pending && !client.read_eof) desired |= EPOLLRDHUP;
    if (client.out && !client.out->empty()) desired |= EPOLLOUT;
    set_interest(client.token, client.fd.get(), client.armed, desired);
}

void Runtime::Impl::update_fallback_backend_interest(Client& client) {
    if (client.backend_token == 0 || !client.backend.valid()) return;
    std::uint32_t desired = 0;
    if (client.backend_connecting) {
        desired |= EPOLLOUT;
    } else {
        const bool room = client.out && client.out->bytes() < client.out->max_bytes();
        if (!client.backend_eof && !client.backend_budget_paused && room) desired |= EPOLLIN;
        if (!client.backend_fin_pending && !client.backend_eof) desired |= EPOLLRDHUP;
    }
    if (client.c2b && !client.c2b->empty()) desired |= EPOLLOUT;
    set_interest(client.backend_token, client.backend.get(), client.backend_armed, desired);
}

void Runtime::Impl::on_fallback_connected(Client& client, Time now) {
    if (!client.backend.valid()) {
        close_client(client.token);
        return;
    }
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(client.backend.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
        error != 0) {
        close_client(client.token);
        return;
    }
    client.backend_connecting = false;
    client.last_activity = now;
    // The fallback backend carries the same small MTProto records as the ME
    // route; Nagle would add the same avoidable latency here.
    (void)io::set_tcp_nodelay(client.backend.get());
    (void)io::set_tcp_keepalive(client.backend.get());
    client.deadline_kind = Client::DeadlineKind::fallback_idle;
    deadlines_.set(client.backend_token, now + config_.idle_timeout);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
    pump_fallback_c2b(client);
    if (clients_.find(client.token) != clients_.end()) pump_fallback_b2c(client);
}

void Runtime::Impl::read_fallback_client(Client& client, Time now) {
    if (client.draining || client.budget_paused || client.read_eof || client.close_requested) return;
    if (!client.c2b) return;
    if (!budget_allows(detail::kClientReadReservation)) {
        client.budget_paused = true;
        paused_clients_.push_back(client.token);
        stats_.add_backpressure(control::Direction::client_to_server);
        update_fallback_client_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    while (total < detail::kReadBatch) {
        const std::size_t room = client.c2b->max_bytes() - client.c2b->bytes();
        if (room == 0) {
            stats_.add_backpressure(control::Direction::client_to_server);
            break;
        }
        const std::size_t limit = std::min(detail::kReadBatch - total, room);
        const ssize_t received = ::recv(client.fd.get(), read_buffer_.data(), limit, MSG_DONTWAIT);
        if (received > 0) {
            const auto bytes = static_cast<std::size_t>(received);
            total += bytes;
            touch(client, now);
            if (!append_fallback_bytes(
                    client, *client.c2b,
                    std::span<const std::uint8_t>(read_buffer_).first(bytes))) {
                return;
            }
        } else if (received == 0) {
            client.read_eof = true;
            client.read_eof_at = now;
            client.fin_pending = true;
            update_fallback_client_interest(client);
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            close_client(token);
            return;
        }
    }
    reaccount(client);
    update_fallback_client_interest(client);
    pump_fallback_c2b(client);
}

void Runtime::Impl::read_fallback_backend(Client& client, Time now) {
    if (client.backend_connecting || client.backend_eof) return;
    if (!client.out) return;
    if (!budget_allows(detail::kClientReadReservation)) {
        if (!client.backend_budget_paused) {
            client.backend_budget_paused = true;
            paused_clients_.push_back(client.token);
        }
        stats_.add_backpressure(control::Direction::server_to_client);
        update_fallback_backend_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    while (total < detail::kReadBatch) {
        const std::size_t room = client.out->max_bytes() - client.out->bytes();
        if (room == 0) {
            stats_.add_backpressure(control::Direction::server_to_client);
            break;
        }
        const std::size_t limit = std::min(detail::kReadBatch - total, room);
        const ssize_t received = ::recv(client.backend.get(), read_buffer_.data(), limit,
                                        MSG_DONTWAIT);
        if (received > 0) {
            const auto bytes = static_cast<std::size_t>(received);
            total += bytes;
            touch(client, now);
            if (!append_fallback_bytes(
                    client, *client.out,
                    std::span<const std::uint8_t>(read_buffer_).first(bytes))) {
                return;
            }
        } else if (received == 0) {
            client.backend_eof = true;
            client.backend_fin_pending = true;
            update_fallback_backend_interest(client);
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            close_client(token);
            return;
        }
    }
    reaccount(client);
    update_fallback_backend_interest(client);
    pump_fallback_b2c(client);
}

void Runtime::Impl::pump_fallback_c2b(Client& client) {
    const std::uint64_t token = client.token;
    if (client.backend.valid() && !client.backend_connecting && client.c2b) {
        while (!client.c2b->empty()) {
            const auto result = client.c2b->flush_to(client.backend.get(), detail::kWriteBatch);
            if (result.status == io::FlushStatus::error) {
                close_client(token);
                return;
            }
            if (result.bytes_written > 0) touch(client, Clock::now());
            if (result.status != io::FlushStatus::drained) break;
        }
        if (client.c2b->empty() && client.read_eof && !client.backend_write_shutdown) {
            ::shutdown(client.backend.get(), SHUT_WR);
            client.backend_write_shutdown = true;
        }
    }
    reaccount(client);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
}

void Runtime::Impl::pump_fallback_b2c(Client& client) {
    const std::uint64_t token = client.token;
    if (client.out && client.fd.valid()) {
        while (!client.out->empty()) {
            const auto result = client.out->flush_to(client.fd.get(), detail::kWriteBatch);
            if (result.status == io::FlushStatus::error) {
                close_client(token);
                return;
            }
            if (result.bytes_written > 0) touch(client, Clock::now());
            if (result.status != io::FlushStatus::drained) break;
        }
        if (client.out->empty() && client.backend_eof && !client.client_write_shutdown) {
            ::shutdown(client.fd.get(), SHUT_WR);
            client.client_write_shutdown = true;
        }
    }
    reaccount(client);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
}

void Runtime::Impl::handle_fallback_client(Client& client, std::uint32_t events, Time now) {
    const std::uint64_t token = client.token;
    if ((events & EPOLLERR) != 0) {
        close_client(token);
        return;
    }
    const bool client_hup = (events & EPOLLHUP) != 0;
    // HUP can arrive together with the last readable bytes. Drain first; a full
    // HUP means the client is gone, so the pair is closed after that drain.
    if ((events & (EPOLLIN | EPOLLHUP)) != 0) {
        read_fallback_client(client, now);
        if (clients_.find(token) == clients_.end()) return;
    }
    if (client_hup) {
        close_client(token);
        return;
    }
    if ((events & EPOLLRDHUP) != 0) {
        client.fin_pending = true;
        client.fin_at = now;
        update_fallback_client_interest(client);
    }
    if ((events & EPOLLOUT) != 0) {
        pump_fallback_b2c(client);
        if (clients_.find(token) == clients_.end()) return;
        pump_fallback_c2b(client);
    }
}

void Runtime::Impl::handle_fallback_backend(Client& client, std::uint32_t events, Time now) {
    const std::uint64_t token = client.token;
    if ((events & EPOLLERR) != 0) {
        close_client(token);
        return;
    }
    if (client.backend_connecting) {
        if ((events & EPOLLHUP) != 0) {
            close_client(token);
            return;
        }
        if ((events & EPOLLOUT) != 0) on_fallback_connected(client, now);
        return;
    }
    const bool backend_hup = (events & EPOLLHUP) != 0;
    if ((events & (EPOLLIN | EPOLLHUP)) != 0) {
        read_fallback_backend(client, now);
        if (clients_.find(token) == clients_.end()) return;
    }
    if (backend_hup) {
        // Backend fully closed: keep the client pair only long enough to flush
        // the already-read B2C bytes, then close. This avoids a level-triggered
        // HUP spin and an unbounded retained pair.
        client.backend_eof = true;
        close_fallback_backend(client);
        client.deadline_kind = Client::DeadlineKind::fallback_idle;
        deadlines_.set(client.token, now + config_.idle_timeout);
        pump_fallback_b2c(client);
        return;
    }
    if ((events & EPOLLRDHUP) != 0) {
        client.backend_fin_pending = true;
        client.backend_fin_at = now;
        update_fallback_backend_interest(client);
    }
    if ((events & EPOLLOUT) != 0) pump_fallback_c2b(client);
}

void Runtime::Impl::close_fallback_backend(Client& client) {
    if (client.backend_token == 0 && !client.backend.valid()) return;
    deadlines_.erase(client.backend_token);
    if (client.backend.valid()) {
        set_interest(client.backend_token, client.backend.get(), client.backend_armed, 0);
    }
    remove_target(client.backend_token);
    client.backend.close();
    client.backend_token = 0;
    client.backend_armed = 0;
    client.backend_connecting = false;
    client.backend_eof = true;
}

void Runtime::Impl::on_fallback_deadline(Client& client, Time now) {
    if (client.deadline_kind == Client::DeadlineKind::fallback_connect) {
        close_client(client.token);
        return;
    }
    if (client.deadline_kind != Client::DeadlineKind::fallback_idle) return;
    const auto idle = config_.idle_timeout;
    if (now - client.last_activity >= idle) {
        close_client(client.token);
    } else {
        const std::uint64_t token =
            client.backend_token != 0 ? client.backend_token : client.token;
        deadlines_.set(token, client.last_activity + idle);
    }
}

void Runtime::Impl::finish_fallback_pairs(Time now) {
    if (fallback_clients_.empty()) return;
    std::vector<std::uint64_t>& remaining = fallback_remaining_;
    remaining.clear();
    for (const std::uint64_t token : fallback_clients_) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        if (client.phase != Client::Phase::fallback) continue;
        if (client.fin_pending && !client.read_eof &&
            now >= client.fin_at + config_.shutdown_timeout) {
            stats_.add_backpressure(control::Direction::client_to_server);
            stats_.connection_rejected(control::RejectReason::other);
            close_client(token);
            continue;
        }
        if (client.backend_fin_pending && !client.backend_eof &&
            now >= client.backend_fin_at + config_.shutdown_timeout) {
            stats_.add_backpressure(control::Direction::server_to_client);
            stats_.connection_rejected(control::RejectReason::other);
            close_client(token);
            continue;
        }
        pump_fallback_c2b(client);
        if (clients_.find(token) == clients_.end()) continue;
        pump_fallback_b2c(*clients_.find(token)->second);
        if (clients_.find(token) == clients_.end()) continue;
        const bool c2b_empty = !client.c2b || client.c2b->empty();
        const bool b2c_empty = !client.out || client.out->empty();
        const bool backend_gone = !client.backend.valid();
        const bool done =
            b2c_empty && ((client.read_eof && client.backend_eof && c2b_empty) || backend_gone);
        if (done || client.close_requested || (stopping_ && now >= shutdown_deadline_)) {
            close_client(token);
        } else {
            remaining.push_back(token);
        }
    }
    fallback_clients_.swap(remaining);
    remaining.clear();
}

} // namespace mtdd

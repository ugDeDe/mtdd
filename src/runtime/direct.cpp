// Opt-in Direct Telegram DC fallback for authenticated clients.
//
// This is NOT the raw-TLS Caddy fallback in fallback.cpp. It speaks Telegram's
// obfuscated2 TCP transport to a trusted official DC address, decodes the
// intermediate transport, and re-frames responses into the client's padded
// intermediate (Secure) FakeTLS session. The client's FakeTLS/auth/replay path
// is unchanged. Direct routes cannot carry the MTProxy ad-tag.
#include "internal.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mtdd {
namespace {

struct DirectEndpoint {
    std::int16_t dc;
    const char* host;
};

// Official Telegram DC IPv4 addresses, from TDLib
// td/telegram/net/ConnectionCreator.cpp (production branch): DC1..5 on ports
// {443,80,5222}. Negative media DCs -1..-5 use the same IP with the signed DC
// carried in the obfuscated2 header. No CDN 203 mapping is provided.
constexpr std::array<DirectEndpoint, 5> kDirectEndpoints{{
    {1, "149.154.175.50"},
    {2, "149.154.167.51"},
    {3, "149.154.175.100"},
    {4, "149.154.167.91"},
    {5, "149.154.171.5"},
}};

const char* direct_host(std::int16_t dc) {
    const int abs_dc = dc < 0 ? -static_cast<int>(dc) : static_cast<int>(dc);
    for (const auto& endpoint : kDirectEndpoints) {
        if (endpoint.dc == abs_dc) return endpoint.host;
    }
    return nullptr;
}

std::mutex g_direct_override_mutex;
std::optional<detail::DirectEndpointOverride> g_direct_override;

// Resolves the compiled official table, or the installed local test override.
bool direct_target(std::int16_t dc, std::string& host, std::uint16_t& port) {
    {
        std::lock_guard<std::mutex> lock(g_direct_override_mutex);
        if (g_direct_override) {
            if (direct_host(dc) == nullptr) return false;
            host = g_direct_override->host;
            port = g_direct_override->port;
            return true;
        }
    }
    const char* compiled = direct_host(dc);
    if (compiled == nullptr) return false;
    host = compiled;
    port = 443;
    return true;
}

void put_u16(std::uint8_t* out, std::uint16_t value) {
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
}

} // namespace

namespace detail {

void set_direct_endpoint_override(std::optional<DirectEndpointOverride> value) {
    std::lock_guard<std::mutex> lock(g_direct_override_mutex);
    g_direct_override = std::move(value);
}

namespace {
std::atomic<int> g_direct_event_throw{0};
} // namespace

void set_direct_event_throw_for_test(int count) {
    g_direct_event_throw.store(count, std::memory_order_relaxed);
}

bool consume_direct_event_throw_for_test() {
    int current = g_direct_event_throw.load(std::memory_order_relaxed);
    while (current > 0) {
        if (g_direct_event_throw.compare_exchange_weak(current, current - 1,
                                                       std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

DirectDrainTelemetry& direct_drain_telemetry() noexcept {
    static DirectDrainTelemetry telemetry;
    return telemetry;
}

} // namespace detail

bool Runtime::Impl::direct_route_enabled(std::int16_t dc) const noexcept {
    if (!config_.direct_fallback_enabled) return false;
    if (direct_host(dc) == nullptr) return false;
    return std::find(config_.direct_fallback_dcs.begin(),
                     config_.direct_fallback_dcs.end(),
                     dc) != config_.direct_fallback_dcs.end();
}

bool Runtime::Impl::start_direct(Client& client, std::int16_t dc, Time now) {
    std::string host;
    std::uint16_t port = 443;
    if (!direct_target(dc, host, port)) {
        ++direct_connect_fail_[dc];
        close_client(client.token);
        return false;
    }
    client.route = Client::Route::direct;
    client.route_dc = dc;
    try {
        client.direct_out.emplace(config_.connection_queue_bytes);
    } catch (const std::exception&) {
        ++direct_connect_fail_[dc];
        close_client(client.token);
        return false;
    }

    // Standard obfuscated2 for a direct DC (TDLib ObfuscatedTransport):
    // raw 32-byte key, no MTProxy secret/SHA-256. The tag is padded
    // intermediate (0xdddddddd) because the client's authenticated
    // padded-intermediate bytes are relayed verbatim; the signed DC travels in
    // bytes 60..61.
    std::array<std::uint8_t, 64> header{};
    for (int attempt = 0; attempt < 8; ++attempt) {
        random_(header);
        if (header[0] == 0xef) continue;
        const std::uint32_t first = static_cast<std::uint32_t>(header[0]) |
                                    (static_cast<std::uint32_t>(header[1]) << 8) |
                                    (static_cast<std::uint32_t>(header[2]) << 16) |
                                    (static_cast<std::uint32_t>(header[3]) << 24);
        if (first == 0x44414548U || first == 0x54534f50U || first == 0x20544547U ||
            first == 0x4954504fU || first == 0xddddddddU || first == 0xeeeeeeeeU ||
            first == 0x02010316U) {
            continue;
        }
        break;
    }
    // Padded intermediate: the client's Secure FakeTLS plaintext is already
    // padded-intermediate framing, so relay it verbatim instead of decoding and
    // re-framing (which would corrupt encrypted lengths/CRC/padding).
    header[56] = 0xdd;
    header[57] = 0xdd;
    header[58] = 0xdd;
    header[59] = 0xdd;
    put_u16(header.data() + 60, static_cast<std::uint16_t>(dc));
    header[62] = 0;
    header[63] = 0;

    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> iv{};
    std::copy_n(header.begin() + 8, 32, key.begin());
    std::copy_n(header.begin() + 40, 16, iv.begin());
    client.direct_encrypt = std::make_unique<protocol::crypto::AesCtr>(key, iv);

    std::array<std::uint8_t, 32> read_key{};
    std::array<std::uint8_t, 16> read_iv{};
    for (std::size_t i = 0; i < 32; ++i) read_key[i] = header[63 - 8 - i];
    for (std::size_t i = 0; i < 16; ++i) read_iv[i] = header[63 - 40 - i];
    client.direct_decrypt = std::make_unique<protocol::crypto::AesCtr>(read_key, read_iv);

    std::array<std::uint8_t, 64> encrypted = header;
    client.direct_encrypt->apply(encrypted);
    std::vector<std::uint8_t> wire(header.begin(), header.begin() + 56);
    wire.insert(wire.end(), encrypted.begin() + 56, encrypted.end());
    if (client.direct_out->append(wire) != io::AppendStatus::ok) {
        ++direct_connect_fail_[dc];
        close_client(client.token);
        return false;
    }

    client.direct_token =
        add_target(Target{Kind::direct_backend, nullptr, client.token});
    auto connected = io::connect_tcp(host, port);
    if (!connected.ok()) {
        ++direct_connect_fail_[dc];
        close_client(client.token);
        return false;
    }
    client.direct_fd = std::move(connected.fd);
    // Small MTProto records: Nagle adds avoidable latency on the opt-in Direct
    // route too. Advisory only (errors are ignored, documented Linux target).
    (void)io::set_tcp_nodelay(client.direct_fd.get());
    client.direct_connecting = connected.in_progress;
    client.last_activity = now;
    deadlines_.set(client.direct_token, now + config_.handshake_timeout);
    reaccount(client);
    update_direct_interest(client);
    if (client.direct_connecting) return true;
    on_direct_connected(client, now);
    return clients_.find(client.token) != clients_.end();
}

void Runtime::Impl::update_direct_interest(Client& client) {
    if (client.direct_token == 0 || !client.direct_fd.valid()) return;
    std::uint32_t desired = 0;
    if (client.direct_connecting) {
        desired |= EPOLLOUT;
    } else {
        const bool room = client.out && client.out->bytes() < client.out->max_bytes();
        if (!client.direct_eof && !client.direct_budget_paused && !client.media_throttled) {
            // While paused, keep EPOLLIN out of the mask or a level-triggered
            // epoll wakes forever on the unread DC bytes. RDHUP is persistent
            // once seen, so it is also removed during pause and after latching
            // direct_fin_pending; only recv()==0 latches EOF.
            if (room) desired |= EPOLLIN;
            if (!client.direct_fin_pending) desired |= EPOLLRDHUP;
        }
        if (client.direct_out && !client.direct_out->empty()) desired |= EPOLLOUT;
    }
    set_interest(client.direct_token, client.direct_fd.get(), client.direct_armed, desired);
}

void Runtime::Impl::on_direct_connected(Client& client, Time now) {
    if (!client.direct_fd.valid()) {
        close_client(client.token);
        return;
    }
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(client.direct_fd.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
        error != 0) {
        ++direct_connect_fail_[client.route_dc];
        close_client(client.token);
        return;
    }
    client.direct_connecting = false;
    deadlines_.erase(client.direct_token);
    client.last_activity = now;
    // "accepted" means an established upstream connection, not an attempt. The
    // handshake result is also only successful once SO_ERROR is clear; a failed
    // connect leaves handshake_pending set so close_client records a failure.
    ++direct_accepted_[client.route_dc];
    record_handshake(client, control::HandshakeResult::success);
    // Writes the 64-byte obfuscated2 header plus any client bytes that arrived
    // while the connect was in progress. One flush path only; the old code
    // flushed and then immediately pumped the same queue again.
    pump_direct_c2s(client);
}

void Runtime::Impl::flush_direct(Client& client) {
    (void)client.direct_flush.take();
    if (!client.direct_fd.valid() || !client.direct_out) return;
    while (!client.direct_out->empty()) {
        const auto result = client.direct_out->flush_to(client.direct_fd.get(),
                                                        detail::kWriteBatch);
        if (result.bytes_written > 0) {
            direct_tx_bytes_[client.route_dc] += result.bytes_written;
        }
        if (result.status == io::FlushStatus::error) {
            close_client(client.token);
            return;
        }
        if (result.status == io::FlushStatus::would_block) break;
    }
    update_direct_interest(client);
}

void Runtime::Impl::pump_direct_c2s(Client& client) {
    (void)client.c2s;
    // Always go through flush_direct(). Even with an empty upstream queue this
    // re-evaluates direct EPOLLIN after client output drains, which is required
    // because update_direct_interest() disables DC reads while client.out is
    // full. set_interest() is a no-op when the mask is unchanged.
    flush_direct(client);
}

void Runtime::Impl::read_direct_backend(Client& client, Time now) {
    if (client.direct_connecting || client.direct_eof || !client.out) return;
    if (!budget_allows(detail::kDirectReadReservation)) {
        if (!client.direct_budget_paused) {
            client.direct_budget_paused = true;
            paused_clients_.push_back(client.token);
            stats_.direct_budget_pause(client.route_dc);
            stats_.add_backpressure(control::Direction::server_to_client);
        }
        update_direct_interest(client);
        return;
    }
    if (client.media && media_blocked(client, now)) {
        // Leave the DC bytes in the kernel: TCP flow control slows the DC.
        media_throttle(client);
        update_direct_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    bool eof = false;
    while (total < detail::kReadBatch) {
        // Bytes already staged in this read's batch count against the client
        // queue limit, so a slow client still pauses DC reads.
        const std::size_t queued = client.out->bytes() + client.s2c_batch.size();
        const std::size_t room =
            queued >= client.out->max_bytes() ? 0 : client.out->max_bytes() - queued;
        if (room == 0) {
            stats_.add_backpressure(control::Direction::server_to_client);
            break;
        }
        const std::size_t limit = std::min(detail::kReadBatch - total, room);
        const ssize_t received = ::recv(client.direct_fd.get(), read_buffer_.data(), limit,
                                        MSG_DONTWAIT);
        if (received > 0) {
            const auto bytes = static_cast<std::size_t>(received);
            total += bytes;
            direct_rx_bytes_[client.route_dc] += bytes;
            touch(client, now);
            // Decrypt in the shared read buffer, then re-encrypt straight into
            // the client's open TLS record: every chunk of this read event ends
            // up in as few records as possible and in one send below, instead
            // of a queue copy plus an EPOLLOUT round trip per chunk.
            auto plain = std::span<std::uint8_t>(read_buffer_).first(bytes);
            client.direct_decrypt->apply(plain);
            if (client.tls->send(std::span<const std::uint8_t>(plain), client.s2c_batch,
                                 &client.s2c_open_record) != protocol::Status::Ok) {
                close_client(token);
                return;
            }
            if (client.metrics) {
                client.metrics->add_payload(control::Direction::server_to_client, bytes);
            }
            media_account(client, bytes, now);
            client.awaiting_reply = false;
            // Short read: the DC socket is drained; level-triggered EPOLLIN
            // reports more data, so skip the EAGAIN-only recv.
            if (bytes < limit) break;
        } else if (received == 0) {
            eof = true;
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
    // One direct send for everything read in this event; EPOLLOUT is armed by
    // pump_client_out() only if the client socket would block.
    if (!client.s2c_batch.empty()) {
        if (!finish_s2c_batch(client)) return;
        if (clients_.find(token) == clients_.end()) return;
    } else {
        client.s2c_open_record = protocol::FakeTlsConnection::kNoOpenRecord;
    }
    if (eof) {
        client.direct_eof = true;
        client.direct_fin_pending = false;
        client.direct_eof_at = now;
        client.awaiting_reply = false;
        direct_eof_clients_.push_back(token);
    }
    reaccount(client);
    update_direct_interest(client);
    update_client_interest(client);
}

void Runtime::Impl::handle_direct_backend(Client& client, std::uint32_t events, Time now) {
    if (client.route != Client::Route::direct) return;
    if (detail::consume_direct_event_throw_for_test()) {
        throw std::runtime_error("injected Direct backend failure");
    }
    if ((events & EPOLLERR) != 0) {
        // A refused/failed non-blocking connect surfaces here before
        // on_direct_connected(); otherwise it would close without being counted.
        if (client.direct_connecting) ++direct_connect_fail_[client.route_dc];
        close_client(client.token);
        return;
    }
    if (client.direct_connecting) {
        if ((events & (EPOLLOUT | EPOLLHUP)) != 0) on_direct_connected(client, now);
        return;
    }
    if ((events & EPOLLIN) != 0) {
        read_direct_backend(client, now);
        if (clients_.find(client.token) == clients_.end()) return;
    }
    if ((events & EPOLLOUT) != 0) {
        // flush_direct() is exactly what pump_direct_c2s() does; the old
        // sequence flushed the same queue twice per writable event.
        pump_direct_c2s(client);
        if (clients_.find(client.token) == clients_.end()) return;
    }
    if ((events & (EPOLLRDHUP | EPOLLHUP)) != 0 && !client.direct_eof) {
        // A FIN is not EOF. Latch the pending state, stop level-triggered
        // RDHUP, and drain until recv()==0 (EOF) or the shutdown bound.
        if (!client.direct_fin_pending) {
            client.direct_fin_pending = true;
            client.direct_fin_at = now;
            deadlines_.set(client.direct_token, now + config_.shutdown_timeout);
        }
        update_direct_interest(client);
        const bool room = client.out && client.out->bytes() < client.out->max_bytes();
        if (room && !client.direct_budget_paused) {
            read_direct_backend(client, now);
            if (clients_.find(client.token) == clients_.end()) return;
        }
    }
}

void Runtime::Impl::finish_direct_eof(Time now) {
    if (direct_eof_clients_.empty()) return;
    std::vector<std::uint64_t> remaining;
    remaining.reserve(direct_eof_clients_.size());
    for (const std::uint64_t token : direct_eof_clients_) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        if (client.route != Client::Route::direct || !client.direct_eof) continue;
        const bool drained = (!client.out || client.out->empty()) &&
                             client.s2c_wire.empty() && client.c2s.empty() &&
                             (!client.direct_out || client.direct_out->empty());
        if (drained || client.close_requested ||
            now >= client.direct_eof_at + config_.shutdown_timeout) {
            close_client(token);
        } else {
            remaining.push_back(token);
        }
    }
    direct_eof_clients_.swap(remaining);
}

} // namespace mtdd

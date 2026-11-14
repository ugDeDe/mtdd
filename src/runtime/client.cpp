#include "internal.hpp"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27  // Linux 4.2+
#endif
#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif

namespace mtdd {
namespace {

bool ascii_iequals(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        const auto lower = [](char value) {
            return static_cast<char>(value >= 'A' && value <= 'Z' ? value - 'A' + 'a' : value);
        };
        if (lower(left[i]) != lower(right[i])) return false;
    }
    return true;
}

// Hello SNI as grouped for the key prefilter: ASCII lowercase, one trailing
// dot dropped. Writes into `out` to reuse its storage.
void normalize_sni(std::string_view name, std::string& out) {
    if (!name.empty() && name.back() == '.') name.remove_suffix(1);
    out.assign(name);
    for (auto& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
}

std::uint64_t user_name_hash(std::string_view name) noexcept {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (const char c : name) {
        hash ^= static_cast<std::uint8_t>(c);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool parse_user_secret(std::string_view hex, std::array<std::uint8_t, 16>& out) {
    if (hex.size() != 32) return false;
    for (std::size_t i = 0; i < 16; ++i) {
        const int high = hex_value(hex[i * 2]);
        const int low = hex_value(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Hot-path scratch reset shared by the client TLS feed path. A per-record shrink
// would malloc/free (mmap/munmap above 128 KiB) for every media response; only
// >256 KiB capacity is released, down to 64 KiB kept warm. Interior buffers
// are charged to the relay budget by capacity.
// detail::trim_scratch() lives in internal.hpp, shared with the ME path.

} // namespace

namespace detail {

ClientLifecycleTelemetry& client_lifecycle_telemetry() noexcept {
    static ClientLifecycleTelemetry telemetry;
    return telemetry;
}

} // namespace detail

std::unique_ptr<Runtime::Impl::Client> Runtime::Impl::acquire_client() {
    auto& telemetry = detail::client_lifecycle_telemetry();
    if (!free_clients_.empty()) {
        Client* recycled = free_clients_.back();
        free_clients_.pop_back();
        telemetry.reuses.fetch_add(1, std::memory_order_relaxed);
        telemetry.last_reused.store(reinterpret_cast<std::uintptr_t>(recycled),
                                    std::memory_order_relaxed);
        // Every reactor owns its own freelist; the published depth is the
        // process-wide sum, maintained with atomic add/sub.
        telemetry.pooled.fetch_sub(1, std::memory_order_relaxed);
        // recycle_client() reset this object to a fresh Client, so no reset
        // is needed here.
        return std::unique_ptr<Client>(recycled);
    }
    telemetry.allocations.fetch_add(1, std::memory_order_relaxed);
    return std::make_unique<Client>();
}

void Runtime::Impl::recycle_client(std::unique_ptr<Client> client) noexcept {
    Client* raw = client.get();
    if (raw == nullptr) return;
    auto& telemetry = detail::client_lifecycle_telemetry();
    if (free_clients_.size() < client_pool_limit_) {
        try {
            // Reset to exactly a freshly constructed Client: assignment from a
            // default-constructed value destroys every owned buffer (releasing
            // vector capacity), disengages every optional, drops metrics/user
            // state and zeroes every flag. If the reset itself or the freelist
            // push throws, `raw` remains a valid Client and the unique_ptr
            // below still deletes it, so the strong guarantee is preserved.
            *raw = Client{};
            free_clients_.push_back(raw);
            client.release();
            telemetry.releases.fetch_add(1, std::memory_order_relaxed);
            telemetry.last_recycled.store(reinterpret_cast<std::uintptr_t>(raw),
                                          std::memory_order_relaxed);
            telemetry.pooled.fetch_add(1, std::memory_order_relaxed);
            return;
        } catch (...) {
            // Fall through and delete instead of pooling.
        }
    }
    telemetry.discards.fetch_add(1, std::memory_order_relaxed);
}

void Runtime::Impl::release_client_pool() noexcept {
    const std::size_t released = free_clients_.size();
    for (Client* client : free_clients_) delete client;
    free_clients_.clear();
    if (released != 0) {
        detail::client_lifecycle_telemetry().pooled.fetch_sub(
            released, std::memory_order_relaxed);
    }
}

void Runtime::Impl::accept_clients(Time now) {
    // Adaptive burst: the listener is level-triggered and the loop turns over
    // far more often than connections arrive, so normally one accept per event
    // is enough and the EAGAIN-only probe (~half of all accept4 calls) is
    // skipped. A burst that fills the limit doubles it for the next event; a
    // drained backlog (EAGAIN) shrinks it back to one.
    const std::size_t burst = accept_burst_;
    bool drained = false;
    std::size_t accepted_now = 0;
    for (std::size_t iteration = 0; iteration < burst; ++iteration) {
        if (config_.max_connections != 0 &&
            (clients_.size() >= static_cast<std::size_t>(config_.max_connections) ||
             shared_->connections.load(std::memory_order_relaxed) >=
                 config_.max_connections)) {
            break;
        }
        // Do not accept a socket that make_client() would immediately reject
        // for lack of budget. Accept-then-close churn under a rejection storm
        // creates orphan sockets; leaving the connection in the listen backlog
        // is bounded by the listener backlog.
        if (!budget_allows(detail::kBudgetHeadroom + 8192)) break;
        sockaddr_storage address{};
        socklen_t length = sizeof(address);
        const int fd = ::accept4(listener_.get(), reinterpret_cast<sockaddr*>(&address), &length,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            drained = errno == EAGAIN || errno == EWOULDBLOCK;
            break;
        }
        ++accepted_now;
        // Reserve one process-wide connection slot before counting the socket as
        // accepted; a socket refused by the global cap is a rejection, not an
        // accepted-and-immediately-closed connection. Each reactor also keeps
        // its own clients_ bound, but only the shared reservation enforces the
        // configured global limit.
        if (!shared_->try_connection(config_.max_connections)) {
            stats_.connection_rejected(control::RejectReason::overload);
            ::close(fd);
            break;
        }
        stats_.connection_accepted();
        shared_->accepted_per_worker[worker_index_].fetch_add(
            1, std::memory_order_relaxed);
        try {
            io::UniqueFd owned{fd};
            control::RejectReason failure = control::RejectReason::overload;
            Client* client = make_client(
                std::move(owned), now, failure,
                io::endpoint_from_address(&address, static_cast<std::size_t>(length)));
            if (client == nullptr) {
                // `overload` is reserved for capacity/admission limits. An
                // accepted socket without a usable peer address (reset before
                // accept) is reported as `other`, not as overload.
                stats_.connection_rejected(failure);
                stats_.connection_closed();
                shared_->release_connection();
                continue;
            }
            client->connection_counted = true;
        } catch (const std::exception&) {
            stats_.connection_closed();
            shared_->release_connection();
        }
    }
    if (drained) {
        accept_burst_ = 1;
    } else if (accepted_now == burst) {
        accept_burst_ = std::min(burst * 2, detail::kAcceptBatch);
    }
    update_listener_interest();
}

Runtime::Impl::Client* Runtime::Impl::make_client(io::UniqueFd fd, Time now,
                                                 control::RejectReason& failure,
                                                 std::optional<io::Endpoint> accepted_peer) {
    if (!budget_allows(detail::kBudgetHeadroom + 8192)) {
        failure = control::RejectReason::buffer_budget;
        return nullptr;
    }
    const auto peer = accepted_peer ? std::move(accepted_peer) : io::peer_endpoint(fd.get());
    if (!peer || peer->port == 0) {
        failure = control::RejectReason::other;
        return nullptr;
    }
    const auto protocol_peer = to_protocol_endpoint(*peer);
    if (!protocol_peer || protocol_peer->port == 0) {
        failure = control::RejectReason::other;
        return nullptr;
    }
    // With PROXY protocol only the configured fronts may connect: anyone else
    // could name an arbitrary client address in the header.
    if (config_.proxy_protocol &&
        std::none_of(proxy_allow_.begin(), proxy_allow_.end(), [&](const detail::WatchNet& net) {
            return detail::watch_net_contains(net, *protocol_peer);
        })) {
        failure = control::RejectReason::invalid_request;
        return nullptr;
    }
    // Reserve one process-wide handshake slot. Released by record_handshake()
    // or by close_client() when the pending flag is cleared without a result.
    if (!shared_->try_handshake(config_.max_handshakes)) {
        failure = control::RejectReason::overload;
        return nullptr;
    }
    bool handshake_reserved = true;
    const auto release_handshake = [&] {
        if (handshake_reserved) {
            handshake_reserved = false;
            shared_->release_handshake();
        }
    };

    std::unique_ptr<Client> owned;
    try {
        owned = acquire_client();
    } catch (...) {
        release_handshake();
        throw;
    }
    owned->fd = std::move(fd);
    // Client-facing FakeTLS records are latency-sensitive and often small.
    // TCP_NODELAY, keepalive and TCP_USER_TIMEOUT are set once on the listener
    // (setup()) and inherited by every accepted socket: no per-connection
    // setsockopt calls on the accept path.
    owned->peer = *protocol_peer;
    // Behind a PROXY-protocol front the saved SYN is the front's, not the
    // client's: no TCP fingerprint then.
    if (config_.fingerprint && !config_.proxy_protocol) {
        std::array<std::uint8_t, 128> syn{};
        socklen_t length = sizeof(syn);
        if (::getsockopt(owned->fd.get(), IPPROTO_TCP, TCP_SAVED_SYN, syn.data(), &length) == 0) {
            owned->syn = detail::parse_saved_syn(std::span<const std::uint8_t>(syn.data(), length));
        }
    }
    owned->accepted_at = now;
    owned->phase = config_.proxy_protocol ? Client::Phase::proxy_header : Client::Phase::tls_hello;
    owned->out.emplace(config_.connection_queue_bytes);
    owned->last_activity = now;
    owned->handshake_pending = true;
    owned->hello.reserve(512);

    std::uint64_t token = 0;
    Client* raw = owned.get();
    owned->deadline_kind = Client::DeadlineKind::handshake;
    try {
        token = add_target(Target{Kind::client, owned.get()});
        owned->token = token;
        clients_.emplace(token, std::move(owned));
    } catch (...) {
        if (token != 0) remove_target(token);
        release_handshake();
        throw;
    }
    ++client_count_;
    ++handshake_count_;
    handshake_reserved = false;
    try {
        deadlines_.set(token, now + config_.handshake_timeout);
        reaccount(*raw);
        update_client_interest(*raw);
        if (!config_.proxy_protocol) admit_client_peer(*raw, now);
    } catch (...) {
        // close_client() is safe here: handshake accounting is still pending and
        // no user metrics have been attached yet.
        close_client(token);
        throw;
    }
    return raw;
}

void Runtime::Impl::admit_client_peer(Client& client, Time now) {
    for (const auto& net : watch_) {
        if (detail::watch_net_contains(net, client.peer)) {
            client.watched = true;
            break;
        }
    }
    bool repeat_visit = false;
    if (config_.suspects && !client.front_peer) {
        const auto seen = shared_->suspects.accept(client.peer, now);
        if (seen.known && config_.suspect_watch_score != 0 &&
            seen.score >= static_cast<double>(config_.suspect_watch_score) &&
            shared_->suspects.watch_budget(now)) {
            client.watched = true;  // known suspect: per-stage log (rate-limited)
        }
        repeat_visit = seen.repeat_visit;
    }
    if (client.watched) watch_accept(client, now);
    if (repeat_visit) suspect(client, control::SuspectSignal::repeat_visits);
}

void Runtime::Impl::handle_client(Client& client, std::uint32_t events, Time now) {
    if (client.phase == Client::Phase::fallback) {
        handle_fallback_client(client, events, now);
        return;
    }
    const std::uint64_t token = client.token;
    // A reset or a fully closed socket is terminal; a half-close is not.
    if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
        close_client(token);
        return;
    }
    if ((events & EPOLLIN) != 0) {
        read_client(client, now);
        if (clients_.find(token) == clients_.end()) return;
        if (client.phase == Client::Phase::fallback) {
            // Classification happened during this read; continue the event in
            // the fallback handler so RDHUP/OUT are not interpreted by the
            // FakeTLS drain list.
            handle_fallback_client(client, events, now);
            return;
        }
        if (client.route == Client::Route::direct && client.direct_flush.pending()) {
            pump_direct_c2s(client);
            if (clients_.find(token) == clients_.end()) return;
        }
    }
    if ((events & EPOLLRDHUP) != 0) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) return;
        // RDHUP only says a FIN is queued. Do not latch EOF and do not disable
        // EPOLLIN until recv()==0, or a buffered tail (e.g. while budget-paused)
        // would be discarded.
        latch_fin_pending(*found->second, now);
    }
    if ((events & EPOLLOUT) != 0) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) return;
        pump_client_out(*found->second);
        if (clients_.find(token) == clients_.end()) return;
        pump_c2s(*found->second, now);
        if (clients_.find(token) == clients_.end()) return;
        enqueue_ready(*found->second);
    }
}

void Runtime::Impl::read_client(Client& client, Time now) {
    if (client.draining || client.budget_paused || client.read_eof || client.close_requested) return;
    if (!client.held_server_hello.empty()) return;  // released by its deadline
    if (client.c2s_backpressured) return;  // resumed by flush_direct()/pump_c2s()
    if (client.rate_pause_c2s) return;  // resumed by process_rate_resumes()
    if (!budget_allows(detail::kClientReadReservation)) {
        client.budget_paused = true;
        if (client.phase != Client::Phase::relay) client.handshake_budget_stalled = true;
        paused_clients_.push_back(client.token);
        stats_.add_backpressure(control::Direction::client_to_server);
        note_budget_refusal(control::BudgetRefusal::client_read);
        update_client_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    while (total < detail::kReadBatch) {
        std::size_t limit = detail::kReadBatch - total;
        if (client.phase == Client::Phase::proxy_header) {
            // v2 is read exactly; v1 at most up to kProxyHeaderV1Max bytes,
            // which is less than the shortest header plus ClientHello, so a
            // v1 over-read never passes the end of the ClientHello.
            const auto scan = protocol::scan_proxy_header(client.hello);
            limit = scan.status == protocol::ProxyHeaderScan::Status::NeedMoreData
                        ? std::min(limit, scan.want)
                        : 0;
            if (limit == 0) break;
        } else if (client.phase == Client::Phase::tls_hello) {
            // Read only up to the end of the current record header or body:
            // no byte after the ClientHello (one or more records) lands in
            // client.hello. A classified hello reads nothing more here.
            const auto scan = protocol::scan_client_hello(client.hello);
            limit = scan.status == protocol::HelloStatus::NeedMoreData
                        ? std::min(limit, scan.want)
                        : 0;
            if (limit == 0) break;
        }
        if (limit > read_buffer_.size()) limit = read_buffer_.size();
        const ssize_t received = ::recv(client.fd.get(), read_buffer_.data(), limit, MSG_DONTWAIT);
        if (received > 0) {
            const auto bytes = static_cast<std::size_t>(received);
            total += bytes;
            touch(client, now);
            consume_client_bytes(client, std::span<const std::uint8_t>(read_buffer_).first(bytes),
                                 now);
            if (clients_.find(token) == clients_.end()) return;
            if (client.phase == Client::Phase::fallback) return;
            // The ServerHello is held back: read nothing past the ClientHello.
            if (!client.held_server_hello.empty()) break;
            // Leave the rest in the kernel once the upstream queue is full.
            if (client.rate_pause_c2s || client.c2s_backpressured) break;
            // A short read drained the socket. The listener is level-triggered
            // and EPOLLIN stays armed until recv()==0, so new bytes or a FIN
            // raise another event; probing again only returned EAGAIN (~40% of
            // all recv calls under load).
            if (bytes < limit) break;
        } else if (received == 0) {
            latch_read_eof(client, now);
            return;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            close_client(token, errno == ETIMEDOUT ? control::RelayCloseReason::client_timeout
                                                   : control::RelayCloseReason::client_error);
            return;
        }
    }
    reaccount(client);
    update_client_interest(client);
}

void Runtime::Impl::consume_client_bytes(Client& client,
                                         std::span<const std::uint8_t> wire, Time now) {
    if (client.phase == Client::Phase::proxy_header) {
        client.hello.insert(client.hello.end(), wire.begin(), wire.end());
        consume_proxy_header(client, now);
        return;
    }
    if (client.phase == Client::Phase::tls_hello) {
        client.hello.insert(client.hello.end(), wire.begin(), wire.end());
        classify_client_hello(client, now);
        return;
    }
    feed_client_tls(client, wire, now);
}

void Runtime::Impl::consume_proxy_header(Client& client, Time now) {
    const auto scan = protocol::scan_proxy_header(client.hello);
    if (scan.status == protocol::ProxyHeaderScan::Status::NeedMoreData) {
        reaccount(client);
        return;
    }
    if (scan.status == protocol::ProxyHeaderScan::Status::Invalid) {
        reject_close(client, control::RejectReason::invalid_request,
                     control::HandshakeResult::failure);
        return;
    }
    if (scan.source) {
        client.peer = *scan.source;
    } else {
        client.front_peer = true;  // LOCAL / UNKNOWN: keep the socket peer
    }
    client.hello.erase(client.hello.begin(),
                       client.hello.begin() + static_cast<std::ptrdiff_t>(scan.length));
    client.phase = Client::Phase::tls_hello;
    const std::uint64_t token = client.token;
    admit_client_peer(client, now);
    if (clients_.find(token) == clients_.end()) return;
    if (client.hello.empty()) {
        reaccount(client);
        return;
    }
    classify_client_hello(client, now);
}

void Runtime::Impl::classify_client_hello(Client& client, Time now) {
    const auto scan = protocol::scan_client_hello(client.hello);
    if (scan.status == protocol::HelloStatus::NotTls ||
        scan.status == protocol::HelloStatus::Invalid) {
        // Not a ClientHello, split or not. Masking gets the bytes exactly
        // as they arrived; the SNI target comes from the reassembly.
        const bool tls = scan.status == protocol::HelloStatus::Invalid;
        const auto reassembled = protocol::reassemble_client_hello(client.hello);
        if (client.watched) watch_hello(client, tls ? reassembled : client.hello);
        if (tls) {
            suspect(client, control::SuspectSignal::junk);  // malformed record(s)
        } else {
            suspect_first_bytes(client);
        }
        if (masking_enabled()) {
            const auto original = std::move(client.hello);
            client.hello.clear();
            start_fallback(client, original, now, reassembled);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }
    if (scan.status == protocol::HelloStatus::Ok) {
        const std::uint64_t token = client.token;
        process_client_hello(client, now);
        if (clients_.find(token) == clients_.end()) return;
    }
    reaccount(client);
}

void Runtime::Impl::process_client_hello(Client& client, Time now) {
    const auto original = std::move(client.hello);
    client.hello.clear();
    const std::uint64_t token = client.token;
    // A ClientHello split over several records is authenticated, replay-keyed
    // and served as the single record the client signed. Masking still gets
    // `original` exactly as it arrived.
    std::vector<std::uint8_t> reassembled;
    std::span<const std::uint8_t> record = original;
    if (protocol::scan_client_hello(original).records > 1) {
        reassembled = protocol::reassemble_client_hello(original);
        record = reassembled;
    }

    if (record.size() < 5 || record[0] != 0x16 || record[1] != 0x03 ||
        (record[2] != 0x01 && record[2] != 0x03)) {
        if (masking_enabled()) {
            start_fallback(client, original, now, record);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }
    const std::size_t record_length =
        (static_cast<std::size_t>(record[3]) << 8) | record[4];
    if (record_length < 100 || record_length > protocol::kFakeTlsMaxClientHello) {
        if (masking_enabled()) {
            start_fallback(client, original, now, record);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }

    if (client.watched) watch_hello(client, record);
    protocol::ClientHelloInfo info;
    const control::UserRecord* user = nullptr;
    // A refused replay gets what any unauthenticated visitor gets (the real
    // site), with the same accounting as a close. The replay result is recorded
    // first: start_fallback() records a pending handshake as failure.
    const auto refuse_replay = [&](control::RejectReason reason) {
        if (!masking_enabled()) {
            reject_close(client, reason, control::HandshakeResult::replay);
            return;
        }
        record_handshake(client, control::HandshakeResult::replay);
        stats_.connection_rejected(reason);
        if (client.watched) {
            watch_log(client, "reject", std::string("reason=") + control::to_string(reason));
        }
        start_fallback(client, original, now, record);
    };
    std::optional<std::int64_t> clock_skew;
    if (!authenticate_hello(client, record, now, info, user, clock_skew)) {
        std::array<std::uint8_t, 32> digest{};
        if (clock_skew) std::copy_n(record.begin() + 11, digest.size(), digest.begin());
        if (clock_skew && !shared_->skew_seen.insert(digest, now)) {
            // The same signed random again, outside the window: a stale replay
            // (older than the replay cache), refused like an in-window one.
            if (client.watched) watch_log(client, "auth", "result=replay");
            record_ja4(client, record, control::Ja4Outcome::replay);
            suspect(client, control::SuspectSignal::junk);
            shared_->replay_rejected_per_worker[worker_index_].fetch_add(
                1, std::memory_order_relaxed);
            refuse_replay(control::RejectReason::auth_failed);
            return;
        }
        // JA4 after the HMAC outcome is known, never before: a failed hello
        // is fingerprinted only within the sampling budget (record_ja4).
        record_ja4(client, record,
                   clock_skew              ? control::Ja4Outcome::clock_skew
                   : hello_last_throttled_ ? control::Ja4Outcome::throttled
                                           : control::Ja4Outcome::unauthenticated);
        if (clock_skew) {
            // The secret matched, only the client clock is off: a mis-clocked
            // user, not a guess. Counted by skew, never scored as suspect.
            stats_.hello_clock_skew(*clock_skew);
            if (client.watched) {
                watch_log(client, "auth", "result=clock_skew skew=" + std::to_string(*clock_skew) +
                                              "s user=" + user->name);
            }
        } else if (client.watched) {
            watch_log(client, "auth", "result=bad_secret");
        }
        if (config_.suspects && !clock_skew) {
            // E: someone who knows our domain but not a valid secret.
            const auto sni = protocol::client_hello_sni(record);
            const bool ours = sni && !domain_for_sni(*sni).empty();
            if (config_.fingerprint) {
                client.platform = detail::classify_platform(client.syn, detail::classify_client_hello(record));
            }
            suspect(client, ours ? control::SuspectSignal::wrong_secret : control::SuspectSignal::junk,
                    sni ? std::string_view(*sni) : std::string_view{});
        }
        if (masking_enabled()) {
            start_fallback(client, original, now, record);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }
    // Shadow ban: a known checker gets what any unauthenticated visitor gets
    // (the real site), so its list marks this proxy dead. No RST, no refusal.
    if (suspect_shadow_ban(client, now)) {
        record_ja4(client, record, control::Ja4Outcome::unauthenticated);
        if (masking_enabled()) {
            start_fallback(client, original, now, record);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }

    // Replay is checked on the authenticated canonical HMAC before any
    // ServerHello bytes are produced or the ClientHello reaches FakeTLS. The
    // cache is shared by all reactors, so a hello observed by one reactor is
    // rejected by every other one.
    // A full bucket evicts its soonest-expiring entry instead of refusing the
    // handshake, so a flood of valid hellos cannot lock other users out.
    const auto outcome = shared_->replay.insert(info.canonical_hmac, now);
    if (outcome == detail::ReplayCache::Outcome::evicted) stats_.replay_cache_evicted();
    if (outcome == detail::ReplayCache::Outcome::duplicate) {
        if (client.watched) watch_log(client, "auth", "result=replay");
        record_ja4(client, record, control::Ja4Outcome::replay);
        suspect(client, control::SuspectSignal::junk);
        shared_->replay_rejected_per_worker[worker_index_].fetch_add(
            1, std::memory_order_relaxed);
        refuse_replay(control::RejectReason::auth_failed);
        return;
    }
    note_hello_success(client, *user);
    record_ja4(client, record, control::Ja4Outcome::authenticated);

    if (client.phase != Client::Phase::tls_hello) return;
    if (config_.fingerprint) {
        client.platform = detail::classify_platform(client.syn, detail::classify_client_hello(record));
    }
    client.user_name = user->name;
    client.auth_at = now;
    client.canary = user->policy.canary;
    if (client.canary) {
        const auto sni = protocol::client_hello_sni(record);
        suspect(client, control::SuspectSignal::canary,
                sni ? std::string_view(*sni) : std::string_view{});
    }
    if (client.watched) {
        watch_log(client, "auth", "result=ok user=" + user->name +
                                      " platform=" + detail::platform_name(client.platform));
    }
    client.generation = user->generation;
    client.metrics = stats_.user(user->name);
    if (!client.metrics) {
        reject_close(client, control::RejectReason::overload,
                     control::HandshakeResult::failure);
        return;
    }
    // Policy gates run after auth and replay, before any slot is reserved, so a
    // rejected user never holds a connection slot.
    if (user->policy.expires_at && *user->policy.expires_at <= unix_now()) {
        reject_close(client, control::RejectReason::user_expired,
                     control::HandshakeResult::failure);
        return;
    }
    // Live connections' batched payload (detail::PayloadBatch) is not yet in
    // this total; it trails by at most one flush per connection.
    if (user->policy.data_quota_bytes &&
        client.metrics->quota_used_bytes() >= *user->policy.data_quota_bytes) {
        reject_close(client, control::RejectReason::user_quota_exceeded,
                     control::HandshakeResult::failure);
        return;
    }
    // Reserve the per-user connection slot atomically: checking the count and
    // then opening would let two reactors both pass at the limit. On any later
    // failure close_client() rolls the reservation back because
    // metrics_counted is already true.
    if (user->max_connections) {
        if (!client.metrics->try_connection_open(*user->max_connections)) {
            reject_close(client, control::RejectReason::user_connection_limit,
                         control::HandshakeResult::failure);
            return;
        }
    } else {
        client.metrics->connection_opened();
    }
    client.metrics_counted = true;
    load_client_rates(client, *user);
    begin_client_tls(client, *user, std::move(info), record, now);
    if (clients_.find(token) != clients_.end()) reaccount(client);
}

void Runtime::Impl::rebuild_hello_keys(
    const std::shared_ptr<const control::UserSnapshot>& snapshot) {
    // Parse and pre-key every enabled secret once per user snapshot, not once
    // per user for every ClientHello, and group the keys by the SNI they can
    // authenticate on.
    hello_keys_.clear();
    hello_key_ptrs_.clear();
    hello_key_users_.clear();
    hello_key_domain_.clear();
    hello_key_name_.clear();
    hello_key_dup_first_.clear();
    hello_key_dup_next_.clear();
    hello_domain_keys_.clear();
    hello_any_domain_keys_.clear();
    hello_key_by_name_.clear();
    hello_keys_snapshot_.reset();
    hello_keys_.reserve(snapshot->users.size());
    std::vector<std::pair<std::array<std::uint8_t, 16>, std::uint32_t>> secrets;
    secrets.reserve(snapshot->users.size());
    for (const auto& candidate : snapshot->users) {
        if (!candidate.enabled) continue;
        std::array<std::uint8_t, 16> secret{};
        if (!parse_user_secret(candidate.secret_hex, secret)) continue;
        const auto index = static_cast<std::uint32_t>(hello_keys_.size());
        hello_keys_.emplace_back(secret);
        secrets.emplace_back(secret, index);
        protocol::crypto::secure_zero(secret);
        hello_key_users_.push_back(&candidate);
        // A user with a personal tls_domain authenticates only on that SNI;
        // the others on the global one (any SNI when none is configured).
        std::string domain;
        normalize_sni(candidate.policy.tls_domain.empty() ? config_.tls_domain
                                                          : candidate.policy.tls_domain,
                      domain);
        if (domain.empty()) {
            hello_any_domain_keys_.push_back(index);
        } else {
            hello_domain_keys_[domain].push_back(index);
        }
        hello_key_domain_.push_back(std::move(domain));
        const std::uint64_t name = user_name_hash(candidate.name);
        hello_key_name_.push_back(name);
        hello_key_by_name_.emplace(name, index);
    }
    for (const auto& key : hello_keys_) hello_key_ptrs_.push_back(&key);
    // Duplicate secrets: identical keys give identical HMACs, so whichever
    // copy matched, the winner is the first in snapshot order that may use
    // the hello's SNI (as when every key was tried in snapshot order).
    const std::size_t count = hello_keys_.size();
    hello_key_dup_first_.resize(count);
    hello_key_dup_next_.assign(count, UINT32_MAX);
    std::stable_sort(secrets.begin(), secrets.end(),
                     [](const auto& left, const auto& right) { return left.first < right.first; });
    for (std::size_t i = 0; i < secrets.size(); ++i) {
        const bool same = i > 0 && secrets[i].first == secrets[i - 1].first;
        hello_key_dup_first_[secrets[i].second] =
            same ? hello_key_dup_first_[secrets[i - 1].second] : secrets[i].second;
        if (same) hello_key_dup_next_[secrets[i - 1].second] = secrets[i].second;
    }
    for (auto& [secret, index] : secrets) protocol::crypto::secure_zero(secret);
    hello_key_mark_.assign(count, 0);
    hello_mark_generation_ = 0;
    hello_candidates_.reserve(count);
    hello_candidate_index_.reserve(count);
    hello_keys_snapshot_ = snapshot;
}

void Runtime::Impl::note_hello_success(const Client& client, const control::UserRecord& user) {
    const detail::IpKey ip = detail::hello_ip_key(client.peer);
    const std::uint64_t name = user_name_hash(user.name);
    hello_ip_hints_.upsert(ip).user = name;
    hello_prefix_hints_.upsert(detail::hello_prefix_key(ip)).user = name;
}

namespace {

std::uint64_t throttle_window(std::chrono::steady_clock::time_point now) noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() /
        detail::kHelloThrottleWindow.count());
}

}  // namespace

bool Runtime::Impl::hello_throttled(const Client& client, Time now) {
    const auto* entry = hello_failures_.find(detail::hello_ip_key(client.peer));
    if (entry == nullptr) return false;
    const std::uint64_t window = throttle_window(now);
    if (entry->window + 1 < window || entry->window > window) return false;
    const std::int64_t span = detail::kHelloThrottleWindow.count();
    const std::int64_t into =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() % span;
    // Sliding estimate: this window's count plus the share of the previous
    // window that still overlaps the last kHelloThrottleWindow.
    const std::uint64_t current = entry->window == window ? entry->current : 0;
    const std::uint64_t previous = entry->window == window ? entry->previous : entry->current;
    const std::uint64_t estimate =
        current + previous * static_cast<std::uint64_t>(span - into) / static_cast<std::uint64_t>(span);
    return estimate >= detail::kHelloThrottleFailures;
}

void Runtime::Impl::note_hello_failure(const Client& client, Time now) {
    auto& entry = hello_failures_.upsert(detail::hello_ip_key(client.peer));
    const std::uint64_t window = throttle_window(now);
    if (entry.window != window) {
        entry.previous = entry.window + 1 == window ? entry.current : 0;
        entry.current = 0;
        entry.window = window;
    }
    if (entry.current < UINT32_MAX) ++entry.current;
}

bool Runtime::Impl::authenticate_hello(Client& client, std::span<const std::uint8_t> record,
                                       Time now, protocol::ClientHelloInfo& info,
                                       const control::UserRecord*& user,
                                       std::optional<std::int64_t>& clock_skew) {
    hello_last_throttled_ = false;
    const auto snapshot = users_snapshot_ ? users_snapshot_ : users_.snapshot();
    if (!snapshot) return false;
    if (hello_keys_snapshot_ != snapshot) rebuild_hello_keys(snapshot);

    // Only keys whose user may authenticate on the hello's SNI are tried: a
    // foreign or missing SNI costs no HMAC. Keys hinted for the client's
    // address and prefix go first; an address over the failed-probe threshold
    // gets those only, so a scanner sharing a CGNAT address with a user can
    // neither burn reactor CPU nor lock that user out.
    struct Selection {
        const Client& client;
        bool throttled;
        bool selected;
    } selection{client, hello_throttled(client, now), false};
    hello_last_throttled_ = selection.throttled;
    const auto allowed = [this](std::uint32_t index) {
        return hello_key_domain_[index].empty() || hello_key_domain_[index] == hello_sni_;
    };
    // Two pointers: fits std::function's local storage, no allocation.
    const protocol::HelloKeySelector select = [this, &selection](std::string_view server_name) {
        const auto allowed_here = [this](std::uint32_t index) {
            return hello_key_domain_[index].empty() || hello_key_domain_[index] == hello_sni_;
        };
        selection.selected = true;
        normalize_sni(server_name, hello_sni_);
        hello_candidates_.clear();
        hello_candidate_index_.clear();
        if (++hello_mark_generation_ == 0) {
            std::fill(hello_key_mark_.begin(), hello_key_mark_.end(), 0U);
            hello_mark_generation_ = 1;
        }
        const auto add = [&](std::uint32_t index) {
            if (hello_key_mark_[index] == hello_mark_generation_) return;
            hello_key_mark_[index] = hello_mark_generation_;
            hello_candidates_.push_back(&hello_keys_[index]);
            hello_candidate_index_.push_back(index);
        };
        const detail::IpKey ip = detail::hello_ip_key(selection.client.peer);
        for (const auto* hint : {hello_ip_hints_.find(ip),
                                 hello_prefix_hints_.find(detail::hello_prefix_key(ip))}) {
            if (hint == nullptr) continue;
            const auto found = hello_key_by_name_.find(hint->user);
            if (found != hello_key_by_name_.end() && allowed_here(found->second)) {
                add(found->second);
            }
        }
        if (selection.throttled) {
            stats_.hello_throttled();
        } else {
            // The SNI group and the any-SNI keys, merged in snapshot order.
            static const std::vector<std::uint32_t> kNone;
            const auto group = hello_sni_.empty() ? hello_domain_keys_.end()
                                                  : hello_domain_keys_.find(hello_sni_);
            const auto& named = group == hello_domain_keys_.end() ? kNone : group->second;
            std::size_t left = 0;
            std::size_t right = 0;
            while (left < named.size() || right < hello_any_domain_keys_.size()) {
                if (right >= hello_any_domain_keys_.size() ||
                    (left < named.size() && named[left] < hello_any_domain_keys_[right])) {
                    add(named[left++]);
                } else {
                    add(hello_any_domain_keys_[right++]);
                }
            }
        }
        return std::span<const protocol::crypto::HmacSha256Key* const>(hello_candidates_);
    };

    protocol::ClientHelloInfo found;
    std::size_t matched = 0;
    const std::int64_t now_unix = unix_now();
    const auto status = protocol::validate_client_hello(
        record, select, now_unix, config_.client_clock_skew_seconds, found, matched);
    const bool authenticated = (status == protocol::HelloStatus::Ok ||
                                status == protocol::HelloStatus::ClockSkew) &&
                               matched < hello_candidate_index_.size();
    if (selection.selected) {
        stats_.hello_hmac_attempts(authenticated ? matched + 1 : hello_candidates_.size());
    }
    if (status == protocol::HelloStatus::Unauthenticated &&
        (!hello_candidates_.empty() || selection.throttled)) {
        // Every candidate missed (or the address is already throttled): a
        // guess. A foreign SNI that cost nothing is not counted.
        note_hello_failure(client, now);
    }
    if (!authenticated) return false;
    // Resolve a duplicate secret to the first user, in snapshot order, that
    // may use this SNI (the matched key itself qualifies, so this ends).
    std::uint32_t index = hello_key_dup_first_[hello_candidate_index_[matched]];
    while (!allowed(index)) index = hello_key_dup_next_[index];
    const control::UserRecord* matched_user = hello_key_users_[index];
    if (status == protocol::HelloStatus::ClockSkew) {
        clock_skew = now_unix - static_cast<std::int64_t>(found.timestamp);
        user = matched_user;
        return false;
    }
    // The prefilter ignores a trailing dot; the SNI itself must still equal
    // the expected domain, as FakeTlsConnection checks it again.
    const std::string& expected_sni = matched_user->policy.tls_domain.empty()
                                          ? config_.tls_domain
                                          : matched_user->policy.tls_domain;
    if (!expected_sni.empty() && !ascii_iequals(found.server_name, expected_sni)) {
        return false;
    }
    info = std::move(found);
    user = matched_user;
    return true;
}

void Runtime::Impl::begin_client_tls(Client& client, const control::UserRecord& user,
                                     protocol::ClientHelloInfo&& info,
                                     std::span<const std::uint8_t> record, Time now) {
    protocol::FakeTlsConnection::Config tls_config;
    tls_config.secret = info.secret;
    tls_config.random = random_;
    tls_config.skew_seconds = config_.client_clock_skew_seconds;
    tls_config.max_client_hello = protocol::kFakeTlsMaxClientHello;
    tls_config.max_record_body = protocol::kFakeTlsMaxRecordBody;
    tls_config.max_pending_plaintext = detail::kReadBatch + 2U * protocol::kFakeTlsMaxRecordBody;
    if (!user.policy.tls_domain.empty()) {
        tls_config.expected_server_name = user.policy.tls_domain;
    } else if (!config_.tls_domain.empty()) {
        tls_config.expected_server_name = config_.tls_domain;
    }
    // The real server of the user's domain sized this flight and chose this
    // suite, extension order and group (measured off the reactor); unmeasured,
    // the protocol layer draws a fallback length and echoes the client.
    if (tls_config.expected_server_name && masking_dns_) {
        if (const auto profile = masking_dns_->server_profile(*tls_config.expected_server_name)) {
            auto& options = tls_config.server_hello;
            options.app_data_min = profile->min - detail::kServerFlightJitter;
            options.app_data_max = profile->max + detail::kServerFlightJitter;
            options.cipher = profile->cipher;
            options.key_share_first = profile->key_share_first;
            options.decline_pq = profile->decline_pq;
        }
    }
    if (!x25519_pool_.empty()) {
        tls_config.server_hello.x25519_public = x25519_pool_.back();
        x25519_pool_.pop_back();
    }
    client.tls.emplace(std::move(tls_config));

    wire_buffer_.clear();
    plain_buffer_.clear();
    const auto status = client.tls->feed(record, wire_buffer_, plain_buffer_);
    if (status == protocol::Status::ProtocolError || status == protocol::Status::Closed) {
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }
    // A real server answers after its own key exchange and signature; with
    // server_hello_delay_* the flight is held (and the client not read) until
    // the per-client server_hello_delay deadline releases it.
    const auto delay = server_hello_delay();
    if (delay.count() > 0) {
        client.held_server_hello.assign(wire_buffer_.begin(), wire_buffer_.end());
    } else if (!push_client_wire(client, wire_buffer_)) {
        stats_.add_backpressure(control::Direction::server_to_client);
        reject_close(client, control::RejectReason::overload,
                     control::HandshakeResult::failure);
        return;
    }
    const auto ip_result = count_client_unique_ip(client, user.policy.max_unique_ips);
    if (ip_result != IpCountResult::ok) {
        reject_close(client,
                     ip_result == IpCountResult::limit ? control::RejectReason::user_ip_limit
                                                       : control::RejectReason::overload,
                     control::HandshakeResult::failure);
        return;
    }
    refresh_ip_history();
    stats_.observe_ip_history(client.ip_key);
    note_ip_payload(client, 0);  // unique_ip_min_bytes == 0: active at handshake
    client.phase = Client::Phase::tls_handshake;
    if (!client.held_server_hello.empty()) {
        client.deadline_kind = Client::DeadlineKind::server_hello_delay;
        deadlines_.set(client.token, now + delay);
        if (client.watched) {
            watch_log(client, "server_hello", "delay_ms=" + std::to_string(delay.count()));
        }
    } else {
        client.deadline_kind = Client::DeadlineKind::handshake;
        deadlines_.set(client.token, now + config_.handshake_timeout);
    }
    update_client_interest(client);
    detail::trim_buffer(wire_buffer_);
    detail::trim_buffer(plain_buffer_);
    reaccount(client);
}

std::chrono::milliseconds Runtime::Impl::server_hello_delay() {
    const auto low = config_.server_hello_delay_min;
    const auto high = std::max(config_.server_hello_delay_max, low);
    if (high.count() <= 0) return std::chrono::milliseconds{0};
    if (low == high) return low;
    std::array<std::uint8_t, 4> draw{};
    random_(draw);
    const std::uint32_t value = (static_cast<std::uint32_t>(draw[0]) << 24) |
                                (static_cast<std::uint32_t>(draw[1]) << 16) |
                                (static_cast<std::uint32_t>(draw[2]) << 8) | draw[3];
    const auto span = static_cast<std::uint64_t>((high - low).count()) + 1U;
    return low + std::chrono::milliseconds(static_cast<std::int64_t>(value % span));
}

void Runtime::Impl::release_server_hello(Client& client, Time now) {
    std::vector<std::uint8_t> wire;
    wire.swap(client.held_server_hello);
    if (!push_client_wire(client, wire)) {
        stats_.add_backpressure(control::Direction::server_to_client);
        reaccount(client);
        reject_close(client, control::RejectReason::overload,
                     control::HandshakeResult::failure);
        return;
    }
    client.deadline_kind = Client::DeadlineKind::handshake;
    deadlines_.set(client.token, now + config_.handshake_timeout);
    reaccount(client);
    // Writes now and re-arms EPOLLIN (the held hello no longer blocks it).
    pump_client_out(client);
}

void Runtime::Impl::feed_client_tls(Client& client, std::span<const std::uint8_t> wire, Time now) {
    if (!client.tls) return;
    const std::uint64_t token = client.token;
    wire_buffer_.clear();
    plain_buffer_.clear();
    const auto status = client.tls->feed(wire, wire_buffer_, plain_buffer_);
    if (!wire_buffer_.empty() && !push_client_wire(client, wire_buffer_)) {
        stats_.add_backpressure(control::Direction::server_to_client);
        reject_close(client, control::RejectReason::overload,
                     client.handshake_pending ? std::optional{control::HandshakeResult::failure}
                                              : std::nullopt);
        return;
    }
    if (status == protocol::Status::ProtocolError || status == protocol::Status::Closed) {
        reject_close(client, control::RejectReason::auth_failed,
                     client.handshake_pending ? std::optional{control::HandshakeResult::failure}
                                              : std::nullopt);
        return;
    }
    if (client.phase != Client::Phase::relay && client.tls->state() ==
                                                   protocol::FakeTlsConnection::State::Ready) {
        client_tls_ready(client, now);
        if (clients_.find(token) == clients_.end()) return;
    }
    if (!plain_buffer_.empty() && client.phase == Client::Phase::relay &&
        client.route == Client::Route::direct) {
        // Relay the authenticated padded-intermediate transport bytes verbatim.
        // Decoding and re-framing here would strip only 0..3 padding bytes and
        // corrupt encrypted MTProto lengths/CRC for padding 4..15.
        if (client.device_scan_left != 0 && !scan_direct_auth_key(client, plain_buffer_, now)) {
            return;
        }
        try {
            client.direct_encrypt->apply(plain_buffer_);
        } catch (const std::exception&) {
            close_client(token);
            return;
        }
        if (!client.direct_out || !client.direct_fd.valid()) {
            close_client(token);
            return;
        }
        auto append_status = client.direct_out->append(plain_buffer_);
        if (append_status != io::AppendStatus::ok) {
            flush_direct(client);
            if (clients_.find(token) == clients_.end()) return;
            append_status = client.direct_out->append(plain_buffer_);
        }
        if (append_status != io::AppendStatus::ok) {
            // Backstop only: update_c2s_backpressure() stops reading before
            // one more read event could overflow direct_out.
            stats_.add_backpressure(control::Direction::client_to_server);
            close_client(token);
            return;
        }
        if (client.metrics) {
            add_payload(client, control::Direction::client_to_server, plain_buffer_.size());
            note_ip_payload(client, plain_buffer_.size());
            note_activity(client, plain_buffer_.size());
            if (client.rate_up != 0) {
                charge_rate(client, control::Direction::client_to_server,
                            plain_buffer_.size(), now);
            }
        }
        client.awaiting_reply = true;
        client.last_forward_at = now;
        reaccount(client);
        update_c2s_backpressure(client);
        // Coalesce all records read in this reactor event into one upstream
        // flush. handle_client() flushes after read_client() returns, so a
        // successful immediate write does not add/remove EPOLLOUT first.
        // flush_direct() arms EPOLLOUT only if the socket would block.
        client.direct_flush.mark();
        detail::trim_scratch(plain_buffer_);
        return;
    }
    if (!plain_buffer_.empty() && client.phase == Client::Phase::relay) {
        // Reused per-reactor scratch: no vector allocation per read event.
        // Every exit (including the early closes below) empties it, so payloads
        // that were not moved into client.c2s are never retained; a burst of
        // tiny frames that grew it is released instead of pinned.
        auto& messages = decoded_messages_;
        struct MessagesReset {
            std::vector<protocol::TransportDecoder::Message>& messages;
            ~MessagesReset() {
                messages.clear();
                if (messages.capacity() > detail::kMessageScratchRetain) {
                    std::vector<protocol::TransportDecoder::Message>().swap(messages);
                }
            }
        } messages_reset{messages};
        messages.clear();
        const auto decoded = client.decoder->feed(plain_buffer_, messages);
        if (decoded == protocol::Status::ProtocolError) {
            close_client(token);
            return;
        }
        const std::size_t cap_limit =
            std::max(config_.connection_queue_bytes, config_.max_frame_bytes + 4096);
        for (auto& message : messages) {
            if (client.watched) watch_frame(client, message.data, message.data.size());
            if (client.device_scan_left != 0) {
                --client.device_scan_left;
                if (message.data.size() >= 8) {
                    std::uint64_t key = 0;
                    for (int i = 7; i >= 0; --i) {
                        key = (key << 8) | message.data[static_cast<std::size_t>(i)];
                    }
                    if (key != 0 && !register_device(client, key, now)) return;
                    if (key == 0) {
                        // Unencrypted key exchange: the TL constructor follows
                        // msg_id (8) and length (4).
                        if (client.zero_key_frames != 255) ++client.zero_key_frames;
                        if (message.data.size() >= 24) {
                            std::uint32_t constructor = 0;
                            for (int i = 23; i >= 20; --i) {
                                constructor = (constructor << 8) |
                                              message.data[static_cast<std::size_t>(i)];
                            }
                            if (constructor == 0xd712e4beU || constructor == 0xf5045f1fU) {
                                // req_DH_params / set_client_DH_params: the key
                                // exchange went past req_pq, so a genuine client
                                // is creating a key from this address. (During
                                // creation auth_key_id stays 0, so register_device
                                // never marks it real — this does.) A checker
                                // only ever sends req_pq and leaves.
                                client.saw_req_dh = true;
                                if (config_.suspects) shared_->suspects.mark_real(client.peer, now);
                            }
                        }
                    }
                }
            }
            const std::size_t bytes = message.data.capacity();
            // The capacity check is a backstop: update_c2s_backpressure() stops
            // reading before one more read event could exceed cap_limit.
            if (client.c2s_capacity + bytes > cap_limit ||
                !budget_allows(bytes + detail::kMeEncodeOverhead)) {
                stats_.add_backpressure(control::Direction::client_to_server);
                close_client(token);
                return;
            }
            add_payload(client, control::Direction::client_to_server, message.data.size());
            note_ip_payload(client, message.data.size());
            note_activity(client, message.data.size());
            if (client.rate_up != 0) {
                charge_rate(client, control::Direction::client_to_server,
                            message.data.size(), now);
            }
            client.c2s_capacity += bytes;
            client.c2s.push_back(std::move(message));
        }
        reaccount(client);
        pump_c2s(client, now);
        if (clients_.find(token) == clients_.end()) return;
        enqueue_ready(client);
        update_c2s_backpressure(client);
    }
    detail::trim_scratch(wire_buffer_);
    detail::trim_scratch(plain_buffer_);
    reaccount(client);
    update_client_interest(client);
}

void Runtime::Impl::client_tls_ready(Client& client, Time now) {
    const auto tag = client.tls->proto_tag();
    const std::int16_t dc = client.tls->dc_id();
    client.media = dc < 0;
    // Devices are counted per signed DC: a device holds one current auth key
    // per DC, and Android uses a separate temporary key for media DCs.
    client.device_dc = dc;
    client.device_scan_left = detail::kDeviceScanFrames;
    if (client.watched) {
        watch_log(client, "tls_ready",
                  "dc=" + std::to_string(dc) + " proto=" +
                      (tag == protocol::ProtoTag::Secure ? "secure" : "other") +
                      " route=" + (direct_route_enabled(dc) ? "direct" : "me"));
    }
    // The share was first computed at authentication, before the DC (and so
    // the media class) was known.
    if (client.media) recompute_rate_share(client);
    if (tag != protocol::ProtoTag::Secure || dc == 0) {
        reject_close(client, control::RejectReason::auth_failed,
                     client.handshake_pending ? std::optional{control::HandshakeResult::failure}
                                              : std::nullopt);
        return;
    }
    if (direct_route_enabled(dc)) {
        // Success is recorded only once the upstream connect is established
        // (on_direct_connected); a failed connect stays handshake-pending so
        // close_client records a truthful failure.
        if (!start_direct(client, dc, now)) return;
        const std::size_t hello_capacity = client.hello.capacity();
        if (hello_capacity != 0) {
            client.hello.clear();
            std::vector<std::uint8_t>().swap(client.hello);
        }
        auto& telemetry = detail::client_lifecycle_telemetry();
        telemetry.relay_transitions.fetch_add(1, std::memory_order_relaxed);
        if (hello_capacity != 0) {
            telemetry.relay_with_hello_capacity.fetch_add(1, std::memory_order_relaxed);
        }
        client.phase = Client::Phase::relay;
        schedule_client_deadline(client, now);
        update_client_interest(client);
        reaccount(client);
        return;
    }
    std::size_t decoder_limit = config_.max_frame_bytes;
    if (decoder_limit > detail::kDecoderHeadroom) decoder_limit -= detail::kDecoderHeadroom;
    try {
        client.decoder.emplace(protocol::TransportDecoder::Config{
            protocol::ProtoTag::Secure, decoder_limit});
    } catch (const std::exception&) {
        reject_close(client, control::RejectReason::invalid_request,
                     client.handshake_pending ? std::optional{control::HandshakeResult::failure}
                                              : std::nullopt);
        return;
    }
    MeConn* me = ensure_me(dc, now);
    if (me == nullptr) {
        // No exact signed-DC route in the current metadata snapshot. There is no
        // direct fallback and no silent DC substitution.
        reject_close(client, control::RejectReason::other,
                     client.handshake_pending ? std::optional{control::HandshakeResult::failure}
                                              : std::nullopt);
        return;
    }
    record_handshake(client, control::HandshakeResult::success);
    attach_to_me(client, *me);
    // The ClientHello buffer is only read in Phase::tls_hello and is moved out
    // by process_client_hello(). A moved-from vector's capacity is unspecified,
    // so release it explicitly: a relay session must never carry handshake
    // buffer capacity, and telemetry asserts the invariant.
    const std::size_t hello_capacity = client.hello.capacity();
    if (hello_capacity != 0) {
        client.hello.clear();
        std::vector<std::uint8_t>().swap(client.hello);
    }
    auto& telemetry = detail::client_lifecycle_telemetry();
    telemetry.relay_transitions.fetch_add(1, std::memory_order_relaxed);
    if (hello_capacity != 0) {
        telemetry.relay_with_hello_capacity.fetch_add(1, std::memory_order_relaxed);
    }
    client.phase = Client::Phase::relay;
    schedule_client_deadline(client, now);
    update_client_interest(client);
    reaccount(client);
}

} // namespace mtdd

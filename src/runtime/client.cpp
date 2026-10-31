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
        failure = control::RejectReason::overload;
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
    {
        std::array<std::uint8_t, 128> syn{};
        socklen_t length = sizeof(syn);
        if (::getsockopt(owned->fd.get(), IPPROTO_TCP, TCP_SAVED_SYN, syn.data(), &length) == 0) {
            owned->syn = detail::parse_saved_syn(std::span<const std::uint8_t>(syn.data(), length));
        }
    }
    if (!watch_.empty()) {
        for (const auto& net : watch_) {
            if (detail::watch_net_contains(net, owned->peer)) {
                owned->watched = true;
                break;
            }
        }
    }
    owned->accepted_at = now;
    bool repeat_visit = false;
    if (config_.suspects) {
        const auto seen = shared_->suspects.accept(owned->peer, now);
        if (seen.known && config_.suspect_watch_score != 0 &&
            seen.score >= static_cast<double>(config_.suspect_watch_score) &&
            shared_->suspects.watch_budget(now)) {
            owned->watched = true;  // known suspect: per-stage log (rate-limited)
        }
        repeat_visit = seen.repeat_visit;
    }
    owned->phase = Client::Phase::tls_hello;
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
        if (raw->watched) watch_accept(*raw, now);
        if (repeat_visit) suspect(*raw, control::SuspectSignal::repeat_visits);
    } catch (...) {
        // close_client() is safe here: handshake accounting is still pending and
        // no user metrics have been attached yet.
        close_client(token);
        throw;
    }
    return raw;
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
    if (client.rate_pause_c2s) return;  // resumed by process_rate_resumes()
    if (!budget_allows(detail::kClientReadReservation)) {
        client.budget_paused = true;
        paused_clients_.push_back(client.token);
        stats_.add_backpressure(control::Direction::client_to_server);
        update_client_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    while (total < detail::kReadBatch) {
        std::size_t limit = detail::kReadBatch - total;
        if (client.phase == Client::Phase::tls_hello) {
            if (client.hello.size() < 5) {
                limit = std::min(limit, 5 - client.hello.size());
            } else {
                const std::size_t record_length =
                    (static_cast<std::size_t>(client.hello[3]) << 8) | client.hello[4];
                const bool tls = client.hello[0] == 0x16 && client.hello[1] == 0x03 &&
                                 (client.hello[2] == 0x01 || client.hello[2] == 0x03);
                if (!tls || record_length < 100 ||
                    record_length > protocol::kFakeTlsMaxClientHello) {
                    limit = 0; // classify from the 5-byte header only
                } else {
                    const std::size_t target = 5 + record_length;
                    if (target > client.hello.size()) {
                        limit = std::min(limit, target - client.hello.size());
                    } else {
                        limit = 0;
                    }
                }
            }
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
            if (client.rate_pause_c2s) break;
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
    if (client.phase == Client::Phase::tls_hello) {
        client.hello.insert(client.hello.end(), wire.begin(), wire.end());
        if (client.hello.size() >= 5) {
            const std::size_t record_length =
                (static_cast<std::size_t>(client.hello[3]) << 8) | client.hello[4];
            const bool tls = client.hello[0] == 0x16 && client.hello[1] == 0x03 &&
                             (client.hello[2] == 0x01 || client.hello[2] == 0x03);
            if (!tls || record_length < 100 ||
                record_length > protocol::kFakeTlsMaxClientHello) {
                if (client.watched) watch_hello(client, client.hello);
                if (tls) {
                    suspect(client, control::SuspectSignal::junk);  // bad record length
                } else {
                    suspect_first_bytes(client);
                }
                if (masking_enabled()) {
                    start_fallback(client, client.hello, now);
                    return;
                }
                reject_close(client, control::RejectReason::auth_failed,
                             control::HandshakeResult::failure);
                return;
            }
            if (5 + record_length == client.hello.size()) {
                const std::uint64_t token = client.token;
                process_client_hello(client, now);
                if (clients_.find(token) == clients_.end()) return;
            }
        }
        reaccount(client);
        return;
    }
    feed_client_tls(client, wire, now);
}

void Runtime::Impl::process_client_hello(Client& client, Time now) {
    auto record = std::move(client.hello);
    client.hello.clear();
    const std::uint64_t token = client.token;

    if (record.size() < 5 || record[0] != 0x16 || record[1] != 0x03 ||
        (record[2] != 0x01 && record[2] != 0x03)) {
        if (masking_enabled()) {
            start_fallback(client, record, now);
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
            start_fallback(client, record, now);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }

    if (client.watched) watch_hello(client, record);
    protocol::ClientHelloInfo info;
    const control::UserRecord* user = nullptr;
    if (!authenticate_hello(client, record, now, info, user)) {
        if (client.watched) watch_log(client, "auth", "result=bad_secret");
        if (config_.suspects) {
            // E: someone who knows our domain but not a valid secret.
            const auto sni = protocol::client_hello_sni(record);
            const bool ours = sni && detail::domain_covers(*sni, config_.tls_domain);
            client.platform = detail::classify_platform(client.syn, detail::classify_client_hello(record));
            suspect(client, ours ? control::SuspectSignal::wrong_secret : control::SuspectSignal::junk,
                    sni ? std::string_view(*sni) : std::string_view{});
        }
        if (masking_enabled()) {
            start_fallback(client, record, now);
            return;
        }
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }
    // Shadow ban: a known checker gets what any unauthenticated visitor gets
    // (the real site), so its list marks this proxy dead. No RST, no refusal.
    if (suspect_shadow_ban(client, now)) {
        if (masking_enabled()) {
            start_fallback(client, record, now);
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
    const auto outcome = shared_->replay.insert(info.canonical_hmac, now);
    stats_.set_replay_cache_entries(worker_index_, shared_->replay.size());
    if (client.watched && outcome != detail::ReplayCache::Outcome::accepted) {
        watch_log(client, "auth", "result=replay");
    }
    if (outcome == detail::ReplayCache::Outcome::duplicate) {
        suspect(client, control::SuspectSignal::junk);
    }
    if (outcome == detail::ReplayCache::Outcome::duplicate) {
        shared_->replay_rejected_per_worker[worker_index_].fetch_add(
            1, std::memory_order_relaxed);
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::replay);
        return;
    }
    if (outcome == detail::ReplayCache::Outcome::saturated) {
        // The bounded cache never evicts a live entry. New unique handshakes are
        // rejected at capacity and reported as replay (documented limitation).
        shared_->replay_rejected_per_worker[worker_index_].fetch_add(
            1, std::memory_order_relaxed);
        reject_close(client, control::RejectReason::overload,
                     control::HandshakeResult::replay);
        return;
    }

    if (client.phase != Client::Phase::tls_hello) return;
    client.platform = detail::classify_platform(client.syn, detail::classify_client_hello(record));
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

bool Runtime::Impl::authenticate_hello(Client& client, std::span<const std::uint8_t> record,
                                       Time now, protocol::ClientHelloInfo& info,
                                       const control::UserRecord*& user) {
    (void)client;
    (void)now;
    const auto snapshot = users_snapshot_ ? users_snapshot_ : users_.snapshot();
    if (!snapshot) return false;
    if (hello_keys_snapshot_ != snapshot) {
        // Parse and pre-key every enabled secret once per user snapshot, not
        // once per user for every ClientHello. Order (and therefore which user
        // wins a duplicate secret) is the snapshot order, as before.
        hello_keys_.clear();
        hello_key_ptrs_.clear();
        hello_key_users_.clear();
        hello_keys_snapshot_.reset();
        hello_keys_.reserve(snapshot->users.size());
        for (const auto& candidate : snapshot->users) {
            if (!candidate.enabled) continue;
            std::array<std::uint8_t, 16> secret{};
            if (!parse_user_secret(candidate.secret_hex, secret)) continue;
            hello_keys_.emplace_back(secret);
            protocol::crypto::secure_zero(secret);
            hello_key_users_.push_back(&candidate);
        }
        for (const auto& key : hello_keys_) hello_key_ptrs_.push_back(&key);
        hello_keys_snapshot_ = snapshot;
    }
    protocol::ClientHelloInfo found;
    std::size_t matched = 0;
    const auto status = protocol::validate_client_hello(record, hello_key_ptrs_, unix_now(),
                                                        120, found, matched);
    if (status != protocol::HelloStatus::Ok || matched >= hello_key_users_.size()) return false;
    if (!config_.tls_domain.empty() && !ascii_iequals(found.server_name, config_.tls_domain)) {
        return false;
    }
    info = std::move(found);
    user = hello_key_users_[matched];
    return true;
}

void Runtime::Impl::begin_client_tls(Client& client, const control::UserRecord& user,
                                     protocol::ClientHelloInfo&& info,
                                     std::span<const std::uint8_t> record, Time now) {
    protocol::FakeTlsConnection::Config tls_config;
    tls_config.secret = info.secret;
    tls_config.random = random_;
    tls_config.skew_seconds = 120;
    tls_config.max_client_hello = protocol::kFakeTlsMaxClientHello;
    tls_config.max_record_body = protocol::kFakeTlsMaxRecordBody;
    tls_config.max_pending_plaintext = detail::kReadBatch + 2U * protocol::kFakeTlsMaxRecordBody;
    if (!config_.tls_domain.empty()) tls_config.expected_server_name = config_.tls_domain;
    client.tls.emplace(std::move(tls_config));

    wire_buffer_.clear();
    plain_buffer_.clear();
    const auto status = client.tls->feed(record, wire_buffer_, plain_buffer_);
    if (status == protocol::Status::ProtocolError || status == protocol::Status::Closed) {
        reject_close(client, control::RejectReason::auth_failed,
                     control::HandshakeResult::failure);
        return;
    }
    if (!push_client_wire(client, wire_buffer_)) {
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
    client.deadline_kind = Client::DeadlineKind::handshake;
    deadlines_.set(client.token, now + config_.handshake_timeout);
    update_client_interest(client);
    detail::trim_buffer(wire_buffer_);
    detail::trim_buffer(plain_buffer_);
    reaccount(client);
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
            stats_.add_backpressure(control::Direction::client_to_server);
            close_client(token);
            return;
        }
        if (client.metrics) {
            client.metrics->add_payload(control::Direction::client_to_server,
                                        plain_buffer_.size());
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
        // Coalesce all records read in this reactor event into one upstream
        // flush. handle_client() flushes after read_client() returns, so a
        // successful immediate write does not add/remove EPOLLOUT first.
        // flush_direct() arms EPOLLOUT only if the socket would block.
        client.direct_flush.mark();
        detail::trim_scratch(plain_buffer_);
        return;
    }
    if (!plain_buffer_.empty() && client.phase == Client::Phase::relay) {
        std::vector<protocol::TransportDecoder::Message> messages;
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
            if (client.c2s_capacity + bytes > cap_limit ||
                !budget_allows(bytes + detail::kMeEncodeOverhead)) {
                stats_.add_backpressure(control::Direction::client_to_server);
                close_client(token);
                return;
            }
            client.metrics->add_payload(control::Direction::client_to_server,
                                        message.data.size());
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

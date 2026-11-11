#include "internal.hpp"

#include <atomic>
#include <cstdint>
#include <utility>
#include <vector>

namespace mtdd {

namespace detail {

EofDrainTelemetry& eof_drain_telemetry() noexcept {
    static EofDrainTelemetry telemetry;
    return telemetry;
}

} // namespace detail

void Runtime::Impl::defer_close(std::uint64_t token) {
    const auto found = clients_.find(token);
    if (found == clients_.end()) return;
    found->second->close_requested = true;
    if (found->second->deferred) return;
    found->second->deferred = true;
    deferred_closes_.push_back(token);
}

void Runtime::Impl::defer_close_conn(const detail::ConnId& id) {
    const auto found = clients_by_conn_.find(id);
    if (found == clients_by_conn_.end()) return;
    defer_close(found->second);
}

void Runtime::Impl::latch_fin_pending(Client& client, Time now) {
    if (client.read_eof || client.fin_pending) return;
    client.fin_pending = true;
    client.fin_at = now;
    if (!client.drain_tracked) {
        client.drain_tracked = true;
        eof_clients_.push_back(client.token);
    }
    const Time expiry = now + config_.shutdown_timeout;
    if (expiry < next_eof_deadline_) next_eof_deadline_ = expiry;
    update_client_interest(client);
}

void Runtime::Impl::latch_read_eof(Client& client, Time now) {
    if (client.read_eof) return;
    client.read_eof = true;
    client.read_eof_at = now;
    client.fin_pending = true; // FIN/EOF are equivalent for interest purposes
    if (!client.drain_tracked) {
        client.drain_tracked = true;
        eof_clients_.push_back(client.token);
    }
    // Earliest possible expiry (the reply-only grace); the sweep recomputes it.
    const Time expiry = now + std::min<std::chrono::nanoseconds>(detail::kEofReplyGrace,
                                                                 config_.shutdown_timeout);
    if (expiry < next_eof_deadline_) next_eof_deadline_ = expiry;
    update_client_interest(client);
}

void Runtime::Impl::finish_eof_clients(Time now, bool force) {
    auto& telemetry = detail::eof_drain_telemetry();
    if (eof_clients_.empty()) {
        next_eof_deadline_ = Time::max();
        return;
    }
    // Coalesce the after-batch call: a full sweep runs at most once per
    // kEofSweepInterval. A due FIN/read-EOF deadline does not start an extra
    // sweep: under churn some deadline expires every few milliseconds, which
    // turned this O(tracked) scan into a per-batch cost. Expiry is therefore
    // late by at most kEofSweepInterval. Housekeeping passes force=true.
    if (!force && now < next_eof_sweep_) return;
    next_eof_sweep_ = now + detail::kEofSweepInterval;
    telemetry.sweeps.fetch_add(1, std::memory_order_relaxed);

    // Reuse the member scratch vector instead of allocating per sweep. The
    // loop is index-based over the length observed on entry so a reentrant
    // append cannot invalidate the iteration; any such token is preserved in
    // the second loop below rather than silently dropped.
    std::vector<std::uint64_t>& remaining = eof_remaining_;
    remaining.clear();
    Time deadline = Time::max();
    const std::size_t tracked = eof_clients_.size();
    for (std::size_t index = 0; index < tracked; ++index) {
        const std::uint64_t token = eof_clients_[index];
        telemetry.visits.fetch_add(1, std::memory_order_relaxed);
        auto found = clients_.find(token);
        telemetry.map_lookups.fetch_add(1, std::memory_order_relaxed);
        if (found == clients_.end()) continue;
        Client* client = found->second.get();
        if (client->read_eof) {
            // pump_client_out has nothing to stage, flush, close or reaccount
            // when no write is wanted; calling it only chased cold allocator
            // metadata (retained_bytes) for every retained EOF client.
            if (client_wants_write(*client)) {
                telemetry.output_pumps.fetch_add(1, std::memory_order_relaxed);
                pump_client_out(*client);
                found = clients_.find(token);
                telemetry.map_lookups.fetch_add(1, std::memory_order_relaxed);
                if (found == clients_.end()) continue;
                client = found->second.get();
            }
            // An empty C2S queue cannot make progress and cannot destroy the
            // client, so the post-pump resolution is only needed when a real
            // pump ran. A Direct route keeps its bytes in direct_out instead of
            // c2s, so a FIN with a pending (EAGAIN-retried) upstream queue must
            // still get one bounded pump.
            // The output pump above may have made room in `out` without any
            // client EPOLLOUT being dispatched. Re-evaluate the Direct mask even
            // when no DC FIN is pending, otherwise a half-closed client can keep
            // the DC read side disarmed forever (idle_timeout).
            if (client->route == Client::Route::direct && client->direct_token != 0) {
                update_direct_interest(*client);
            }
            const bool direct_pending = client->route == Client::Route::direct &&
                                        client->direct_out && !client->direct_out->empty();
            if (direct_pending) {
                detail::direct_drain_telemetry().pumps.fetch_add(1, std::memory_order_relaxed);
            }
            if (!client->c2s.empty() || direct_pending) {
                pump_c2s(*client, now);
                found = clients_.find(token);
                telemetry.map_lookups.fetch_add(1, std::memory_order_relaxed);
                if (found == clients_.end()) continue;
                client = found->second.get();
                enqueue_ready(*client);
            }
            // A Direct client's half-close is not upstream EOF: the DC->client
            // response stream may still hold unread data or a pending FIN. Only
            // recv()==0 (direct_eof) proves the tail is complete. The existing
            // read_eof_at + shutdown_timeout expiry below remains the bound, so
            // this is not an indefinite half-close wait.
            const bool direct_open =
                client->route == Client::Route::direct && client->direct_fd.valid() &&
                !client->direct_eof;
            const bool drained = client->c2s.empty() && !client_wants_write(*client) &&
                                 !client->awaiting_reply && !direct_open &&
                                 (!client->direct_out || client->direct_out->empty());
            // Nothing left to deliver except a hoped-for ME reply: the peer has
            // closed its side, so wait only a short grace instead of the full
            // shutdown_timeout. Each such client holds a socket in CLOSE_WAIT
            // and a conn id on the shared ME writer.
            const bool reply_only = client->awaiting_reply && client->c2s.empty() &&
                                    !client_wants_write(*client) && !direct_open &&
                                    (!client->direct_out || client->direct_out->empty());
            const Time expiry =
                client->read_eof_at + (reply_only ? std::min<std::chrono::nanoseconds>(
                                                        detail::kEofReplyGrace,
                                                        config_.shutdown_timeout)
                                                  : std::chrono::nanoseconds(
                                                        config_.shutdown_timeout));
            if (drained || now >= expiry || client->close_requested) {
                telemetry.closes.fetch_add(1, std::memory_order_relaxed);
                close_client(token, control::RelayCloseReason::client_eof);
            } else {
                remaining.push_back(token);
                if (expiry < deadline) deadline = expiry;
            }
        } else if (client->fin_pending) {
            // FIN observed but the read side has not reached recv()==0 yet.
            // Progress normally comes from EPOLLIN after an unpause. If the
            // backlog cannot be read within the bounded FIN lifetime, fail
            // closed with truthful counters instead of retaining forever.
            if (client->close_requested) {
                telemetry.closes.fetch_add(1, std::memory_order_relaxed);
                close_client(token);
            } else {
                const Time expiry = client->fin_at + config_.shutdown_timeout;
                if (now >= expiry) {
                    stats_.add_backpressure(control::Direction::client_to_server);
                    stats_.connection_rejected(control::RejectReason::other);
                    telemetry.closes.fetch_add(1, std::memory_order_relaxed);
                    close_client(token);
                } else {
                    remaining.push_back(token);
                    if (expiry < deadline) deadline = expiry;
                }
            }
        } else {
            client->drain_tracked = false;
        }
    }
    // Preserve tokens appended reentrantly during the sweep. No current pump or
    // close path latches FIN/EOF, but keeping this explicit means the scratch
    // vector can never lose pending work if that changes.
    for (std::size_t index = tracked; index < eof_clients_.size(); ++index) {
        const std::uint64_t token = eof_clients_[index];
        remaining.push_back(token);
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        const Client& client = *found->second;
        if (client.read_eof) {
            const Time expiry = client.read_eof_at + config_.shutdown_timeout;
            if (expiry < deadline) deadline = expiry;
        } else if (client.fin_pending) {
            const Time expiry = client.fin_at + config_.shutdown_timeout;
            if (expiry < deadline) deadline = expiry;
        }
    }
    eof_clients_.swap(remaining);
    remaining.clear();
    next_eof_deadline_ = deadline;
}

void Runtime::Impl::process_deferred() {
    if (!deferred_closes_.empty()) {
        auto pending = std::move(deferred_closes_);
        deferred_closes_.clear();
        for (const std::uint64_t token : pending) {
            const auto found = clients_.find(token);
            if (found == clients_.end()) continue;
            found->second->deferred = false;
            close_client(token);
        }
    }
    if (!deferred_me_failures_.empty()) {
        auto failures = std::move(deferred_me_failures_);
        deferred_me_failures_.clear();
        const Time now = Clock::now();
        for (const std::uint64_t token : failures) {
            const auto found = me_by_token_.find(token);
            if (found == me_by_token_.end() || found->second == nullptr) continue;
            MeConn& me = *found->second;
            me.failure_deferred = false;
            fail_me(me, now);
        }
    }
}

} // namespace mtdd

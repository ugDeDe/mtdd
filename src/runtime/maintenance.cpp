#include "internal.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <string>
#include <utility>

namespace mtdd {

void Runtime::Impl::apply_shared_tunables() {
    const std::uint64_t generation =
        shared_->tunables_generation.load(std::memory_order_acquire);
    if (generation == tunables_seen_) return;
    tunables_seen_ = generation;
    config_.me_clients_per_writer =
        shared_->me_clients_per_writer.load(std::memory_order_relaxed);
    config_.me_connections_per_dc =
        shared_->me_connections_per_dc.load(std::memory_order_relaxed);
    // A lower cap applies now: clamp the target and scale-drain the excess
    // writers (fewest bound clients first). Draining only stops new bindings;
    // each writer closes after its own clients leave, so nobody is dropped.
    const std::size_t cap = config_.me_connections_per_dc;
    for (auto& [dc, pool] : me_pool_) {
        if (pool.scale_target > cap) pool.scale_target = cap;
        std::vector<MeConn*> active;
        for (auto& connection : pool.conns) {
            if (connection && !connection->draining &&
                connection->generation == pool.desired_generation) {
                active.push_back(connection.get());
            }
        }
        if (active.size() <= cap) continue;
        std::sort(active.begin(), active.end(), [](const MeConn* left, const MeConn* right) {
            return left->clients < right->clients;
        });
        for (std::size_t index = 0; index < active.size() - cap; ++index) {
            active[index]->draining = true;
            active[index]->scale_draining = true;
            active[index]->draining_deadline = Time::max();
            ++pool.scale_down_total;
        }
        publish_me_pool(dc);
    }
    recompute_ready();
}

void Runtime::Impl::housekeeping(Time now) {
    // A reload must never become a reactor failure; on allocation failure the
    // generation is already consumed and the next reload retries.
    try {
        apply_shared_tunables();
    } catch (...) {
    }
    shared_->replay.evict(now);
    refresh_ip_history();
    stats_.set_replay_cache_entries(worker_index_, shared_->replay.size());
    if (!stopping_) {
        advance_warming(now);
        for (auto& [dc, pool] : me_pool_) {
            (void)pool;
            scale_me_pool(dc, now);
        }
        for (auto& [dc, pool] : me_pool_) {
            (void)dc;
            for (auto& me : pool.conns) {
                if (!me || me->draining) continue;
                if (me->state == MeConn::State::backoff && now >= me->next_attempt) {
                    connect_me(*me, now);
                }
            }
        }
    }
    if (!stopping_) evict_slow_me_writers(now);
    // Retire draining connections at zero clients or at their hard deadline.
    reap_me_pool(now);
    // Safety net: a ready queue with remaining work is resumed every 150 ms
    // even if the 1 ms wake deadline was lost. The pump itself is bounded.
    for (auto& [dc, pool] : me_pool_) {
        (void)dc;
        for (auto& me : pool.conns) {
            if (me && me->state == MeConn::State::ready && !me->ready_clients.empty()) {
                pump_me_ready_queue(*me, now);
            }
        }
    }
    finish_eof_clients(now, true);
    finish_direct_eof(now);
    finish_fallback_pairs(now);
    unpause_clients_if_possible(now);
    reaccount_shared();
    // The process-wide connection count can drop because another reactor closed
    // a client; re-evaluate this reactor's listener so a reactor that paused
    // accepting at the global cap resumes without waiting for local traffic.
    update_listener_interest();
}

bool Runtime::Impl::budget_allows(std::size_t extra) const {
    const std::size_t limit = config_.global_buffer_bytes;
    if (budget_used_ >= limit) return false;
    return extra <= limit - budget_used_;
}

std::size_t Runtime::Impl::shared_bytes() const noexcept {
    return read_buffer_.capacity() + plain_buffer_.capacity() + frame_buffer_.capacity() +
           wire_buffer_.capacity() + to_me_buffer_.capacity();
}

void Runtime::Impl::reaccount(Client& client) {
    std::size_t next = client.hello.capacity();
    if (client.tls) next += client.tls->retained_bytes();
    if (client.decoder) next += client.decoder->retained_bytes();
    if (client.out) next += client.out->capacity_bytes();
    if (client.c2b) next += client.c2b->capacity_bytes();
    if (client.direct_out) next += client.direct_out->capacity_bytes();
    next += client.s2c_wire.capacity();
    next += client.s2c_batch.capacity();
    next += client.c2s_capacity;
    if (next >= client.accounted) {
        budget_used_ += next - client.accounted;
    } else {
        const std::size_t drop = client.accounted - next;
        budget_used_ = drop > budget_used_ ? 0 : budget_used_ - drop;
    }
    client.accounted = next;
}

void Runtime::Impl::reaccount(MeConn& me) {
    std::size_t next = 0;
    if (me.session) next += me.session->retained_bytes();
    if (me.out) next += me.out->capacity_bytes();
    for (const auto& frame : me.frames) next += frame.bytes.capacity();
    if (next >= me.accounted) {
        budget_used_ += next - me.accounted;
    } else {
        const std::size_t drop = me.accounted - next;
        budget_used_ = drop > budget_used_ ? 0 : budget_used_ - drop;
    }
    me.accounted = next;
}

void Runtime::Impl::reaccount_shared() {
    const std::size_t next = shared_bytes();
    if (next >= shared_accounted_) {
        budget_used_ += next - shared_accounted_;
    } else {
        const std::size_t drop = shared_accounted_ - next;
        budget_used_ = drop > budget_used_ ? 0 : budget_used_ - drop;
    }
    shared_accounted_ = next;
}

void Runtime::Impl::forget_accounting(std::size_t accounted) {
    budget_used_ = accounted > budget_used_ ? 0 : budget_used_ - accounted;
}

void Runtime::Impl::unpause_clients_if_possible(Time now) {
    // A paused ME read reserves one full read batch plus headroom, matching the
    // admission check in read_me(); a weaker threshold would only re-pause.
    if (budget_allows(detail::kReadBatch + detail::kBudgetHeadroom / 2)) {
        for (auto& [dc, pool] : me_pool_) {
            (void)dc;
            for (auto& me : pool.conns) {
                if (me && me->budget_paused) {
                    me->budget_paused = false;
                    ++me->budget_resumes;
                    if (me->budget_paused_at != Time{}) {
                        const auto age = now > me->budget_paused_at
                                             ? std::chrono::duration_cast<
                                                   std::chrono::milliseconds>(
                                                   now - me->budget_paused_at)
                                                   .count()
                                             : 0;
                        me->budget_pause_max_ms =
                            std::max(me->budget_pause_max_ms,
                                     static_cast<std::uint64_t>(age > 0 ? age : 0));
                    }
                    update_me_interest(*me);
                }
            }
        }
    }
    // Clients resume only with more free budget than an ME read needs, so the
    // shared writer is always re-armed first and never starved by its clients.
    if (!budget_allows(detail::kClientReadReservation)) {
        reaccount_shared();
        return;
    }
    const bool direct_can_resume = budget_allows(detail::kDirectReadReservation);
    std::vector<std::uint64_t> remaining;
    remaining.reserve(paused_clients_.size());
    for (const std::uint64_t token : paused_clients_) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        bool keep = false;
        if (client.direct_budget_paused) {
            if (!direct_can_resume) {
                keep = true;
            } else {
                client.direct_budget_paused = false;
                // EPOLLIN (and a FIN-induced readable state) resumes the read.
                // Do not call read_direct_backend() here: it may push a new
                // pause token while this vector is being iterated.
                update_direct_interest(client);
            }
        }
        const bool was_other = client.budget_paused || client.backend_budget_paused;
        client.budget_paused = false;
        client.backend_budget_paused = false;
        if (was_other) {
            update_client_interest(client);
            if (client.phase == Client::Phase::fallback) update_fallback_backend_interest(client);
        }
        if (keep) remaining.push_back(token);
    }
    paused_clients_.swap(remaining);
}

// ---------------------------------------------------------------------------
// User snapshot and metadata
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

void Runtime::Impl::begin_shutdown(Time now) {
    if (stopping_) return;
    stopping_ = true;
    stats_.set_ready(worker_index_, false);
    shutdown_deadline_ = now + config_.shutdown_timeout;
    if (listener_.valid()) {
        set_interest(listener_token_, listener_.get(), listener_events_, 0);
        listener_.close();
    }
    std::vector<std::uint64_t> tokens;
    tokens.reserve(clients_.size());
    for (const auto& [token, client] : clients_) {
        (void)client;
        tokens.push_back(token);
    }
    std::vector<std::uint64_t> closing;
    for (const std::uint64_t token : tokens) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        if (client.phase == Client::Phase::fallback) {
            client.draining = true;
            update_client_interest(client);
            update_fallback_backend_interest(client);
            pump_fallback_c2b(client);
            const auto after_c2b = clients_.find(token);
            if (after_c2b == clients_.end()) continue;
            pump_fallback_b2c(*after_c2b->second);
            continue;
        }
        const bool direct_ready =
            client.phase == Client::Phase::relay && client.route == Client::Route::direct;
        const bool relay_ready = client.phase == Client::Phase::relay && client.me != nullptr &&
                                 client.me->state == MeConn::State::ready;
        if (!direct_ready && !relay_ready) {
            closing.push_back(token);
            continue;
        }
        client.draining = true;
        update_client_interest(client);
        pump_client_out(client);
        const auto again = clients_.find(token);
        if (again == clients_.end()) continue;
        pump_c2s(*again->second, now);
        const auto direct = clients_.find(token);
        if (direct != clients_.end() && direct->second->route == Client::Route::direct) {
            update_direct_interest(*direct->second);
        }
    }
    for (const std::uint64_t token : closing) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        // R8(c): a normal shutdown is not a handshake timeout. Close without
        // recording a handshake result and attribute the rejection to "other".
        stats_.connection_rejected(control::RejectReason::other);
        close_client(token, false);
    }
}

void Runtime::Impl::shutdown_pump(Time now) {
    std::vector<std::uint64_t> tokens;
    tokens.reserve(clients_.size());
    for (const auto& [token, client] : clients_) {
        (void)client;
        tokens.push_back(token);
    }
    std::vector<std::uint64_t> closing;
    for (const std::uint64_t token : tokens) {
        const auto found = clients_.find(token);
        if (found == clients_.end() || !found->second->draining) continue;
        Client& client = *found->second;
        if (client.phase == Client::Phase::fallback) {
            pump_fallback_c2b(client);
            const auto again = clients_.find(token);
            if (again == clients_.end()) continue;
            pump_fallback_b2c(*again->second);
            const auto current = clients_.find(token);
            if (current == clients_.end()) continue;
            const bool drained = (!current->second->out || current->second->out->empty()) &&
                                 (!current->second->c2b || current->second->c2b->empty());
            if (drained || current->second->close_requested || now >= shutdown_deadline_) {
                closing.push_back(token);
            }
            continue;
        }
        pump_client_out(client);
        const auto again = clients_.find(token);
        if (again == clients_.end()) continue;
        pump_c2s(*again->second, now);
        const auto current = clients_.find(token);
        if (current == clients_.end()) continue;
        // A FIN whose tail has not reached recv()==0 is not drained even if the
        // user-space queues happen to be empty.
        const bool direct_tail =
            current->second->direct_fin_pending && !current->second->direct_eof;
        const bool drained = (!current->second->out || current->second->out->empty()) &&
                             current->second->s2c_wire.empty() &&
                             current->second->c2s.empty() && !current->second->awaiting_reply &&
                             (!current->second->direct_out ||
                              current->second->direct_out->empty()) &&
                             !direct_tail;
        if (drained || current->second->close_requested || now >= shutdown_deadline_) {
            closing.push_back(token);
        }
    }
    for (const std::uint64_t token : closing) {
        close_client(token, control::RelayCloseReason::shutdown);
    }
    for (auto& [dc, pool] : me_pool_) {
        (void)dc;
        for (auto& me : pool.conns) {
            if (me) pump_me_out(*me);
        }
    }
}

void Runtime::Impl::finalize() {
    if (finalized_) return;
    finalized_ = true;
    // Never keep accepting after the reactor's event loop has ended, including
    // the fatal-error path that skips begin_shutdown().
    if (listener_.valid()) {
        set_interest(listener_token_, listener_.get(), listener_events_, 0);
        listener_.close();
    }
    std::vector<std::uint64_t> tokens;
    tokens.reserve(clients_.size());
    for (const auto& [token, client] : clients_) {
        (void)client;
        tokens.push_back(token);
    }
    for (const std::uint64_t token : tokens) {
        close_client(token, control::RelayCloseReason::shutdown);
    }
    for (auto& [dc, pool] : me_pool_) {
        for (auto& me : pool.conns) {
            if (!me) continue;
            // R8(b): one bounded final flush of queued ME frames before teardown.
            pump_me_out(*me);
            shutdown_me(*me);
        }
        // This reactor no longer owns an ME socket for the DC: publish the zero
        // pool for its slot before the connections are destroyed.
        stats_.me_connected(worker_index_, dc, false);
        stats_.me_pool(worker_index_, dc, 0, 0);
        stats_.me_worker(worker_index_, dc, control::MeWorkerSnapshot{});
    }
    me_by_token_.clear();
    me_pool_.clear();
    stats_.set_ready(worker_index_, false);
    stats_.set_buffer_bytes(worker_index_, control::BufferState::queued, 0);
    stats_.set_buffer_bytes(worker_index_, control::BufferState::pending_write, 0);
    stats_.set_buffer_bytes(worker_index_, control::BufferState::relay, 0);
    stats_.me_pending_buffer_bytes(worker_index_, 0);
    stats_.set_buffer_budget_used(worker_index_, 0);
    stats_.set_handshakes_pending(worker_index_, 0);
    stats_.set_worker_diagnostics(worker_index_, 0,
                                  config_.global_buffer_bytes, 0, 0);
    stats_.set_replay_cache_entries(worker_index_, 0);
    const auto& lifecycle = detail::client_lifecycle_telemetry();
    stats_.set_client_pool(worker_index_, 0,
                           lifecycle.allocations.load(std::memory_order_relaxed),
                           lifecycle.reuses.load(std::memory_order_relaxed));
    release_client_pool();
    // The last reactor to finish clears the process-wide IP gauges. Every
    // reactor closed its clients above, so no decrement can race this clear.
    const std::size_t finished =
        shared_->exited.fetch_add(1, std::memory_order_relaxed) + 1;
    if (finished >= shared_->workers) {
        {
            const std::lock_guard lock{shared_->ip_mutex};
            shared_->unique_ip_counts.clear();
            shared_->user_unique_ip_counts.clear();
            shared_->active_ip_counts.clear();
            shared_->user_active_ip_counts.clear();
            stats_.set_active_unique_ips(0);
            stats_.set_qualified_unique_ips(0);
        }
    }
    barrier_.stop();
    mark_exited();
}

void Runtime::Impl::mark_exited() noexcept {
    // Notify while the waiter still needs this mutex: a destructor may return
    // as soon as exited_ becomes true and then destroy the condition variable.
    // Releasing the lock before notify_all() would let that destruction race
    // the notification itself.
    const std::lock_guard lock{exit_mutex_};
    exited_ = true;
    exit_changed_.notify_all();
}

} // namespace mtdd

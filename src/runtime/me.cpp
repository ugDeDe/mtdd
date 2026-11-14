#include "internal.hpp"
#include "retry.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace mtdd {

namespace detail {
namespace {
std::atomic<int> g_remote_close_push_failure{0};
std::mutex g_me_ping_tuning_mutex;
std::optional<MePingTuning> g_me_ping_tuning;
std::mutex g_me_drain_mutex;
std::optional<std::chrono::seconds> g_me_drain_deadline;
} // namespace

void set_me_ping_tuning_for_test(std::optional<MePingTuning> value) {
    const std::lock_guard lock{g_me_ping_tuning_mutex};
    g_me_ping_tuning = value;
}

MePingTuning me_ping_tuning() {
    const std::lock_guard lock{g_me_ping_tuning_mutex};
    return g_me_ping_tuning.value_or(MePingTuning{});
}

void set_me_drain_deadline_for_test(std::optional<std::chrono::seconds> value) {
    const std::lock_guard lock{g_me_drain_mutex};
    g_me_drain_deadline = value;
}

std::chrono::seconds me_drain_deadline() {
    const std::lock_guard lock{g_me_drain_mutex};
    return g_me_drain_deadline.value_or(kMeDrainDeadline);
}

void set_remote_close_push_failure_for_test(int count) {
    g_remote_close_push_failure.store(count, std::memory_order_relaxed);
}

bool consume_remote_close_push_failure_for_test() {
    int current = g_remote_close_push_failure.load(std::memory_order_relaxed);
    while (current > 0) {
        if (g_remote_close_push_failure.compare_exchange_weak(
                current, current - 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}
} // namespace detail


std::optional<protocol::Endpoint>
Runtime::Impl::to_protocol_endpoint(const io::Endpoint& endpoint) {
    std::array<std::uint8_t, 16> bytes{};
    if (::inet_pton(AF_INET, endpoint.address.c_str(), bytes.data()) == 1) {
        return protocol::Endpoint::v4({bytes[0], bytes[1], bytes[2], bytes[3]}, endpoint.port);
    }
    if (::inet_pton(AF_INET6, endpoint.address.c_str(), bytes.data()) == 1) {
        return protocol::Endpoint::v6(bytes, endpoint.port);
    }
    return std::nullopt;
}

bool Runtime::Impl::me_candidates(std::int16_t dc, std::vector<MeEndpoint>& out) const {
    out.clear();
    if (!metadata_snapshot_ || metadata_snapshot_->secret.empty()) return false;
    for (const auto& endpoint : metadata_snapshot_->endpoints) {
        if (endpoint.dc == dc) out.push_back(endpoint);
    }
    return !out.empty();
}

std::size_t Runtime::Impl::me_frame_capacity() const noexcept {
    const std::size_t base =
        std::min<std::size_t>(config_.max_frame_bytes + detail::kMeFrameOverhead, 64U * 1024U * 1024U);
    return base * 2 + 64U * 1024U;
}

std::size_t Runtime::Impl::me_generation_count(const DcPool& pool,
                                              std::uint64_t generation) const noexcept {
    std::size_t count = 0;
    for (const auto& connection : pool.conns) {
        if (!connection || connection->draining) continue;
        if (connection->generation == generation) ++count;
    }
    return count;
}

void Runtime::Impl::erase_me_from_pool(DcPool& pool, MeConn* me) noexcept {
    auto& connections = pool.conns;
    connections.erase(
        std::remove_if(connections.begin(), connections.end(),
                       [me](const std::unique_ptr<MeConn>& connection) {
                           return connection.get() == me;
                       }),
        connections.end());
}

Runtime::Impl::MeConn* Runtime::Impl::pick_me(std::int16_t dc) noexcept {
    const auto found = me_pool_.find(dc);
    if (found == me_pool_.end()) return nullptr;
    MeConn* best = nullptr;
    // Rank ready connections above connecting/handshaking ones, and those above
    // retry backoff. Among equals, least-loaded wins: live clients first (a
    // client is a hard protocol binding), then queued bytes/frames.
    const auto rank = [](const MeConn& connection) {
        if (connection.state == MeConn::State::ready) return 0;
        if (connection.state == MeConn::State::connecting ||
            connection.state == MeConn::State::handshaking) {
            return 1;
        }
        return 2;
    };
    for (const auto& connection : found->second.conns) {
        if (!connection || connection->draining) continue;
        if (best == nullptr) {
            best = connection.get();
            continue;
        }
        const int left = rank(*connection);
        const int right = rank(*best);
        if (left != right) {
            if (left < right) best = connection.get();
            continue;
        }
        if (connection->clients != best->clients) {
            if (connection->clients < best->clients) best = connection.get();
            continue;
        }
        const std::size_t left_queue = connection->out ? connection->out->bytes() : 0;
        const std::size_t right_queue = best->out ? best->out->bytes() : 0;
        if (left_queue != right_queue) {
            if (left_queue < right_queue) best = connection.get();
            continue;
        }
        if (connection->frame_bytes < best->frame_bytes) best = connection.get();
    }
    return best;
}

void Runtime::Impl::publish_me_pool(std::int16_t dc) noexcept {
    std::uint64_t total = 0;
    std::uint64_t ready = 0;
    std::uint64_t clients = 0;
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        const auto& pool = found->second;
        for (const auto& connection : found->second.conns) {
            if (!connection) continue;
            ++total;
            clients += connection->clients;
            // Draining connections still exist as sockets but are not a
            // readiness source: new clients never attach to them. They only
            // start draining after a successor of the same DC is ready, so the
            // pool keeps at least one ready non-draining member throughout a
            // replacement.
            if (!connection->draining && connection->state == MeConn::State::ready) ++ready;
        }
        stats_.me_pool_scaling(worker_index_, dc,
            pool.desired_generation ? pool.scale_target : 0, clients,
            pool.scale_up_total, pool.scale_down_total, pool.creation_failures_total);
    }
    stats_.me_pool(worker_index_, dc, total, ready);
    stats_.me_connected(worker_index_, dc, ready > 0);
    publish_me_rtt(dc);
    publish_me_control(dc);
}

void Runtime::Impl::publish_me_io(std::int16_t dc) noexcept {
    // Cumulative per DC: the base holds bytes folded from replaced or failed
    // connections, plus the mirrors of the live ones. Summing the live members
    // alone would reset the series on every pool rotation.
    std::uint64_t rx = 0;
    std::uint64_t tx = 0;
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        const DcPool& pool = found->second;
        rx = pool.rx_bytes;
        tx = pool.tx_bytes;
        for (const auto& connection : pool.conns) {
            if (!connection) continue;
            rx += connection->rx_bytes;
            tx += connection->tx_bytes;
        }
    }
    stats_.me_io(worker_index_, dc, rx, tx);
}

void Runtime::Impl::publish_me_worker_diagnostics(std::int16_t dc, Time now) noexcept {
    control::MeWorkerSnapshot values;
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        const DcPool& pool = found->second;
        values.budget_pauses_total = pool.budget_pauses;
        values.budget_resumes_total = pool.budget_resumes;
        values.max_pause_age_ms = pool.budget_pause_max_ms;
        values.slow_evictions_total = pool.slow_evictions_total;
        for (const auto& connection : pool.conns) {
            if (!connection) continue;
            ++values.connections;
            const bool serving =
                !connection->draining &&
                connection->state == MeConn::State::ready;
            if (serving) ++values.ready_connections;
            // Actual interest mask, not an inferred "should be armed" value:
            // the read gate removes EPOLLIN, which is the symptom under test.
            if ((connection->armed & EPOLLIN) != 0) {
                ++values.read_armed_connections;
            }
            values.budget_pauses_total += connection->budget_pauses;
            values.budget_resumes_total += connection->budget_resumes;
            values.max_pause_age_ms = std::max(values.max_pause_age_ms,
                                              connection->budget_pause_max_ms);
            if (serving) {
                std::uint64_t worst = connection->rtt_last_us;
                if (!connection->pending_pings.empty() &&
                    now > connection->pending_pings.front().second) {
                    worst = std::max(
                        worst,
                        static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                now - connection->pending_pings.front().second)
                                .count()));
                }
                values.worst_writer_rtt_us =
                    std::max(values.worst_writer_rtt_us, worst);
                if (connection->slow_since != Time{}) ++values.slow_writers;
            }
            if (!connection->budget_paused) continue;
            ++values.budget_paused_connections;
            values.bound_clients_on_paused += connection->clients;
            if (connection->budget_paused_at == Time{} ||
                now <= connection->budget_paused_at) {
                continue;
            }
            const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now - connection->budget_paused_at)
                                 .count();
            const auto age_ms =
                static_cast<std::uint64_t>(age > 0 ? age : 0);
            values.current_pause_age_ms =
                std::max(values.current_pause_age_ms, age_ms);
            // A running pause is part of the maximum: a pause that never
            // resumes must be visibly growing, not frozen at zero.
            values.max_pause_age_ms =
                std::max(values.max_pause_age_ms, age_ms);
        }
    }
    stats_.me_worker(worker_index_, dc, values);
}

void Runtime::Impl::publish_me_answer_age(std::int16_t dc, Time now) noexcept {
    bool seen = false;
    Time last_answer{};
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        for (const auto& connection : found->second.conns) {
            if (!connection || !connection->answer_seen) continue;
            if (!seen || connection->last_answer_at > last_answer) {
                seen = true;
                last_answer = connection->last_answer_at;
            }
        }
    }
    if (!seen) {
        // Empty pool, or every live member is a fresh replacement that has not
        // answered yet. Publishing "absent" is the honest health signal; the
        // previous value must not freeze at "0 s ago" for a dead ME.
        stats_.me_last_answer_clear(worker_index_, dc);
        return;
    }
    const auto age = now > last_answer
                         ? std::chrono::duration_cast<std::chrono::seconds>(
                               now - last_answer)
                               .count()
                         : 0;
    stats_.me_last_answer_age(worker_index_, dc,
                              static_cast<std::uint64_t>(age > 0 ? age : 0));
}

void Runtime::Impl::publish_me_rtt(std::int16_t dc) noexcept {
    // A per-DC gauge must not be "last writer wins" across pool members: the
    // last PONG would otherwise hide a degraded member and oscillate between
    // connections. Publish the mean EMA of the ready members with a sample.
    double sum = 0.0;
    std::size_t samples = 0;
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        for (const auto& connection : found->second.conns) {
            if (!connection || connection->draining) continue;
            if (connection->state != MeConn::State::ready || !connection->rtt_valid) continue;
            sum += connection->rtt_ema_us;
            ++samples;
        }
    }
    if (samples == 0) return; // no fresh sample: keep the last published value
    const double mean = sum / static_cast<double>(samples);
    stats_.me_ping_rtt(worker_index_, dc,
                       static_cast<std::uint64_t>(mean < 0.0 ? 0.0 : mean + 0.5));
}

void Runtime::Impl::publish_me_control(std::int16_t dc) noexcept {
    // Cumulative per DC: the base holds counters folded from replaced
    // connections, plus the mirrored counters of the live ones. Numbers never
    // move backwards when a pool member is closed or replaced.
    std::uint64_t close_conn = 0;
    std::uint64_t close_ext = 0;
    std::uint64_t unknown = 0;
    std::uint64_t malformed = 0;
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        const DcPool& pool = found->second;
        close_conn = pool.control_close_conn;
        close_ext = pool.control_close_ext;
        unknown = pool.control_unknown;
        malformed = pool.control_malformed;
        for (const auto& connection : pool.conns) {
            if (!connection) continue;
            close_conn += connection->control_close_conn;
            close_ext += connection->control_close_ext;
            unknown += connection->control_unknown;
            malformed += connection->control_malformed;
        }
    }
    stats_.me_control(worker_index_, dc, close_conn, close_ext, unknown, malformed);
}

void Runtime::Impl::fold_me_control(MeConn& me) noexcept {
    if (const auto found = me_pool_.find(me.dc); found != me_pool_.end()) {
        DcPool& pool = found->second;
        pool.control_close_conn += me.control_close_conn;
        pool.control_close_ext += me.control_close_ext;
        pool.control_unknown += me.control_unknown;
        pool.control_malformed += me.control_malformed;
    }
    me.control_close_conn = 0;
    me.control_close_ext = 0;
    me.control_unknown = 0;
    me.control_malformed = 0;
}

void Runtime::Impl::fold_me_counters(MeConn& me) noexcept {
    fold_me_control(me);
    if (const auto found = me_pool_.find(me.dc); found != me_pool_.end()) {
        found->second.rx_bytes += me.rx_bytes;
        found->second.tx_bytes += me.tx_bytes;
        // Budget-pause history must survive a pool replacement, otherwise the
        // diagnostic counters would reset exactly when a stuck worker rotates.
        found->second.budget_pauses += me.budget_pauses;
        found->second.budget_resumes += me.budget_resumes;
        found->second.budget_pause_max_ms =
            std::max(found->second.budget_pause_max_ms, me.budget_pause_max_ms);
    }
    me.rx_bytes = 0;
    me.tx_bytes = 0;
    me.budget_pauses = 0;
    me.budget_resumes = 0;
    me.budget_pause_max_ms = 0;
    // The keepalive liveness window compares rx_bytes growth; keep its
    // baseline in sync with the reset mirror (a new window seeds it again).
    me.ping_window_rx = 0;
}

void Runtime::Impl::advance_me_generation(std::int16_t dc, Time now) {
    std::vector<MeEndpoint> candidates;
    const bool route_exists = me_candidates(dc, candidates);
    const auto found = me_pool_.find(dc);
    if (found == me_pool_.end()) {
        if (route_exists) (void)ensure_me(dc, now);
        return;
    }
    DcPool& pool = found->second;
    if (!route_exists) {
        // The DC disappeared from the metadata: draining without a successor is
        // the only legitimate case, and it is bounded by the hard deadline.
        drain_me_pool(dc, now);
        return;
    }
    // Successor first: the current working generation keeps accepting clients
    // and stays a readiness source until the new generation reaches ready.
    pool.desired_generation = ++next_me_generation_;
    const Time deadline = now + detail::me_drain_deadline();
    std::vector<MeConn*> obsolete;
    for (const auto& connection : pool.conns) {
        if (!connection) continue;
        if (connection->scale_draining && connection->generation != pool.serving_generation) {
            connection->scale_draining = false;
            connection->draining_deadline = deadline;
        }
        if (connection->draining) continue;
        if (connection->generation == pool.serving_generation) continue;
        obsolete.push_back(connection.get());
    }
    for (MeConn* connection : obsolete) {
        if (connection->clients == 0) {
            // Never-ready intermediate generation: nothing can be served by it,
            // so it is closed immediately instead of accumulating sockets.
            retire_me(*connection);
        } else {
            // Clients are already bound to it (cold start only): keep them, but
            // never give it new clients.
            connection->draining = true;
            connection->scale_draining = false;
            connection->draining_deadline = deadline;
        }
    }
    (void)ensure_me(dc, now);
}

void Runtime::Impl::drain_me_generations_below(DcPool& pool, std::uint64_t keep, Time now) {
    const Time deadline = now + detail::me_drain_deadline();
    for (auto& connection : pool.conns) {
        if (!connection) continue;
        if (connection->generation >= keep) continue;
        connection->draining = true;
        connection->scale_draining = false;
        connection->draining_deadline = deadline;
    }
}

bool Runtime::Impl::restore_me_serving_generation() {
    bool restored = false;
    for (auto& [dc, pool] : me_pool_) {
        std::vector<MeEndpoint> candidates;
        if (!me_candidates(dc, candidates)) {
            // The DC was dropped from the metadata: no successor can arrive, so
            // the draining connections must expire on their hard deadline.
            continue;
        }
        bool found = false;
        std::uint64_t generation = 0;
        for (const auto& connection : pool.conns) {
            if (!connection || !connection->draining || connection->scale_draining) continue;
            if (connection->state != MeConn::State::ready) continue;
            if (!found || connection->generation > generation) {
                generation = connection->generation;
                found = true;
            }
        }
        if (!found) continue;
        bool promoted = false;
        for (auto& connection : pool.conns) {
            if (!connection || !connection->draining || connection->scale_draining) continue;
            if (connection->generation != generation) continue;
            if (connection->state != MeConn::State::ready) continue;
            connection->draining = false;
            connection->draining_deadline = Time{};
            promoted = true;
        }
        if (!promoted) continue;
        pool.serving_generation = generation;
        publish_me_pool(dc);
        restored = true;
    }
    return restored;
}

void Runtime::Impl::drain_me_pool(std::int16_t dc, Time now) {
    const auto found = me_pool_.find(dc);
    if (found == me_pool_.end()) return;
    DcPool& pool = found->second;
    // A reappearing DC must start from a fresh generation.
    pool.desired_generation = 0;
    pool.scale_target = 1;
    pool.next_scale = Time{};
    pool.low_load_since = Time{};
    pool.pressure_samples = 0;
    const Time deadline = now + detail::me_drain_deadline();
    for (auto& connection : pool.conns) {
        if (!connection) continue;
        connection->draining = true;
        connection->scale_draining = false;
        connection->draining_deadline = deadline;
    }
    publish_me_pool(dc);
    recompute_ready();
}

Runtime::Impl::MeConn* Runtime::Impl::ensure_me(std::int16_t dc, Time now) {
    std::vector<MeEndpoint> candidates;
    if (!me_candidates(dc, candidates)) return nullptr;

    auto [slot, inserted] = me_pool_.try_emplace(dc);
    (void)inserted;
    DcPool& pool = slot->second;
    if (pool.desired_generation == 0) pool.desired_generation = ++next_me_generation_;
    const std::uint64_t generation = pool.desired_generation;

    const std::size_t target = std::clamp<std::size_t>(
        pool.scale_target, 1, config_.me_connections_per_dc);
    // Bound sockets and fixed session overhead even when metadata lists many
    // DCs. Reserve one slot for successor-first metadata replacement.
    std::size_t reactor_writers = 0;
    // Members already dialling or handshaking for this generation. The pool
    // target is reached as a batch, so this is what keeps a cold pool from
    // opening all missing writers in one burst.
    std::size_t pending = 0;
    if (me_generation_count(pool, generation) < target) {
        for (const auto& [other_dc, other_pool] : me_pool_) {
            (void)other_dc;
            reactor_writers += other_pool.conns.size();
        }
        for (const auto& member : pool.conns) {
            if (!member || member->draining || member->generation != generation) continue;
            if (member->state == MeConn::State::connecting ||
                member->state == MeConn::State::handshaking) {
                ++pending;
            }
        }
    }
    const bool successor = pool.serving_generation != 0 &&
                           generation != pool.serving_generation;
    const std::size_t reactor_limit = successor ? 64 : 63;
    // Fill the slots of the requested generation only. The working generation
    // may still be present (successor-first replacement), so counting every
    // non-draining slot would suppress the successor entirely.
    std::size_t dialed = 0;
    while (me_generation_count(pool, generation) < target &&
           pool.conns.size() < 2U * config_.me_connections_per_dc &&
           reactor_writers < reactor_limit &&
           pending < detail::kMePendingBatch &&
           dialed < detail::kMeDialBatch) {
        if (me_generation_count(pool, generation) > 0 && !budget_allows(65536)) {
            note_budget_refusal(control::BudgetRefusal::me_dial);
            break;
        }
        MeConn* connection = nullptr;
        try {
            auto owned = std::make_unique<MeConn>();
            owned->dc = dc;
            owned->generation = generation;
            owned->meta = metadata_snapshot_;
            owned->out.emplace(config_.connection_queue_bytes);
            // Spread pool members over the DC endpoint list instead of dialling
            // the same address from every slot (candidate rotates on failure).
            owned->candidate = pool.conns.size() % candidates.size();
            connection = owned.get();
            // unique_ptr keeps the address stable across vector growth. The
            // object is owned by the pool before any target/me_by_token_ entry
            // is created, so a throw here cannot leave a dangling registration.
            pool.conns.push_back(std::move(owned));
            ++reactor_writers;
            connection->token = add_target(Target{Kind::me, connection});
            connection->ping_token = add_target(Target{Kind::me_ping, connection});
            me_by_token_[connection->token] = connection;
            connect_me(*connection, now);
        } catch (const std::exception&) {
            ++pool.creation_failures_total;
            // One unusable ME slot (allocation or metadata copy failure) is not
            // a reactor failure: roll the partial registration back and let the
            // next metadata poll or retry deadline rebuild the slot.
            if (connection != nullptr) {
                if (connection->ping_token != 0) {
                    deadlines_.erase(connection->ping_token);
                    remove_target(connection->ping_token);
                    connection->ping_token = 0;
                }
                if (connection->token != 0) {
                    deadlines_.erase(connection->token);
                    remove_target(connection->token);
                    me_by_token_.erase(connection->token);
                    connection->token = 0;
                }
                erase_me_from_pool(pool, connection);
            }
            break;
        }
        ++dialed;
        // A successful attempt is now a concurrent handshake and counts against
        // the pool bound; a synchronous failure leaves a backoff member, which
        // does not occupy a dial slot.
        if (connection->state == MeConn::State::connecting ||
            connection->state == MeConn::State::handshaking) {
            ++pending;
        }
    }
    publish_me_pool(dc);
    recompute_ready();
    // The caller only needs an attachable conn. A null result means metadata
    // lost the route entirely, which is the same outcome as a missing DC.
    return pick_me(dc);
}

void Runtime::Impl::reap_me_pool(Time now) {
    for (auto& [dc, pool] : me_pool_) {
        (void)dc;
        std::vector<MeConn*> dead;
        for (const auto& connection : pool.conns) {
            if (!connection || !connection->draining) continue;
            const bool queues_empty = connection->frames.empty() &&
                connection->ready_clients.empty() &&
                connection->remote_close.pending_size() == 0 &&
                (!connection->out || connection->out->empty());
            if (connection->scale_draining ? (connection->clients == 0 && queues_empty)
                                           : (connection->clients == 0 || now >= connection->draining_deadline)) {
                dead.push_back(connection.get());
            }
        }
        for (MeConn* connection : dead) retire_me(*connection);
    }
}

void Runtime::Impl::evict_slow_me_writers(Time now) {
    const auto& tuning = ping_tuning_;
    const auto slow_rtt_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(tuning.slow_rtt).count());
    for (auto& [dc, pool] : me_pool_) {
        MeConn* worst = nullptr;
        std::size_t healthy = 0;
        for (const auto& connection : pool.conns) {
            if (!connection || connection->draining ||
                connection->state != MeConn::State::ready) {
                continue;
            }
            MeConn& me = *connection;
            std::uint64_t pending_age_us = 0;
            if (!me.pending_pings.empty() && now > me.pending_pings.front().second) {
                pending_age_us = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        now - me.pending_pings.front().second)
                        .count());
            }
            const bool slow =
                pending_age_us >= slow_rtt_us || me.rtt_last_us >= slow_rtt_us;
            if (!slow) {
                me.slow_since = Time{};
                ++healthy;
                continue;
            }
            if (me.slow_since == Time{}) me.slow_since = now;
            // Both signals are required: PONG overdue, and client requests left
            // unanswered for the whole window. Either alone is common on a
            // healthy writer (some ME hosts never PONG while relaying fine).
            const bool clients_stalled =
                me.unanswered_since != Time{} &&
                now - me.unanswered_since >= tuning.slow_evict_after;
            if (clients_stalled && now - me.slow_since >= tuning.slow_evict_after &&
                (worst == nullptr || me.slow_since < worst->slow_since)) {
                worst = &me;
            }
        }
        // Never retire the last working writer of a DC: a slow route still
        // beats none, and a slow Telegram side makes every writer slow, so the
        // healthy-sibling requirement also stops a pool-wide replacement storm.
        if (worst == nullptr || healthy == 0 || now < pool.next_slow_evict) continue;
        pool.next_slow_evict = now + tuning.slow_evict_gap;
        ++pool.slow_evictions_total;
        // Stop new admissions and bound the wait of the clients already bound:
        // their conn ids cannot migrate, and on a stalled stream they are not
        // being served anyway. The next scale tick dials the replacement.
        worst->draining = true;
        worst->scale_draining = false;
        worst->draining_deadline = now + tuning.slow_drain;
        publish_me_pool(dc);
        recompute_ready();
        (void)ensure_me(dc, now);
    }
}

void Runtime::Impl::scale_me_pool(std::int16_t dc, Time now) {
    const auto found = me_pool_.find(dc);
    if (found == me_pool_.end()) return;
    DcPool& pool = found->second;
    if (pool.desired_generation == 0) return;
    // A shortfall against the current target is filled on every tick, not only
    // on the 10 s scaling decision. ensure_me() owns the batch bounds, so the
    // pool ramps quickly after a restart without opening all writers at once.
    if (me_generation_count(pool, pool.desired_generation) < pool.scale_target) {
        (void)ensure_me(dc, now);
    }
    if (now < pool.next_scale) return;
    pool.next_scale = now + std::chrono::seconds(10);

    std::size_t clients = 0;
    std::size_t active = 0;
    bool pressure = false;
    bool connecting = false;
    for (const auto& connection : pool.conns) {
        if (!connection) continue;
        clients += connection->clients;
        if (connection->draining || connection->generation != pool.desired_generation) continue;
        ++active;
        connecting |= connection->state != MeConn::State::ready;
        const std::size_t queued = connection->frame_bytes +
            (connection->out ? connection->out->bytes() : 0);
        pressure |= connection->queued_clients > 0 &&
                    queued >= config_.connection_queue_bytes * 3 / 4;
    }
    pool.pressure_samples = pressure ? std::min(pool.pressure_samples + 1, 2U) : 0;
    // Fast ramp: demand alone sets the target up to the configured cap instead
    // of one writer per decision. ceil() so a partial writer is always enough
    // for the clients it carries; scale-down keeps its hysteresis below.
    const std::size_t per_writer =
        std::max<std::size_t>(config_.me_clients_per_writer, 1);
    const std::size_t needed = (clients + per_writer - 1) / per_writer;
    const std::size_t ramp = std::min(
        needed, static_cast<std::size_t>(config_.me_connections_per_dc));
    if (ramp > pool.scale_target) {
        const std::size_t delta = ramp - pool.scale_target;
        pool.scale_target = ramp;
        pool.scale_up_total += delta;
        pool.low_load_since = Time{};
        // Reviving a scale-drained member is cheaper than dialling a new socket
        // and keeps its already-handshaked session.
        std::size_t revived = 0;
        for (auto& connection : pool.conns) {
            if (revived >= delta) break;
            if (!connection || !connection->scale_draining) continue;
            if (connection->generation != pool.desired_generation) continue;
            if (connection->state != MeConn::State::ready) continue;
            connection->scale_draining = false;
            connection->draining = false;
            connection->draining_deadline = Time{};
            ++revived;
        }
        (void)ensure_me(dc, now);
        if (revived > 0) {
            publish_me_pool(dc);
            recompute_ready();
        }
        return;
    }
    const bool needs_more = clients > active * config_.me_clients_per_writer ||
                            pool.pressure_samples >= 2;
    if (needs_more && pool.scale_target < config_.me_connections_per_dc && !connecting) {
        pool.low_load_since = Time{};
        for (auto& connection : pool.conns) {
            if (connection && connection->scale_draining &&
                connection->generation == pool.desired_generation &&
                connection->state == MeConn::State::ready) {
                ++pool.scale_target;
                ++pool.scale_up_total;
                connection->scale_draining = false;
                connection->draining = false;
                connection->draining_deadline = Time{};
                publish_me_pool(dc);
                recompute_ready();
                return;
            }
        }
        if (!budget_allows(65536)) {
            note_budget_refusal(control::BudgetRefusal::me_dial);
            return;
        }
        ++pool.scale_target;
        ++pool.scale_up_total;
        (void)ensure_me(dc, now);
        return;
    }
    const bool low = pool.scale_target > 1 && !pressure &&
        clients * 10 <= (pool.scale_target - 1) * config_.me_clients_per_writer * 7;
    if (!low) {
        pool.low_load_since = Time{};
        return;
    }
    if (pool.low_load_since == Time{}) {
        pool.low_load_since = now;
        return;
    }
    if (now - pool.low_load_since < std::chrono::minutes(5)) return;
    MeConn* victim = nullptr;
    for (auto& connection : pool.conns) {
        if (!connection || connection->draining ||
            connection->generation != pool.desired_generation) continue;
        if (!victim || connection->clients < victim->clients) victim = connection.get();
    }
    if (!victim || active <= 1) return;
    --pool.scale_target;
    ++pool.scale_down_total;
    victim->draining = true;
    victim->scale_draining = true;
    victim->draining_deadline = Time::max();
    pool.low_load_since = now;
    publish_me_pool(dc);
    recompute_ready();
}

void Runtime::Impl::retire_me(MeConn& me) {
    const std::int16_t dc = me.dc;
    DcPool* pool = nullptr;
    if (const auto found = me_pool_.find(dc); found != me_pool_.end()) {
        pool = &found->second;
    }
    // Fold inbound control counters and socket bytes before the session is
    // released: the per-DC totals stay monotone across replacements.
    fold_me_counters(me);
    // Retiring is only reached after the hard deadline or at zero clients, but
    // closing is defensive: a connection that leaves the pool must not keep a
    // client bound to a dead MeConn pointer.
    close_me_clients(me);
    const auto token_found = me_by_token_.find(me.token);
    if (token_found != me_by_token_.end() && token_found->second == &me) {
        me_by_token_.erase(token_found);
    }
    shutdown_me(me);
    if (pool != nullptr) {
        erase_me_from_pool(*pool, &me);
        if (pool->conns.empty()) {
            // Empty pools keep their folded control/byte base but must not hand
            // a stale generation to a DC that reappears later.
            pool->desired_generation = 0;
            pool->serving_generation = 0;
        }
    }
    publish_me_pool(dc);
    // Republish the cumulative bytes with the folded base so the series is
    // already correct before the next 1 Hz tick.
    publish_me_io(dc);
    recompute_ready();
}

} // namespace mtdd

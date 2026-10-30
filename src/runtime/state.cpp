#include "internal.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace mtdd {

namespace {

// Endpoint identity of one DC as an order-independent set. `proxy_for` line
// order carries no meaning (the reactor rotates candidates itself), so a pure
// reorder must not look like a metadata replacement.
std::vector<std::pair<std::string, std::uint16_t>> dc_endpoint_set(
    const std::vector<MeEndpoint>& endpoints, std::int16_t dc) {
    std::vector<std::pair<std::string, std::uint16_t>> keys;
    for (const auto& endpoint : endpoints) {
        if (endpoint.dc == dc) keys.emplace_back(endpoint.host, endpoint.port);
    }
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    return keys;
}

} // namespace

std::uint64_t Runtime::Impl::enabled_user_count() const noexcept {
    if (!users_snapshot_) return 0;
    std::uint64_t count = 0;
    for (const auto& user : users_snapshot_->users) {
        if (user.enabled) ++count;
    }
    return count;
}

void Runtime::Impl::poll_users(Time now) {
    auto snapshot = users_.snapshot();
    if (!snapshot) return;
    if (users_snapshot_ && users_snapshot_.get() == snapshot.get()) return;
    const bool initial = !users_snapshot_;
    users_snapshot_ = std::move(snapshot);
    apply_user_snapshot(initial);
    (void)now;
}

void Runtime::Impl::apply_user_snapshot(bool initial) {
    enabled_users_ = enabled_user_count();
    if (!initial && users_snapshot_) {
        std::vector<std::uint64_t> obsolete;
        for (const auto& [token, client] : clients_) {
            if (client->user_name.empty()) continue;
            const auto* user = users_snapshot_->find(client->user_name);
            if (user == nullptr || !user->enabled || user->generation != client->generation) {
                obsolete.push_back(token);
                continue;
            }
            // A live PATCH of the rate limits applies to open sessions too.
            load_client_rates(*client, *user);
            if (client->rate_pause_c2s || client->rate_pause_s2c) {
                next_rate_resume_ = Clock::now();  // re-evaluate against the new rate
            }
        }
        for (const std::uint64_t token : obsolete) {
            close_client(token, control::RelayCloseReason::revoked);
        }
    }
    if (users_snapshot_) barrier_.acknowledge(worker_index_, users_snapshot_->revision);
    recompute_ready();
}

void Runtime::Impl::poll_metadata(Time now) {
    auto snapshot = metadata_.snapshot();
    if (snapshot.get() == metadata_snapshot_.get()) return;
    const auto previous = metadata_snapshot_;
    metadata_snapshot_ = std::move(snapshot);
    if (!metadata_snapshot_) {
        recompute_ready();
        return;
    }
    if (!previous) {
        start_warming(now);
        recompute_ready();
        return;
    }
    const bool secret_changed = previous->secret != metadata_snapshot_->secret;
    std::vector<std::int16_t> changed;
    for (const auto& [dc, pool] : me_pool_) {
        (void)pool;
        // The secret is global: a rotation invalidates every DC route.
        if (secret_changed ||
            dc_endpoint_set(previous->endpoints, dc) !=
                dc_endpoint_set(metadata_snapshot_->endpoints, dc)) {
            changed.push_back(dc);
        }
    }
    for (const std::int16_t dc : changed) {
        // Successor first, drain second: the working generation keeps accepting
        // clients and keeps counting for readiness until the new one is ready.
        // A DC that disappeared from the metadata has no successor; only then
        // are its connections drained against the hard deadline.
        advance_me_generation(dc, now);
    }
    start_warming(now);
    recompute_ready();
}

void Runtime::Impl::start_warming(Time now) {
    if (warming_) return;
    warm_dcs_.clear();
    if (!metadata_snapshot_) return;
    std::vector<std::int16_t> distinct;
    for (const auto& endpoint : metadata_snapshot_->endpoints) {
        if (endpoint.dc == 0) continue;
        if (std::find(distinct.begin(), distinct.end(), endpoint.dc) == distinct.end()) {
            distinct.push_back(endpoint.dc);
        }
    }
    const auto rank = [](std::int16_t dc) {
        if (dc >= 1 && dc <= 5) return 0;
        if (dc <= -1 && dc >= -5) return 1;
        return 2;
    };
    std::sort(distinct.begin(), distinct.end(), [&](std::int16_t left, std::int16_t right) {
        if (rank(left) != rank(right)) return rank(left) < rank(right);
        const int left_abs = left < 0 ? -static_cast<int>(left) : static_cast<int>(left);
        const int right_abs = right < 0 ? -static_cast<int>(right) : static_cast<int>(right);
        if (left_abs != right_abs) return left_abs < right_abs;
        return left < right;
    });
    // Warm every primary and media DC (+/-1..5), not just the first one that
    // answers: a cold DC makes its first client wait for TCP connect plus the
    // ME handshake. Scale-down never removes a DC's last writer, so a warmed
    // pool stays as a floor of one writer. Other ids (CDN/test) stay lazy
    // unless the metadata lists nothing else.
    constexpr std::size_t kFallbackWarmRoutes = 4;
    const auto primary_end = std::find_if(distinct.begin(), distinct.end(),
                                          [&](std::int16_t dc) { return rank(dc) == 2; });
    if (primary_end != distinct.begin()) {
        distinct.erase(primary_end, distinct.end());
    } else if (distinct.size() > kFallbackWarmRoutes) {
        distinct.resize(kFallbackWarmRoutes);
    }
    warm_dcs_ = std::move(distinct);
    warming_ = !warm_dcs_.empty();
    advance_warming(now);
}

void Runtime::Impl::advance_warming(Time now) {
    if (!warming_ || stopping_) return;
    bool complete = true;
    for (const std::int16_t dc : warm_dcs_) {
        const auto found = me_pool_.find(dc);
        bool has_member = false;
        if (found != me_pool_.end()) {
            for (const auto& connection : found->second.conns) {
                if (connection && !connection->draining) {
                    has_member = true;
                    break;
                }
            }
        }
        if (has_member) continue;
        // ensure_me() bounds the dial batch per pool. A member that fails
        // synchronously stays in backoff and is retried by housekeeping.
        // A DC without usable candidates returns null and is not retried here.
        if (ensure_me(dc, now) != nullptr) complete = false;
    }
    if (complete) warming_ = false;
    recompute_ready();
}

void Runtime::Impl::recompute_ready() {
    const bool meta_ok = metadata_snapshot_ && !metadata_snapshot_->endpoints.empty() &&
                         !metadata_snapshot_->secret.empty();
    bool any_ready = false;
    for (const auto& [dc, pool] : me_pool_) {
        (void)dc;
        for (const auto& connection : pool.conns) {
            if (connection && !connection->draining &&
                connection->state == MeConn::State::ready) {
                any_ready = true;
            }
        }
    }
    if (!any_ready) {
        // The successor may die after it took over. The previous generation is
        // still draining with live clients, and it is then the only working
        // route: promote it back instead of reporting not-ready while it still
        // relays. Readiness itself still never counts a draining connection.
        any_ready = restore_me_serving_generation();
    }
    // R1: readiness means a usable (authenticated, ready) ME session exists.
    // Connecting/handshaking/warming are attempt state, not usability. Warming
    // is still driven independently so a usable route is established without
    // waiting for client traffic.
    const bool usable = meta_ok && any_ready;
    set_ready(enabled_users_ > 0 && usable && !stopping_);
}

void Runtime::Impl::set_ready(bool ready) {
    stats_.set_ready(worker_index_, ready);
}

} // namespace mtdd

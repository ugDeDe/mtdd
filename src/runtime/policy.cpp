// Per-user policy enforcement that is not decided at admission: rate limits
// and the periodic expiry/quota sweep.
//
// Rate limit design (per user, enforced per connection):
//   * A user's limit (UserPolicy::rate_limit_*), the per-user media limit and
//     the process-wide media cap are each split evenly over the connections
//     that were active (moved payload) in the last second. Activity is counted
//     by every reactor in its 1 Hz gauge pass and published to shared counters.
//   * Each connection keeps its own GCRA state for its share, so connections
//     slow down evenly and independently: no shared bucket, no shared queue and
//     no lock or atomic on the hot path. An unlimited connection pays one branch.
//   * An overdrawn connection removes EPOLLIN from the source of that direction
//     (and holds already-read ME requests); nothing is dropped or buffered
//     additionally. process_rate_resumes() re-arms it on time.
#include "internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <vector>

namespace mtdd {
namespace {

std::int64_t steady_ns(std::chrono::steady_clock::time_point now) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

constexpr std::uint64_t kRateMinBurstBytes = 64U * 1024U;
// A share never drops below this, so a user with very many active connections
// still makes progress on each of them.
constexpr std::uint64_t kRateMinShareBytes = 1024U;
constexpr std::int64_t kRateMaxCostNs = 1'000'000'000'000'000;

std::int64_t rate_ns_for(std::uint64_t bytes, std::uint64_t rate) noexcept {
    const long double ns = static_cast<long double>(bytes) * 1e9L / static_cast<long double>(rate);
    return ns >= static_cast<long double>(kRateMaxCostNs) ? kRateMaxCostNs
                                                           : static_cast<std::int64_t>(ns);
}

// One second of traffic at the share, at least 64 KiB.
std::int64_t burst_ns(std::uint64_t rate) noexcept {
    return rate_ns_for(std::max(rate, kRateMinBurstBytes), rate);
}

std::uint64_t share_of(std::uint64_t total, std::int64_t active) noexcept {
    if (total == 0) return 0;
    const auto n = static_cast<std::uint64_t>(std::max<std::int64_t>(active, 1));
    return std::max(total / n, kRateMinShareBytes);
}

std::uint64_t tighter(std::uint64_t left, std::uint64_t right) noexcept {
    if (left == 0) return right;
    if (right == 0) return left;
    return std::min(left, right);
}

} // namespace

void Runtime::Impl::load_client_rates(Client& client, const control::UserRecord& user) {
    client.policy_up = user.policy.rate_limit_up_bytes_per_sec.value_or(0);
    client.policy_down = user.policy.rate_limit_down_bytes_per_sec.value_or(0);
    recompute_rate_share(client);
}

void Runtime::Impl::recompute_rate_share(Client& client) noexcept {
    if (client.metrics) client.share_generation = client.metrics->active_generation();
    client.share_media_generation =
        shared_->active_media_generation.load(std::memory_order_relaxed);
    const std::int64_t all = client.metrics ? client.metrics->active_rate_connections() : 1;
    std::uint64_t down = share_of(client.policy_down, all);
    if (client.media) {
        const std::int64_t media = client.metrics ? client.metrics->active_media_connections() : 1;
        down = tighter(down, share_of(shared_->media_user_rate.load(std::memory_order_relaxed),
                                      media));
        down = tighter(down, share_of(shared_->media_total_rate.load(std::memory_order_relaxed),
                                      shared_->active_media_total.load(std::memory_order_relaxed)));
    }
    client.rate_down = down;
    client.rate_up = share_of(client.policy_up, all);
}

bool Runtime::Impl::rate_limited(const Client& client) const noexcept {
    if (client.policy_up != 0 || client.policy_down != 0) return true;
    return client.media &&
           (shared_->media_user_rate.load(std::memory_order_relaxed) != 0 ||
            shared_->media_total_rate.load(std::memory_order_relaxed) != 0);
}

void Runtime::Impl::set_counted_active(Client& client, bool active) noexcept {
    if (client.counted_active == active || !client.metrics) return;
    client.counted_active = active;
    const std::int64_t delta = active ? 1 : -1;
    client.metrics->add_active_connections(delta, client.media ? delta : 0);
    if (client.media) {
        shared_->active_media_total.fetch_add(delta, std::memory_order_relaxed);
        shared_->active_media_generation.fetch_add(1, std::memory_order_relaxed);
    }
    // A newly active connection takes its share right away; the others of
    // the user adjust on the next 1 Hz pass.
    if (active) recompute_rate_share(client);
}

void Runtime::Impl::charge_rate(Client& client, control::Direction direction,
                                std::uint64_t bytes, Time now) {
    // The split changed (a connection of this user, or a media connection
    // anywhere, became active or idle): take the new share before charging.
    if ((client.metrics && client.metrics->active_generation() != client.share_generation) ||
        (client.media && shared_->active_media_generation.load(std::memory_order_relaxed) !=
                             client.share_media_generation)) {
        recompute_rate_share(client);
    }
    const bool up = direction == control::Direction::client_to_server;
    const std::uint64_t rate = up ? client.rate_up : client.rate_down;
    if (rate == 0) return;
    const std::int64_t now_ns = steady_ns(now);
    std::int64_t& tat = up ? client.rate_tat_up : client.rate_tat_down;
    tat = std::max(tat, now_ns) + rate_ns_for(bytes, rate);
    const std::int64_t resume = tat - burst_ns(rate);
    if (resume <= now_ns) return;
    bool& flag = up ? client.rate_pause_c2s : client.rate_pause_s2c;
    if (flag) return;
    flag = true;
    if (!up && client.media) stats_.media_throttled();
    if (!client.rate_listed) {
        client.rate_listed = true;
        rate_clients_.push_back(client.token);
    }
    const Time at = Time(std::chrono::nanoseconds(resume));
    if (at < next_rate_resume_) next_rate_resume_ = at;
    update_client_interest(client);
    if (client.route == Client::Route::direct) update_direct_interest(client);
}

void Runtime::Impl::process_rate_resumes(Time now) {
    if (now < next_rate_resume_) return;
    const std::int64_t now_ns = steady_ns(now);
    Time next = Time::max();
    rate_remaining_.clear();
    // Iterate a copy: resuming may pump held ME requests, which never closes
    // a client synchronously, but keep the list stable regardless.
    std::vector<std::uint64_t> tokens;
    tokens.swap(rate_clients_);
    for (const std::uint64_t token : tokens) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        bool changed = false;
        bool s2c_resumed = false;
        const auto check = [&](bool& flag, std::int64_t tat, std::uint64_t rate, bool s2c) {
            if (!flag) return;
            const std::int64_t resume = rate == 0 ? 0 : tat - burst_ns(rate);
            if (resume <= now_ns) {
                flag = false;
                changed = true;
                if (s2c) s2c_resumed = true;
            } else {
                next = std::min(next, Time(std::chrono::nanoseconds(resume)));
            }
        };
        check(client.rate_pause_c2s, client.rate_tat_up, client.rate_up, false);
        check(client.rate_pause_s2c, client.rate_tat_down, client.rate_down, true);
        if (changed) {
            update_client_interest(client);
            if (client.route == Client::Route::direct) {
                update_direct_interest(client);
            } else if (s2c_resumed) {
                // Requests read before the pause were held; forward them now.
                pump_c2s(client, now);
                if (clients_.find(token) == clients_.end()) continue;
                enqueue_ready(client);
            }
        }
        if (clients_.find(token) == clients_.end()) continue;
        if (client.rate_pause_c2s || client.rate_pause_s2c) {
            rate_remaining_.push_back(token);
        } else {
            client.rate_listed = false;
        }
    }
    rate_clients_.swap(rate_remaining_);
    next_rate_resume_ = next;
}

void Runtime::Impl::sweep_user_policy(Time now) {
    if (!users_snapshot_ || clients_.empty()) return;
    // The snapshot's find() is a linear scan; with many users a per-client
    // lookup made this 1 Hz sweep O(clients x users). Index the users that
    // actually carry an expiry or a quota once per snapshot, and skip the
    // client walk entirely when there are none.
    if (policy_index_snapshot_ != users_snapshot_) {
        policy_index_.clear();
        for (const auto& user : users_snapshot_->users) {
            if (user.policy.expires_at || user.policy.data_quota_bytes) {
                policy_index_.emplace(user.name, &user);
            }
        }
        policy_index_snapshot_ = users_snapshot_;
    }
    if (policy_index_.empty()) return;
    const std::int64_t now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();
    std::vector<std::uint64_t>& doomed = policy_doomed_;
    doomed.clear();
    for (const auto& [token, client] : clients_) {
        if (client->user_name.empty() || !client->metrics) continue;
        const auto indexed = policy_index_.find(client->user_name);
        if (indexed == policy_index_.end()) continue;
        const auto* user = indexed->second;
        const auto& policy = user->policy;
        // Quota enforcement is checked once per sweep, so a live session can
        // overshoot its quota by up to one tick of traffic; that is accepted.
        if ((policy.expires_at && *policy.expires_at <= now_unix) ||
            (policy.data_quota_bytes &&
             client->metrics->quota_used_bytes() >= *policy.data_quota_bytes)) {
            doomed.push_back(token);
        }
    }
    for (const std::uint64_t token : doomed) close_client(token);
    doomed.clear();
    (void)now;
}

} // namespace mtdd

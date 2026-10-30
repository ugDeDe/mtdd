// Per-user policy enforcement that is not decided at admission: the token
// bucket rate limit and the periodic expiry/quota sweep.
//
// Rate limit design:
//   * One GCRA bucket per user per direction lives in control::UserMetrics, so
//     every reactor drains the same bucket.
//   * Clients cache the configured rate (0 = unlimited) so an unlimited user
//     pays a single branch on the hot path. The cache is refreshed from the
//     latest users snapshot, which is how a live PATCH takes effect.
//   * An overdrawn bucket removes EPOLLIN from the source of that direction;
//     no data is dropped or buffered additionally. process_rate_resumes()
//     re-arms it once the bucket has refilled.
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

} // namespace

void Runtime::Impl::load_client_rates(Client& client, const control::UserRecord& user) {
    client.rate_up = user.policy.rate_limit_up_bytes_per_sec.value_or(0);
    client.rate_down = user.policy.rate_limit_down_bytes_per_sec.value_or(0);
}

void Runtime::Impl::charge_rate(Client& client, control::Direction direction,
                                std::uint64_t bytes, Time now) {
    if (!client.metrics) return;
    const bool up = direction == control::Direction::client_to_server;
    const std::uint64_t rate = up ? client.rate_up : client.rate_down;
    if (rate == 0) return;
    const std::int64_t now_ns = steady_ns(now);
    const std::int64_t resume = client.metrics->rate_consume(direction, bytes, rate, now_ns);
    if (resume == 0) return;
    bool& flag = up ? client.rate_pause_c2s : client.rate_pause_s2c;
    if (flag) return;
    flag = true;
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
    // Iterate a copy: update_*_interest never closes a client, but keep the
    // list stable against future changes.
    std::vector<std::uint64_t> tokens;
    tokens.swap(rate_clients_);
    for (const std::uint64_t token : tokens) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        bool changed = false;
        const auto check = [&](bool& flag, control::Direction direction, std::uint64_t rate) {
            if (!flag) return;
            const std::int64_t resume =
                (rate == 0 || !client.metrics)
                    ? 0
                    : client.metrics->rate_resume_at(direction, rate, now_ns);
            if (resume == 0) {
                flag = false;
                changed = true;
            } else {
                next = std::min(next, Time(std::chrono::nanoseconds(resume)));
            }
        };
        check(client.rate_pause_c2s, control::Direction::client_to_server, client.rate_up);
        check(client.rate_pause_s2c, control::Direction::server_to_client, client.rate_down);
        if (changed) {
            update_client_interest(client);
            if (client.route == Client::Route::direct) update_direct_interest(client);
        }
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
    const std::int64_t now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();
    std::vector<std::uint64_t> doomed;
    for (const auto& [token, client] : clients_) {
        if (client->user_name.empty() || !client->metrics) continue;
        const auto* user = users_snapshot_->find(client->user_name);
        if (user == nullptr) continue;  // apply_user_snapshot() owns removal
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
    (void)now;
}

} // namespace mtdd

// Per-user policy enforcement that is not decided at admission: rate limits
// and the periodic expiry/quota sweep.
//
// Rate limit design (per user, enforced per connection):
//   * A user's limit (UserPolicy::rate_limit_*) is split evenly over the
//     user's connections that were active (moved payload) in the last second.
//     Activity is counted by every reactor in its 1 Hz gauge pass and
//     published to shared counters.
//   * Media shaping (Config::shaping, one class per direction) is
//     hierarchical: the process-wide total is split evenly over the users
//     active in the class, a user's part (capped by the rule's or the user's
//     own per-user media limit) over that user's active connections in the
//     class. A user with many connections therefore gets no more of the total
//     than a user with one.
//   * Work-conserving: at every level the split gives "heavy" connections
//     (held at their share in the last second: paused, or moving >= 90% of
//     it) what the "light" ones leave unused, never less than the equal
//     share. Light connections keep the equal share; one that needs more is
//     paused there, turns heavy on the next 1 Hz pass and then takes part in
//     the leftover. A user's light connections count against the user, and
//     light users against the total. The overshoot when light connections
//     all wake up at once is bounded by one second at the equal share.
//   * Each connection keeps its own GCRA state for the tightest of its
//     shares, so connections slow down evenly and independently: no shared
//     bucket, no shared queue and no lock or atomic on the hot path. An
//     unlimited connection pays one branch. A media rule's burst_kib sets the
//     GCRA tolerance while the media share is the binding one.
//   * Shares alone cannot hold a limit: every new connection would start with
//     a fresh GCRA state, and on the ME route requests already sent are
//     answered regardless. So each byte is also charged to shared budgets
//     (control::SharedRateBucket): the user's own, the user's media class and
//     the class total. A direction is paused while its share or any shared
//     budget is overdrawn, and gated before it moves more data, so a new
//     connection waits for an overdrawn budget too. Media requests forwarded
//     to the ME pre-pay kMediaRequestEstimate, so connections resuming at
//     once cannot all send requests into the same budget; answers consume the
//     advance and the unused rest is refunded.
//   * An overdrawn connection removes EPOLLIN from the source of that direction
//     (and holds already-read ME requests); nothing is dropped or buffered
//     additionally. process_rate_resumes() re-arms it on time.
#include "internal.hpp"

#include <algorithm>
#include <array>
#include <initializer_list>
#include <chrono>
#include <cstdint>
#include <optional>
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
// Nor does a split media burst drop below this.
constexpr std::uint64_t kRateMinSplitBurstBytes = 16U * 1024U;
constexpr std::int64_t kRateMaxCostNs = 1'000'000'000'000'000;
// Advance charge per media request forwarded to the ME (a typical
// upload.getFile part); see precharge_media_request().
constexpr std::uint64_t kMediaRequestEstimate = 128U * 1024U;
// Longest a paused connection sleeps before checking the budgets again.
constexpr std::chrono::milliseconds kRateRecheck{250};

std::int64_t rate_ns_for(std::uint64_t bytes, std::uint64_t rate) noexcept {
    const long double ns = static_cast<long double>(bytes) * 1e9L / static_cast<long double>(rate);
    return ns >= static_cast<long double>(kRateMaxCostNs) ? kRateMaxCostNs
                                                           : static_cast<std::int64_t>(ns);
}

// GCRA tolerance: `burst` bytes when set, else one second of traffic at the
// share, at least 64 KiB.
std::int64_t burst_ns(std::uint64_t rate, std::uint64_t burst) noexcept {
    return rate_ns_for(burst != 0 ? burst : std::max(rate, kRateMinBurstBytes), rate);
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

constexpr std::array<control::Direction, 2> kMediaDirections{
    control::Direction::client_to_server, control::Direction::server_to_client};

using RateClass = control::UserMetrics::RateClass;
constexpr std::array<RateClass, 2> kAllClasses{RateClass::up, RateClass::down};
constexpr std::array<RateClass, 2> kMediaClasses{RateClass::media_up, RateClass::media_down};

std::uint64_t nonnegative(std::int64_t value) noexcept {
    return value > 0 ? static_cast<std::uint64_t>(value) : 0U;
}

// Work-conserving share of `budget` for one connection among `active`, of
// which `heavy` are held at their share and the others moved `light` bytes in
// the last second. 0 = unlimited.
std::uint64_t fair_share(std::uint64_t budget, std::int64_t active, std::int64_t heavy,
                         std::int64_t light, bool is_heavy) noexcept {
    if (budget == 0) return 0;
    const std::uint64_t equal = share_of(budget, active);
    if (!is_heavy || heavy <= 0) return equal;
    const std::uint64_t used = nonnegative(light);
    const std::uint64_t spare = budget > used ? budget - used : 0;
    return std::max(equal, spare / static_cast<std::uint64_t>(heavy));
}

} // namespace

void Runtime::Impl::load_client_rates(Client& client, const control::UserRecord& user) {
    client.policy_up = user.policy.rate_limit_up_bytes_per_sec.value_or(0);
    client.policy_down = user.policy.rate_limit_down_bytes_per_sec.value_or(0);
    client.max_devices = user.policy.max_devices.value_or(0);
    const std::array<std::optional<std::uint64_t>, 2> media{
        user.policy.media_rate_limit_up_bytes_per_sec,
        user.policy.media_rate_limit_down_bytes_per_sec};
    for (std::size_t index = 0; index < media.size(); ++index) {
        client.media_policy_set[index] = media[index].has_value();
        client.media_policy[index] = media[index].value_or(0);
    }
    recompute_rate_share(client);
    load_client_ad_tag(client, user);
}

void Runtime::Impl::load_client_ad_tag(Client& client, const control::UserRecord& user) noexcept {
    // The store admits only 32 lowercase hex digits, not all zero; anything
    // else falls back to the global tag.
    const std::string& hex = user.policy.ad_tag;
    client.has_ad_tag = false;
    if (hex.size() != client.ad_tag.bytes.size() * 2) return;
    const auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    bool nonzero = false;
    for (std::size_t i = 0; i < client.ad_tag.bytes.size(); ++i) {
        const int high = digit(hex[i * 2]);
        const int low = digit(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return;
        client.ad_tag.bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
        nonzero = nonzero || client.ad_tag.bytes[i] != 0;
    }
    client.has_ad_tag = nonzero;
}

void Runtime::Impl::assign_media_classes(Client& client, std::int16_t dc) noexcept {
    for (std::size_t index = 0; index < client.media.size(); ++index) {
        client.media[index] = shared_->media[index].selects(dc);
    }
}

void Runtime::Impl::recompute_rate_share(Client& client) noexcept {
    if (client.metrics) client.share_generation = client.metrics->active_generation();
    const auto* metrics = client.metrics.get();
    const std::int64_t all = metrics ? metrics->active_rate_connections() : 1;
    const std::array<std::uint64_t, 2> policy{client.policy_up, client.policy_down};
    // Index 0 = up (client_to_server), 1 = down, as SharedState::media. Both
    // the connection's own share and what a heavy connection of the user gets
    // (published for metrics) are computed.
    std::array<std::uint64_t, 2> rate{};
    std::array<std::uint64_t, 2> heavy_rate{};
    std::array<std::uint64_t, 2> burst{};
    for (std::size_t index = 0; index < 2; ++index) {
        const std::int64_t heavy = metrics ? metrics->heavy_connections(kAllClasses[index]) : 0;
        const std::int64_t light = metrics ? metrics->light_bytes(kAllClasses[index]) : 0;
        rate[index] = fair_share(policy[index], all, heavy, light, client.demand_heavy[index]);
        heavy_rate[index] = fair_share(policy[index], all, heavy, light, true);
        if (!client.media[index]) continue;
        const auto& rule = shared_->media[index];
        client.share_media_generation[index] = rule.generation.load(std::memory_order_relaxed);
        const std::uint64_t user_cap = client.media_policy_set[index]
                                           ? client.media_policy[index]
                                           : rule.user_rate.load(std::memory_order_relaxed);
        const std::uint64_t total = rule.total_rate.load(std::memory_order_relaxed);
        const std::int64_t connections =
            metrics ? metrics->active_media_connections(kMediaDirections[index]) : 1;
        const std::int64_t user_heavy =
            metrics ? metrics->heavy_connections(kMediaClasses[index]) : 0;
        const std::int64_t user_light = metrics ? metrics->light_bytes(kMediaClasses[index]) : 0;
        const std::int64_t users = rule.active_users.load(std::memory_order_relaxed);
        const std::int64_t heavy_users = rule.heavy_users.load(std::memory_order_relaxed);
        const std::int64_t class_light = rule.light_bytes.load(std::memory_order_relaxed);
        const auto media_share = [&](bool is_heavy) {
            // Per-user cap: water-filled over the user's own connections.
            const std::uint64_t by_user =
                fair_share(user_cap, connections, user_heavy, user_light, is_heavy);
            // Total: equal part of an equal user part, or for a heavy
            // connection what light users and light connections leave,
            // split over heavy users and then the user's heavy connections.
            std::uint64_t by_total = 0;
            if (total != 0) {
                by_total = share_of(share_of(total, users), connections);
                if (is_heavy && heavy_users > 0 && user_heavy > 0) {
                    const std::uint64_t used = nonnegative(class_light);
                    const std::uint64_t spare = total > used ? total - used : 0;
                    by_total = std::max(by_total, spare / static_cast<std::uint64_t>(heavy_users) /
                                                      static_cast<std::uint64_t>(user_heavy));
                }
            }
            return tighter(by_user, by_total);
        };
        heavy_rate[index] = tighter(heavy_rate[index], media_share(true));
        const std::uint64_t share = media_share(client.demand_heavy[index]);
        if (share == 0) continue;
        if (rate[index] == 0 || share <= rate[index]) {
            rate[index] = share;
            const std::uint64_t rule_burst = rule.burst.load(std::memory_order_relaxed);
            if (rule_burst != 0) {
                const auto n = static_cast<std::uint64_t>(std::max<std::int64_t>(connections, 1));
                burst[index] = std::max(rule_burst / n, kRateMinSplitBurstBytes);
            }
        }
    }
    client.rate_up = rate[0];
    client.rate_down = rate[1];
    client.burst_up = burst[0];
    client.burst_down = burst[1];
    if (client.metrics && client.counted_active) {
        client.metrics->set_rate_share(control::Direction::client_to_server, heavy_rate[0]);
        client.metrics->set_rate_share(control::Direction::server_to_client, heavy_rate[1]);
    }
}

bool Runtime::Impl::rate_limited(const Client& client) const noexcept {
    if (client.policy_up != 0 || client.policy_down != 0) return true;
    for (std::size_t index = 0; index < 2; ++index) {
        if (!client.media[index]) continue;
        const auto& rule = shared_->media[index];
        const bool user_limited = client.media_policy_set[index]
                                      ? client.media_policy[index] != 0
                                      : rule.user_rate.load(std::memory_order_relaxed) != 0;
        if (user_limited || rule.total_rate.load(std::memory_order_relaxed) != 0) return true;
    }
    return false;
}

void Runtime::Impl::set_counted_active(Client& client, bool active) noexcept {
    if (client.counted_active == active || !client.metrics) return;
    client.counted_active = active;
    const std::int64_t delta = active ? 1 : -1;
    // An idle or closed connection takes its demand out of the split.
    if (!active) {
        for (std::size_t index = 0; index < 2; ++index) set_rate_demand(client, index, false, 0);
    }
    client.metrics->add_active_connections(delta);
    for (std::size_t index = 0; index < 2; ++index) {
        if (!client.media[index]) continue;
        auto& rule = shared_->media[index];
        const int users = client.metrics->add_active_media(kMediaDirections[index], delta);
        if (users != 0) rule.active_users.fetch_add(users, std::memory_order_relaxed);
        rule.generation.fetch_add(1, std::memory_order_relaxed);
    }
    // A newly active connection takes its share right away; the others of
    // the user adjust on the next 1 Hz pass.
    if (active) recompute_rate_share(client);
}

bool Runtime::Impl::rate_share_stale(const Client& client) const noexcept {
    if (client.metrics && client.metrics->active_generation() != client.share_generation) {
        return true;
    }
    for (std::size_t index = 0; index < 2; ++index) {
        if (client.media[index] &&
            shared_->media[index].generation.load(std::memory_order_relaxed) !=
                client.share_media_generation[index]) {
            return true;
        }
    }
    return false;
}

std::size_t Runtime::Impl::shared_limits(Client& client, std::size_t direction,
                                         std::array<SharedLimit, 3>& out) noexcept {
    std::size_t count = 0;
    const std::uint64_t policy = direction == 0 ? client.policy_up : client.policy_down;
    if (client.metrics && policy != 0) {
        out[count++] = {&client.metrics->rate_bucket(kAllClasses[direction]), policy,
                        std::max(policy, kRateMinBurstBytes)};
    }
    if (!client.media[direction]) return count;
    auto& rule = shared_->media[direction];
    const std::uint64_t burst = rule.burst.load(std::memory_order_relaxed);
    const std::uint64_t user_cap = client.media_policy_set[direction]
                                       ? client.media_policy[direction]
                                       : rule.user_rate.load(std::memory_order_relaxed);
    if (client.metrics && user_cap != 0) {
        out[count++] = {&client.metrics->rate_bucket(kMediaClasses[direction]), user_cap,
                        std::max({user_cap, burst, kRateMinBurstBytes})};
    }
    const std::uint64_t total = rule.total_rate.load(std::memory_order_relaxed);
    if (total != 0) {
        out[count++] = {&rule.total_bucket, total, std::max({total, burst, kRateMinBurstBytes})};
    }
    return count;
}

std::int64_t Runtime::Impl::shared_resume(Client& client, std::size_t direction,
                                          std::int64_t now_ns) noexcept {
    std::array<SharedLimit, 3> limits;
    const std::size_t count = shared_limits(client, direction, limits);
    std::int64_t resume = 0;
    for (std::size_t i = 0; i < count; ++i) {
        resume = std::max(resume,
                          limits[i].bucket->resume_at(limits[i].rate, limits[i].tolerance, now_ns));
    }
    return resume;
}

void Runtime::Impl::pause_rate(Client& client, bool up, std::int64_t resume_ns,
                               bool own) noexcept {
    bool& flag = up ? client.rate_pause_c2s : client.rate_pause_s2c;
    const std::size_t index = up ? 0 : 1;
    if (own) {
        client.rate_pause_own[index] = true;
        client.rate_window_paused[index] = true;
    }
    if (flag) return;
    flag = true;
    if (up && client.media[0]) stats_.media_upload_throttled();
    if (!up && client.media[1]) stats_.media_throttled();
    if (!client.rate_listed) {
        client.rate_listed = true;
        rate_clients_.push_back(client.token);
    }
    const Time at = std::min(Time(std::chrono::nanoseconds(resume_ns)),
                             Clock::now() + kRateRecheck);
    if (at < next_rate_resume_) next_rate_resume_ = at;
    update_client_interest(client);
    if (client.route == Client::Route::direct) update_direct_interest(client);
}

bool Runtime::Impl::rate_gate(Client& client, control::Direction direction, Time now) noexcept {
    const bool up = direction == control::Direction::client_to_server;
    bool& flag = up ? client.rate_pause_c2s : client.rate_pause_s2c;
    if (flag) return true;
    if (rate_share_stale(client)) recompute_rate_share(client);
    const std::uint64_t rate = up ? client.rate_up : client.rate_down;
    if (rate == 0) return false;
    const std::int64_t now_ns = steady_ns(now);
    const std::int64_t tat = up ? client.rate_tat_up : client.rate_tat_down;
    const std::int64_t own = tat - burst_ns(rate, up ? client.burst_up : client.burst_down);
    const std::int64_t resume = std::max(own, shared_resume(client, up ? 0 : 1, now_ns));
    if (resume <= now_ns) return false;
    pause_rate(client, up, resume, own > now_ns);
    return true;
}

bool Runtime::Impl::precharge_media_request(Client& client, Time now) noexcept {
    if (!client.media[1] || client.rate_down == 0) return false;
    std::array<SharedLimit, 3> limits;
    const std::size_t count = shared_limits(client, 1, limits);
    if (count == 0) return false;
    const std::int64_t now_ns = steady_ns(now);
    // At most one estimate outstanding per connection: a media connection
    // also carries acks and pings that get no file-sized answer, and an
    // advance per message would leave the budgets in a debt nobody repays.
    // Later messages only check the budgets.
    std::int64_t resume = 0;
    if (client.precharge_down < kMediaRequestEstimate) {
        const std::uint64_t advance = kMediaRequestEstimate - client.precharge_down;
        client.precharge_down += advance;
        for (std::size_t i = 0; i < count; ++i) {
            resume = std::max(resume, limits[i].bucket->charge(advance, limits[i].rate,
                                                               limits[i].tolerance, now_ns));
        }
    } else {
        for (std::size_t i = 0; i < count; ++i) {
            resume = std::max(resume, limits[i].bucket->resume_at(limits[i].rate,
                                                                  limits[i].tolerance, now_ns));
        }
    }
    if (resume <= now_ns) return false;
    pause_rate(client, false, resume, false);
    return true;
}

void Runtime::Impl::refund_precharge(Client& client) noexcept {
    if (client.precharge_down == 0) return;
    std::array<SharedLimit, 3> limits;
    const std::size_t count = shared_limits(client, 1, limits);
    for (std::size_t i = 0; i < count; ++i) {
        limits[i].bucket->refund(client.precharge_down, limits[i].rate);
    }
    client.precharge_down = 0;
    // The budgets moved back: connections waiting on them look again at once.
    if (count != 0) next_rate_resume_ = Time{};
}

void Runtime::Impl::charge_rate(Client& client, control::Direction direction,
                                std::uint64_t bytes, Time now) {
    // The split changed (a connection of this user, or a media user anywhere,
    // became active or idle, or the rule was reloaded): take the new share
    // before charging.
    if (rate_share_stale(client)) recompute_rate_share(client);
    const bool up = direction == control::Direction::client_to_server;
    const std::size_t index = up ? 0 : 1;
    const std::uint64_t rate = up ? client.rate_up : client.rate_down;
    if (rate == 0) return;
    client.rate_window[index] += bytes;
    const std::int64_t now_ns = steady_ns(now);
    std::int64_t& tat = up ? client.rate_tat_up : client.rate_tat_down;
    tat = std::max(tat, now_ns) + rate_ns_for(bytes, rate);
    const std::int64_t own = tat - burst_ns(rate, up ? client.burst_up : client.burst_down);
    std::int64_t resume = own;
    // Shared budgets; an answer first uses up what its request pre-paid.
    std::uint64_t shared_bytes = bytes;
    if (!up && client.precharge_down != 0) {
        const std::uint64_t covered = std::min(shared_bytes, client.precharge_down);
        client.precharge_down -= covered;
        shared_bytes -= covered;
    }
    std::array<SharedLimit, 3> limits;
    const std::size_t count = shared_limits(client, index, limits);
    for (std::size_t i = 0; i < count; ++i) {
        resume = std::max(resume, limits[i].bucket->charge(shared_bytes, limits[i].rate,
                                                           limits[i].tolerance, now_ns));
    }
    if (resume <= now_ns) return;
    pause_rate(client, up, resume, own > now_ns);
}

void Runtime::Impl::set_rate_demand(Client& client, std::size_t direction, bool heavy,
                                    std::int64_t light) noexcept {
    if (!client.metrics) return;
    const std::int64_t heavy_delta =
        static_cast<std::int64_t>(heavy) - static_cast<std::int64_t>(client.demand_heavy[direction]);
    const std::int64_t light_delta = light - client.demand_light[direction];
    if (heavy_delta == 0 && light_delta == 0) return;
    client.demand_heavy[direction] = heavy;
    client.demand_light[direction] = light;
    client.metrics->add_heavy_connections(kAllClasses[direction], heavy_delta);
    client.metrics->add_light_bytes(kAllClasses[direction], light_delta);
    if (!client.media[direction]) return;
    auto& rule = shared_->media[direction];
    const int users = client.metrics->add_heavy_connections(kMediaClasses[direction], heavy_delta);
    client.metrics->add_light_bytes(kMediaClasses[direction], light_delta);
    if (users != 0) rule.heavy_users.fetch_add(users, std::memory_order_relaxed);
    if (light_delta != 0) rule.light_bytes.fetch_add(light_delta, std::memory_order_relaxed);
    // A heavy-set change moves everyone's share; light bytes alone are picked
    // up by the 1 Hz recompute.
    if (heavy_delta != 0) rule.generation.fetch_add(1, std::memory_order_relaxed);
}

void Runtime::Impl::update_rate_demand(Client& client) noexcept {
    const std::array<std::uint64_t, 2> rate{client.rate_up, client.rate_down};
    const std::array<bool, 2>& paused = client.rate_pause_own;
    for (std::size_t index = 0; index < 2; ++index) {
        bool heavy = false;
        std::int64_t light = 0;
        if (client.counted_active && rate[index] != 0) {
            const std::uint64_t moved = client.rate_window[index];
            heavy = client.rate_window_paused[index] || paused[index] ||
                    moved / 9U >= rate[index] / 10U;
            if (!heavy) light = static_cast<std::int64_t>(moved);
        }
        set_rate_demand(client, index, heavy, light);
        // No answer for a whole second: whatever the requests pre-paid is
        // not coming, give it back to the shared budgets. Also while paused:
        // a waiting connection otherwise holds its unused advance (most of
        // 128 KiB after a small photo) for as long as it waits, and many
        // waiting connections then keep the budget overdrawn for everyone.
        // An answer that still arrives later is charged as it comes.
        if (index == 1 && client.rate_window[1] == 0) refund_precharge(client);
        client.rate_window[index] = 0;
        client.rate_window_paused[index] = false;
    }
}

void Runtime::Impl::publish_shaping_state() noexcept {
    for (std::size_t index = 0; index < shared_->media.size(); ++index) {
        const auto& rule = shared_->media[index];
        control::ShapingClassSnapshot entry;
        entry.user_rate_bytes_per_sec = rule.user_rate.load(std::memory_order_relaxed);
        entry.total_rate_bytes_per_sec = rule.total_rate.load(std::memory_order_relaxed);
        entry.burst_bytes = rule.burst.load(std::memory_order_relaxed);
        entry.active_users = std::max<std::int64_t>(rule.active_users.load(std::memory_order_relaxed), 0);
        entry.heavy_users = std::max<std::int64_t>(rule.heavy_users.load(std::memory_order_relaxed), 0);
        entry.light_bytes_per_sec = nonnegative(rule.light_bytes.load(std::memory_order_relaxed));
        stats_.set_shaping_class(index, entry);
    }
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
        const auto check = [&](bool& flag, std::int64_t tat, std::uint64_t rate,
                               std::uint64_t burst, bool s2c) {
            if (!flag) return;
            std::int64_t resume = rate == 0 ? 0 : tat - burst_ns(rate, burst);
            resume = std::max(resume, shared_resume(client, s2c ? 1 : 0, now_ns));
            if (resume <= now_ns) {
                flag = false;
                client.rate_pause_own[s2c ? 1 : 0] = false;
                changed = true;
                if (s2c) s2c_resumed = true;
            } else {
                // Shared budgets also move by refunds and by other reactors:
                // look again soon instead of sleeping to a resume time that
                // a refund may already have brought forward.
                next = std::min({next, Time(std::chrono::nanoseconds(resume)),
                                 now + kRateRecheck});
            }
        };
        check(client.rate_pause_c2s, client.rate_tat_up, client.rate_up, client.burst_up, false);
        check(client.rate_pause_s2c, client.rate_tat_down, client.rate_down, client.burst_down,
              true);
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
        // Payload is batched per connection (detail::PayloadBatch): this
        // reactor's batches were flushed by the 1 Hz pass just before this
        // sweep, other reactors' lag by at most one flush (1 s or 64 KiB per
        // connection), so enforcement may trail the wire by that much more.
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

// Exact online unique-IP accounting. The maps are process-wide (shared by every
// reactor) and touched only on authenticated admission, the one-time byte
// threshold crossing of a connection, and client close, never per packet.
// "Seen" maps count handshakes; "active" maps count only connections that moved
// at least Config::unique_ip_min_bytes, so an IP with several qualified
// connections still counts once. Published values are atomics in
// Statistics/UserMetrics.
#include "internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace mtdd {
namespace {

detail::IpKey make_ip_key(const protocol::Endpoint& peer) {
    const auto wire = peer.wire20();
    detail::IpKey key{};
    std::copy_n(wire.begin(), key.size(), key.begin());
    return detail::collapse_ip_key(key);
}

template <class Map>
void drop_one(Map& map, const detail::IpKey& key) noexcept {
    const auto entry = map.find(key);
    if (entry == map.end()) return;
    if (entry->second > 1) {
        --entry->second;
    } else {
        map.erase(entry);
    }
}

} // namespace

Runtime::Impl::IpCountResult Runtime::Impl::count_client_unique_ip(
    Client& client, std::optional<std::uint32_t> max_unique_ips) {
    if (client.ip_counted) return IpCountResult::ok;
    if (client.metrics == nullptr) return IpCountResult::failure;
    if (client.user_name.empty()) return IpCountResult::failure;

    const detail::IpKey key = make_ip_key(client.peer);
    {
        // Publish the gauges while the maps are still locked: a store after
        // unlock could be overwritten by another reactor's older value, leaving
        // a non-zero gauge after the last client closed.
        const std::lock_guard lock{shared_->ip_mutex};
        bool global_incremented = false;
        bool user_incremented = false;
        if (max_unique_ips) {
            // Check and insert under the same lock so two reactors cannot both
            // admit the limit-th+1 distinct address.
            const auto existing = shared_->user_unique_ip_counts.find(client.user_name);
            if (existing != shared_->user_unique_ip_counts.end() &&
                existing->second.find(key) == existing->second.end() &&
                existing->second.size() >= *max_unique_ips) {
                return IpCountResult::limit;
            }
            if (existing == shared_->user_unique_ip_counts.end() && *max_unique_ips == 0) {
                return IpCountResult::limit;
            }
        }
        try {
            const auto [global, inserted] =
                shared_->unique_ip_counts.try_emplace(key, 0);
            (void)inserted;
            ++global->second;
            global_incremented = true;

            auto& per_user = shared_->user_unique_ip_counts[client.user_name];
            const auto [entry, user_inserted] = per_user.try_emplace(key, 0);
            (void)user_inserted;
            ++entry->second;
            user_incremented = true;
            stats_.set_active_unique_ips(
                static_cast<std::uint64_t>(shared_->unique_ip_counts.size()));
            client.metrics->set_active_unique_ips(
                static_cast<std::uint64_t>(per_user.size()));
        } catch (...) {
            // Roll back without allocating. Leave no empty user map behind.
            if (user_incremented) {
                const auto user =
                    shared_->user_unique_ip_counts.find(client.user_name);
                if (user != shared_->user_unique_ip_counts.end()) {
                    const auto entry = user->second.find(key);
                    if (entry != user->second.end()) {
                        if (entry->second > 1) {
                            --entry->second;
                        } else {
                            user->second.erase(entry);
                        }
                    }
                    if (user->second.empty()) {
                        shared_->user_unique_ip_counts.erase(user);
                    }
                }
            }
            if (global_incremented) {
                const auto global = shared_->unique_ip_counts.find(key);
                if (global != shared_->unique_ip_counts.end()) {
                    if (global->second > 1) {
                        --global->second;
                    } else {
                        shared_->unique_ip_counts.erase(global);
                    }
                }
            }
            return IpCountResult::failure;
        }
    }

    client.ip_key = key;
    client.ip_counted = true;
    return IpCountResult::ok;
}

void Runtime::Impl::qualify_client_unique_ip(Client& client) {
    if (client.ip_qualified || !client.ip_counted || client.metrics == nullptr) return;
    {
        // Same publish-under-lock rule as count_client_unique_ip().
        const std::lock_guard lock{shared_->ip_mutex};
        bool global_incremented = false;
        try {
            ++shared_->active_ip_counts.try_emplace(client.ip_key, 0).first->second;
            global_incremented = true;
            auto& per_user = shared_->user_active_ip_counts[client.user_name];
            ++per_user.try_emplace(client.ip_key, 0).first->second;
            stats_.set_qualified_unique_ips(
                static_cast<std::uint64_t>(shared_->active_ip_counts.size()));
            client.metrics->set_qualified_unique_ips(
                static_cast<std::uint64_t>(per_user.size()));
        } catch (...) {
            // Roll back without allocating; the next payload retries.
            if (global_incremented) drop_one(shared_->active_ip_counts, client.ip_key);
            const auto user = shared_->user_active_ip_counts.find(client.user_name);
            if (user != shared_->user_active_ip_counts.end() && user->second.empty()) {
                shared_->user_active_ip_counts.erase(user);
            }
            return;
        }
        client.ip_qualified = true;
    }
    refresh_ip_history();
    stats_.observe_ip_history_active(client.ip_key);
}

void Runtime::Impl::decrement_client_unique_ip(Client& client) noexcept {
    if (!client.ip_counted) return;
    client.ip_counted = false;

    // Same ordering rule as count_client_unique_ip(): publish under the lock.
    const std::lock_guard lock{shared_->ip_mutex};
    if (client.ip_qualified) {
        client.ip_qualified = false;
        drop_one(shared_->active_ip_counts, client.ip_key);
        stats_.set_qualified_unique_ips(
            static_cast<std::uint64_t>(shared_->active_ip_counts.size()));
        std::uint64_t remaining = 0;
        const auto active_user = shared_->user_active_ip_counts.find(client.user_name);
        if (active_user != shared_->user_active_ip_counts.end()) {
            drop_one(active_user->second, client.ip_key);
            remaining = active_user->second.size();
            if (active_user->second.empty()) shared_->user_active_ip_counts.erase(active_user);
        }
        if (client.metrics) client.metrics->set_qualified_unique_ips(remaining);
    }
    const auto global = shared_->unique_ip_counts.find(client.ip_key);
    if (global != shared_->unique_ip_counts.end()) {
        if (global->second > 1) {
            --global->second;
        } else {
            shared_->unique_ip_counts.erase(global);
        }
    }
    stats_.set_active_unique_ips(
        static_cast<std::uint64_t>(shared_->unique_ip_counts.size()));

    const auto user =
        shared_->user_unique_ip_counts.find(client.user_name);
    if (user != shared_->user_unique_ip_counts.end()) {
        const auto entry = user->second.find(client.ip_key);
        if (entry != user->second.end()) {
            if (entry->second > 1) {
                --entry->second;
            } else {
                user->second.erase(entry);
            }
        }
        if (user->second.empty()) {
            shared_->user_unique_ip_counts.erase(user);
            if (client.metrics) client.metrics->set_active_unique_ips(0);
        } else if (client.metrics) {
            client.metrics->set_active_unique_ips(
                static_cast<std::uint64_t>(user->second.size()));
        }
    } else if (client.metrics) {
        client.metrics->set_active_unique_ips(0);
    }
}

void Runtime::Impl::refresh_ip_history() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    if (!stats_.rotate_ip_history(now)) return;
    // A calendar period changed. Exactly one reactor observes rotate() == true
    // and seeds every currently active exact IP once, so long-lived sessions are
    // represented in the new period without N-fold duplicate observations.
    // The active sketch is seeded only with IPs currently past the threshold.
    std::vector<detail::IpKey> active;
    std::vector<detail::IpKey> qualified;
    {
        const std::lock_guard lock{shared_->ip_mutex};
        active.reserve(shared_->unique_ip_counts.size());
        for (const auto& [key, count] : shared_->unique_ip_counts) {
            if (count != 0) active.push_back(key);
        }
        qualified.reserve(shared_->active_ip_counts.size());
        for (const auto& [key, count] : shared_->active_ip_counts) {
            if (count != 0) qualified.push_back(key);
        }
    }
    for (const auto& key : active) stats_.observe_ip_history(key);
    for (const auto& key : qualified) stats_.observe_ip_history_active(key);
}

} // namespace mtdd

// Per-user device accounting for UserPolicy::max_devices, keyed by the MTProto
// auth_key_id each connection presents (see detail::DeviceTable).
#include "internal.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace mtdd {
namespace detail {

std::uint64_t DeviceTable::prune_locked(Keys& keys, Clock::time_point now,
                                        std::chrono::seconds window) {
    std::unordered_map<std::int16_t, std::uint64_t> per_dc;
    for (auto it = keys.begin(); it != keys.end();) {
        if (it->second.open == 0 && now - it->second.last > window) {
            it = keys.erase(it);
            continue;
        }
        ++per_dc[it->first.dc];
        ++it;
    }
    std::uint64_t devices = 0;
    for (const auto& [dc, count] : per_dc) {
        (void)dc;
        devices = std::max(devices, count);
    }
    return devices;
}

DeviceTable::Admit DeviceTable::admit(const std::string& user, std::int16_t dc,
                                      std::uint64_t key, std::uint32_t max_devices,
                                      Clock::time_point now, std::chrono::seconds window,
                                      std::uint64_t& devices) {
    std::lock_guard<std::mutex> lock(mutex_);
    Keys& keys = users_[user];
    prune_locked(keys, now, window);
    const Key id{key, dc};
    if (const auto found = keys.find(id); found != keys.end()) {
        ++found->second.open;
        found->second.last = now;
        devices = prune_locked(keys, now, window);
        return Admit::ok;
    }
    if (max_devices != 0) {
        std::uint64_t on_dc = 0;
        for (const auto& [other, entry] : keys) {
            (void)entry;
            if (other.dc == dc) ++on_dc;
        }
        if (on_dc >= max_devices) {
            devices = prune_locked(keys, now, window);
            return Admit::limit;
        }
    }
    keys.emplace(id, Entry{1, now});
    devices = prune_locked(keys, now, window);
    return Admit::ok;
}

void DeviceTable::release(const std::string& user, std::int16_t dc, std::uint64_t key,
                          Clock::time_point now, std::chrono::seconds window,
                          std::uint64_t& devices) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto user_it = users_.find(user);
    if (user_it == users_.end()) {
        devices = 0;
        return;
    }
    if (const auto found = user_it->second.find(Key{key, dc}); found != user_it->second.end()) {
        if (found->second.open > 0) --found->second.open;
        found->second.last = now;
    }
    devices = prune_locked(user_it->second, now, window);
}

void DeviceTable::prune(Clock::time_point now, std::chrono::seconds window,
                        std::vector<std::pair<std::string, std::uint64_t>>& counts) {
    std::lock_guard<std::mutex> lock(mutex_);
    counts.clear();
    for (auto it = users_.begin(); it != users_.end();) {
        const std::uint64_t devices = prune_locked(it->second, now, window);
        counts.emplace_back(it->first, devices);
        if (it->second.empty()) {
            it = users_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace detail

bool Runtime::Impl::register_device(Client& client, std::uint64_t auth_key_id, Time now) {
    client.device_scan_left = 0;
    client.direct_scan_skip = 0;
    if (client.device_registered || auth_key_id == 0 || client.user_name.empty()) return true;
    std::uint64_t devices = 0;
    const auto result = shared_->devices.admit(client.user_name, client.device_dc, auth_key_id,
                                               client.max_devices, now, config_.device_window,
                                               devices);
    if (client.metrics) client.metrics->set_devices(devices);
    if (result == detail::DeviceTable::Admit::limit) {
        note_close(client, control::RelayCloseReason::device_limit);
        defer_close(client.token);
        return false;
    }
    client.auth_key_id = auth_key_id;
    client.device_registered = true;
    return true;
}

void Runtime::Impl::release_device(Client& client, Time now) noexcept {
    if (!client.device_registered) return;
    client.device_registered = false;
    try {
        std::uint64_t devices = 0;
        shared_->devices.release(client.user_name, client.device_dc, client.auth_key_id, now,
                                 config_.device_window, devices);
        if (client.metrics) client.metrics->set_devices(devices);
    } catch (...) {
    }
}

bool Runtime::Impl::scan_direct_auth_key(Client& client, std::span<const std::uint8_t> plain,
                                         Time now) {
    // Padded intermediate: [u32 length (bit 31 = quick ack)][payload + padding].
    // The first 8 payload bytes are the auth_key_id (0 = unencrypted key
    // exchange, keep scanning). Only the first frames of a connection are
    // inspected; the relayed bytes are never modified.
    std::size_t offset = 0;
    while (client.device_scan_left != 0 && offset < plain.size()) {
        if (client.direct_scan_skip != 0) {
            const std::size_t take =
                std::min<std::size_t>(client.direct_scan_skip, plain.size() - offset);
            client.direct_scan_skip -= static_cast<std::uint32_t>(take);
            offset += take;
            continue;
        }
        const std::size_t want = client.direct_scan_head.size() - client.direct_scan_have;
        const std::size_t take = std::min(want, plain.size() - offset);
        std::memcpy(client.direct_scan_head.data() + client.direct_scan_have,
                    plain.data() + offset, take);
        client.direct_scan_have = static_cast<std::uint8_t>(client.direct_scan_have + take);
        offset += take;
        if (client.direct_scan_have < client.direct_scan_head.size()) break;
        std::uint32_t length = 0;
        std::uint64_t key = 0;
        for (int i = 3; i >= 0; --i) length = (length << 8) | client.direct_scan_head[i];
        for (int i = 11; i >= 4; --i) key = (key << 8) | client.direct_scan_head[i];
        length &= 0x7fffffffU;
        client.direct_scan_have = 0;
        --client.device_scan_left;
        if (key != 0) return register_device(client, key, now);
        // Skip the rest of this frame (length counts payload + padding).
        client.direct_scan_skip = length > 8 ? length - 8 : 0;
    }
    return true;
}

void Runtime::Impl::publish_devices(Time now) {
    std::vector<std::pair<std::string, std::uint64_t>> counts;
    shared_->devices.prune(now, config_.device_window, counts);
    for (const auto& [name, devices] : counts) {
        if (auto metrics = stats_.user(name)) metrics->set_devices(devices);
    }
}

} // namespace mtdd

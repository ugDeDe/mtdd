// Per-user device accounting for UserPolicy::max_devices, keyed by the MTProto
// auth_key_id each connection presents (see detail::DeviceTable).
#include "internal.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>

namespace mtdd {
namespace detail {

void DeviceTable::erase_key(UserKeys& user, Keys::iterator it) {
    PerDc& dc = user.per_dc[it->first.dc];
    if (dc.count.recent > 0) --dc.count.recent;
    if (it->second.open != 0) {
        if (dc.count.connected > 0) --dc.count.connected;
    } else {
        dc.idle.erase(it->second.idle);
    }
    user.keys.erase(it);
}

void DeviceTable::expire(UserKeys& user, PerDc& dc, Clock::time_point now,
                         std::chrono::seconds window) {
    // Oldest first: stop at the first idle key still inside the window. A key
    // released by another reactor a few microseconds "earlier" may sit behind
    // a newer one; it then expires on a later pass.
    while (!dc.idle.empty()) {
        const auto it = user.keys.find(dc.idle.front());
        if (it == user.keys.end()) {  // never happens; keep the list consistent
            dc.idle.pop_front();
            continue;
        }
        if (now - it->second.last <= window) break;
        erase_key(user, it);
    }
}

DeviceTable::Count DeviceTable::total(const UserKeys& user) {
    Count devices;
    for (const auto& [dc, entry] : user.per_dc) {
        (void)dc;
        devices.recent = std::max(devices.recent, entry.count.recent);
        devices.connected = std::max(devices.connected, entry.count.connected);
    }
    return devices;
}

DeviceTable::Count DeviceTable::prune_locked(UserKeys& user, Clock::time_point now,
                                             std::chrono::seconds window) {
    for (auto it = user.per_dc.begin(); it != user.per_dc.end();) {
        expire(user, it->second, now, window);
        if (it->second.count.recent == 0) {
            it = user.per_dc.erase(it);
        } else {
            ++it;
        }
    }
    return total(user);
}

DeviceTable::Admit DeviceTable::admit(const std::string& user_name, std::int16_t dc,
                                      std::uint64_t key, const protocol::Endpoint& peer,
                                      Platform platform, std::uint32_t max_devices,
                                      Clock::time_point now, std::chrono::seconds window,
                                      Count& devices) {
    std::lock_guard<std::mutex> lock(mutex_);
    UserKeys& user = users_[user_name];
    PerDc& on_dc = user.per_dc[dc];
    const Key id{key, dc};
    if (const auto found = user.keys.find(id); found != user.keys.end()) {
        if (found->second.open++ == 0) {
            on_dc.idle.erase(found->second.idle);
            ++on_dc.count.connected;
        }
        found->second.last = now;
        found->second.peer = peer;
        if (platform != Platform::undefined) found->second.platform = platform;
        devices = total(user);
        return Admit::ok;
    }
    if (max_devices != 0) {
        // The limit counts keys of this DC within the window: expired idle
        // keys are dropped first, so they never hold a slot.
        expire(user, on_dc, now, window);
        if (on_dc.count.recent >= max_devices) {
            // Only devices with an open connection hold a slot: the least
            // recently seen idle key gives way (a switched device, or the
            // previous temporary key of the same one).
            if (on_dc.idle.empty()) {
                devices = total(user);
                return Admit::limit;
            }
            erase_key(user, user.keys.find(on_dc.idle.front()));
        }
    }
    user.keys.emplace(id, Entry{1, now, peer, platform, {}});
    ++on_dc.count.recent;
    ++on_dc.count.connected;
    devices = total(user);
    return Admit::ok;
}

void DeviceTable::release(const std::string& user_name, std::int16_t dc, std::uint64_t key,
                          Clock::time_point now, std::chrono::seconds window,
                          Count& devices) {
    (void)window; // expiry is the periodic prune's job; release stays O(1)
    std::lock_guard<std::mutex> lock(mutex_);
    const auto user_it = users_.find(user_name);
    if (user_it == users_.end()) {
        devices = Count{};
        return;
    }
    UserKeys& user = user_it->second;
    if (const auto found = user.keys.find(Key{key, dc}); found != user.keys.end()) {
        Entry& entry = found->second;
        PerDc& on_dc = user.per_dc[dc];
        if (entry.open > 0) {
            if (--entry.open == 0) {
                if (on_dc.count.connected > 0) --on_dc.count.connected;
                entry.idle = on_dc.idle.insert(on_dc.idle.end(), found->first);
            }
        } else {
            // Already idle: seen again now, so it moves to the young end.
            on_dc.idle.splice(on_dc.idle.end(), on_dc.idle, entry.idle);
        }
        entry.last = now;
    }
    devices = total(user);
}

std::vector<control::Statistics::DeviceInfo> DeviceTable::list(const std::string& user,
                                                               Clock::time_point now,
                                                               std::chrono::seconds window) {
    struct Row {
        Key id;
        std::uint32_t open;
        Clock::time_point last;
        protocol::Endpoint peer;
        Platform platform;
    };
    std::vector<Row> rows;
    {
        // Copy under the lock, format after it: a shared user may list tens of
        // thousands of keys, and every reactor's admit/release waits here.
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = users_.find(user);
        if (found == users_.end()) return {};
        prune_locked(found->second, now, window);
        rows.reserve(found->second.keys.size());
        for (const auto& [id, entry] : found->second.keys) {
            rows.push_back(Row{id, entry.open, entry.last, entry.peer, entry.platform});
        }
    }
    std::vector<control::Statistics::DeviceInfo> out;
    out.reserve(rows.size());
    for (const Row& row : rows) {
        control::Statistics::DeviceInfo info;
        // A short stable tag, not the key itself.
        info.id = static_cast<std::uint32_t>((row.id.auth_key_id * 0x9E3779B97F4A7C15ULL) >> 32);
        info.dc = row.id.dc;
        info.connections = row.open;
        info.idle_seconds =
            row.open != 0
                ? 0
                : std::chrono::duration_cast<std::chrono::seconds>(now - row.last).count();
        char text[INET6_ADDRSTRLEN] = {};
        if (row.peer.ipv6) {
            ::inet_ntop(AF_INET6, row.peer.address.data(), text, sizeof(text));
        } else {
            ::inet_ntop(AF_INET, row.peer.address.data(), text, sizeof(text));
        }
        info.ip = text;
        info.platform = platform_name(row.platform);
        out.push_back(std::move(info));
    }
    return out;
}

void DeviceTable::prune(Clock::time_point now, std::chrono::seconds window,
                        std::vector<std::pair<std::string, Count>>& counts) {
    std::lock_guard<std::mutex> lock(mutex_);
    counts.clear();
    for (auto it = users_.begin(); it != users_.end();) {
        const Count devices = prune_locked(it->second, now, window);
        counts.emplace_back(it->first, devices);
        if (it->second.keys.empty()) {
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
    // A real key: this address hosts a real client (suspect detection).
    if (config_.suspects) shared_->suspects.mark_real(client.peer, now);
    detail::DeviceTable::Count devices;
    const auto result = shared_->devices.admit(client.user_name, client.device_dc, auth_key_id,
                                               client.peer, client.platform, client.max_devices, now, config_.device_window,
                                               devices);
    if (client.metrics) client.metrics->set_devices(devices.recent, devices.connected);
    if (client.watched) {
        char key[24];
        std::snprintf(key, sizeof(key), "%016llx", static_cast<unsigned long long>(auth_key_id));
        watch_log(client, "device",
                  std::string("auth_key_id=") + key + " dc=" + std::to_string(client.device_dc) +
                      " platform=" + detail::platform_name(client.platform) + " result=" +
                      (result == detail::DeviceTable::Admit::limit ? "device_limit" : "ok"));
    }
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
        detail::DeviceTable::Count devices;
        shared_->devices.release(client.user_name, client.device_dc, client.auth_key_id, now,
                                 config_.device_window, devices);
        if (client.metrics) client.metrics->set_devices(devices.recent, devices.connected);
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
        if (client.watched) {
            watch_frame(client, std::span<const std::uint8_t>(client.direct_scan_head).subspan(4),
                        length);
        }
        client.direct_scan_have = 0;
        --client.device_scan_left;
        if (key != 0) return register_device(client, key, now);
        if (client.zero_key_frames != 255) ++client.zero_key_frames;
        // Unencrypted key exchange: the TL constructor follows the 24-byte
        // header. req_DH_params / set_client_DH_params prove a key is being
        // created from this address (see the ME path in client.cpp).
        std::uint32_t constructor = 0;
        for (int i = 27; i >= 24; --i) constructor = (constructor << 8) | client.direct_scan_head[i];
        if (constructor == 0xd712e4beU || constructor == 0xf5045f1fU) {
            client.saw_req_dh = true;
            shared_->suspects.mark_real(client.peer, now);
        }
        // Skip the rest of this frame (we already consumed 24 payload bytes).
        client.direct_scan_skip = length > 24 ? length - 24 : 0;
    }
    return true;
}

void Runtime::Impl::publish_devices(Time now) {
    std::vector<std::pair<std::string, detail::DeviceTable::Count>> counts;
    shared_->devices.prune(now, config_.device_window, counts);
    for (const auto& [name, devices] : counts) {
        if (auto metrics = stats_.user(name)) metrics->set_devices(devices.recent, devices.connected);
    }
}

} // namespace mtdd

// Suspicious-behaviour detection: the per-IP suspect table and the fraud score.
//
// Each signal is recorded once per occurrence on a connection event. The score
// sums, over the distinct signals an address has shown, the signal's weight
// (control::suspect_signal_weight) plus a quarter of it for every repeat, up
// to double. The total is capped at 100 and halves every 24 h since the
// address was last seen, so one stray probe fades while a checker that keeps
// coming back stays high. `matches` (distinct signals) is the primary sort key
// of GET /v1/suspects: two unrelated signals from one address say more than
// one signal repeated many times.
//
// Real clients race connections (several key exchanges, keep the fastest),
// ping proxies with a bare TCP connect, keep stale links and retry hellos, so
// A, E, F, G and H are ambiguous: an address that recently brought a real
// MTProto key (non-zero auth_key_id) neither gets an entry for them nor scores
// them. A checker never brings a key. B, C, D and K always count.
#include "internal.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>

namespace mtdd::detail {
namespace {

constexpr auto kVisitGap = std::chrono::minutes(5);
constexpr auto kMultiModeWindow = std::chrono::seconds(3);
// A session this long is a real client; an address that ever had one is not
// flagged for repeated short visits.
constexpr auto kLongSession = std::chrono::seconds(60);
constexpr std::uint32_t kRepeatVisits = 3;
// A real session keeps its address "real" this long.
constexpr std::int64_t kRealMinutes = 60;
// On a full shard the lowest-scoring of this many oldest entries is evicted,
// so a flood of one-off junk cannot push out a real suspect.
constexpr std::size_t kEvictWindow = 8;

std::int64_t steady_minutes(SuspectTable::Clock::time_point now) {
    return std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch()).count();
}

std::string ip_text(const protocol::Endpoint& peer) {
    char text[INET6_ADDRSTRLEN] = {};
    ::inet_ntop(peer.ipv6 ? AF_INET6 : AF_INET, peer.address.data(), text, sizeof(text));
    return text;
}

const char* layout_text(SynLayout layout) {
    switch (layout) {
        case SynLayout::linux_stack: return "linux";
        case SynLayout::apple_stack: return "apple";
        case SynLayout::windows_stack: return "windows";
        case SynLayout::other: break;
    }
    return "other";
}

const char* tls_text(TlsTemplate tls) {
    switch (tls) {
        case TlsTemplate::safari: return "safari";
        case TlsTemplate::chrome: return "chrome";
        case TlsTemplate::other: break;
    }
    return "other";
}

double hours_between(SuspectTable::Clock::time_point from, SuspectTable::Clock::time_point to) {
    if (to <= from) return 0.0;
    return std::chrono::duration<double, std::ratio<3600>>(to - from).count();
}

std::uint32_t matches_of(const std::array<std::uint32_t, control::kSuspectSignals>& hits) {
    std::uint32_t matches = 0;
    for (const auto count : hits) matches += count != 0 ? 1U : 0U;
    return matches;
}

std::string signals_of(const std::array<std::uint32_t, control::kSuspectSignals>& hits) {
    std::string out;
    for (std::size_t i = 0; i < hits.size(); ++i) {
        if (hits[i] == 0) continue;
        if (!out.empty()) out.push_back(',');
        out += control::to_string(static_cast<control::SuspectSignal>(i));
    }
    return out;
}

} // namespace

IpKey suspect_key(const protocol::Endpoint& peer) noexcept {
    IpKey key{};
    if (peer.ipv6) {
        key = peer.address;
    } else {
        key[10] = 0xff;
        key[11] = 0xff;
        std::memcpy(key.data() + 12, peer.address.data(), 4);
    }
    // IPv6 privacy addresses rotate inside a /64: one host, one entry.
    return collapse_ip_key(key);
}

RawProbe classify_raw_probe(std::span<const std::uint8_t> bytes) noexcept {
    // B: "ee"/"dd" + 32 hex digits (+ hex domain) as ASCII text.
    const auto hex = [](std::uint8_t c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    if (bytes.size() >= 34) {
        const bool prefix = (bytes[0] == 'e' && bytes[1] == 'e') || (bytes[0] == 'd' && bytes[1] == 'd') ||
                            (bytes[0] == 'E' && bytes[1] == 'E') || (bytes[0] == 'D' && bytes[1] == 'D');
        std::size_t run = 0;
        while (run < bytes.size() && hex(bytes[run])) ++run;
        if (prefix && run >= 34) return RawProbe::secret_text;
    }
    // C: the 64-byte obfuscated2 header is random: many distinct byte values,
    // mostly not printable text.
    if (bytes.size() >= 64) {
        std::array<bool, 256> seen{};
        std::size_t distinct = 0;
        std::size_t printable = 0;
        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint8_t c = bytes[i];
            if (!seen[c]) {
                seen[c] = true;
                ++distinct;
            }
            if (c >= 0x20 && c < 0x7f) ++printable;
        }
        if (distinct >= 40 && printable < 48) return RawProbe::raw_obfuscated2;
    }
    return RawProbe::junk;
}

bool domain_covers(std::string_view name, std::string_view domain) {
    const auto lower = [](std::string_view text) {
        std::string out(text);
        for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (!out.empty() && out.back() == '.') out.pop_back();
        return out;
    };
    const std::string host = lower(name);
    const std::string base = lower(domain);
    if (base.empty() || host.empty()) return false;
    return host == base || (host.size() > base.size() &&
                            host.compare(host.size() - base.size() - 1, base.size() + 1,
                                         "." + base) == 0);
}

SuspectTable::SuspectTable(std::size_t capacity)
    : per_shard_(std::max<std::size_t>(capacity / kShards, 16)),
      real_(std::make_unique<std::atomic<std::uint64_t>[]>(kRealSlots)) {
    for (std::size_t i = 0; i < kRealSlots; ++i) real_[i].store(0, std::memory_order_relaxed);
}

void SuspectTable::mark_real(const protocol::Endpoint& peer, Clock::time_point now) {
    const IpKey key = suspect_key(peer);
    const std::uint64_t hash = IpKeyHash{}(key);
    const std::uint64_t tag = (hash >> 32) | 1U;
    const auto minute = static_cast<std::uint32_t>(steady_minutes(now));
    real_[hash & (kRealSlots - 1)].store((tag << 32) | minute, std::memory_order_relaxed);
    Shard& shard = shard_for(key);
    std::lock_guard<std::mutex> lock(shard.mutex);
    if (const auto found = shard.entries.find(key); found != shard.entries.end()) {
        found->second.real = true;
    }
}

bool SuspectTable::recently_real(const protocol::Endpoint& peer, Clock::time_point now) const noexcept {
    const std::uint64_t hash = IpKeyHash{}(suspect_key(peer));
    const std::uint64_t slot = real_[hash & (kRealSlots - 1)].load(std::memory_order_relaxed);
    if (slot == 0 || (slot >> 32) != ((hash >> 32) | 1U)) return false;
    const auto minute = static_cast<std::uint32_t>(slot);
    const auto now_minute = static_cast<std::uint32_t>(steady_minutes(now));
    return static_cast<std::uint32_t>(now_minute - minute) <= kRealMinutes;
}

bool SuspectTable::watch_budget(Clock::time_point now) noexcept {
    const std::int64_t minute = steady_minutes(now);
    std::int64_t current = watch_minute_.load(std::memory_order_relaxed);
    if (current != minute &&
        watch_minute_.compare_exchange_strong(current, minute, std::memory_order_relaxed)) {
        watch_used_.store(0, std::memory_order_relaxed);
    }
    return watch_used_.fetch_add(1, std::memory_order_relaxed) < kWatchPerMinute;
}

SuspectTable::Shard& SuspectTable::shard_for(const IpKey& key) noexcept {
    return shards_[IpKeyHash{}(key) % kShards];
}

double SuspectTable::score_of(const std::array<std::uint32_t, control::kSuspectSignals>& hits,
                              double age_hours, bool real) noexcept {
    double score = 0;
    for (std::size_t i = 0; i < hits.size(); ++i) {
        if (hits[i] == 0) continue;
        const auto signal = static_cast<control::SuspectSignal>(i);
        if (real && control::suspect_signal_ambiguous(signal)) continue;
        const double weight = control::suspect_signal_weight(signal);
        score += weight * (1.0 + 0.25 * std::min<std::uint32_t>(hits[i] - 1, 4));
    }
    score = std::min(score, 100.0);
    return score * std::exp2(-age_hours / 24.0);
}

SuspectTable::Recorded SuspectTable::record(const Context& context, Signal signal,
                                            Clock::time_point now, std::int64_t unix_now,
                                            double watch_score) {
    Recorded out;
    if (context.peer == nullptr) return out;
    // A real client's pings and retries: no entry, no score.
    if (control::suspect_signal_ambiguous(signal) && recently_real(*context.peer, now)) return out;
    const IpKey key = suspect_key(*context.peer);
    Shard& shard = shard_for(key);
    std::lock_guard<std::mutex> lock(shard.mutex);
    auto found = shard.entries.find(key);
    if (found == shard.entries.end()) {
        // Eviction: drop stale queue items (re-inserted or pruned keys, told
        // apart by sequence), then the lowest-scoring of the oldest entries.
        while (shard.entries.size() >= per_shard_ && !shard.order.empty()) {
            for (std::size_t i = 0; i < shard.order.size() && i < kEvictWindow;) {
                const auto old = shard.entries.find(shard.order[i].first);
                if (old == shard.entries.end() || old->second.sequence != shard.order[i].second) {
                    shard.order.erase(shard.order.begin() + static_cast<std::ptrdiff_t>(i));
                } else {
                    ++i;
                }
            }
            if (shard.order.empty()) break;
            std::size_t victim = 0;
            double lowest = 0;
            for (std::size_t i = 0; i < shard.order.size() && i < kEvictWindow; ++i) {
                const Entry& old = shard.entries.find(shard.order[i].first)->second;
                const double score = score_of(old.hits, hours_between(old.last, now), old.real);
                if (i == 0 || score < lowest) {
                    victim = i;
                    lowest = score;
                }
            }
            shard.entries.erase(shard.order[victim].first);
            shard.order.erase(shard.order.begin() + static_cast<std::ptrdiff_t>(victim));
        }
        Entry entry;
        entry.first = now;
        entry.first_unix = unix_now;
        entry.last_visit = now;
        entry.visits = 1;
        entry.sequence = ++shard.sequence;
        found = shard.entries.emplace(key, std::move(entry)).first;
        shard.order.emplace_back(key, found->second.sequence);
        if (shard.order.size() > 2 * per_shard_) {
            std::deque<std::pair<IpKey, std::uint64_t>> rebuilt;
            for (const auto& [k, e] : shard.entries) rebuilt.emplace_back(k, e.sequence);
            std::sort(rebuilt.begin(), rebuilt.end(),
                      [](const auto& a, const auto& b) { return a.second < b.second; });
            shard.order.swap(rebuilt);
        }
    }
    Entry& entry = found->second;
    auto& count = entry.hits[static_cast<std::size_t>(signal)];
    if (count != UINT32_MAX) ++count;
    entry.last = now;
    entry.last_unix = unix_now;
    entry.peer = *context.peer;
    if (context.syn != nullptr && context.syn->valid) entry.syn = *context.syn;
    if (context.platform != Platform::undefined) entry.platform = context.platform;
    if (context.tls != TlsTemplate::other) entry.tls = context.tls;
    if (!context.user.empty()) entry.user = std::string(context.user);
    if (!context.sni.empty()) entry.sni = std::string(context.sni.substr(0, 255));
    if (signal == Signal::raw_obfuscated2) entry.last_raw = now;
    out.score = score_of(entry.hits, 0.0, entry.real);
    out.matches = matches_of(entry.hits);
    if (watch_score > 0 && out.score >= watch_score && !entry.watch_reported) {
        entry.watch_reported = true;
        out.crossed_watch = true;
        out.signals = signals_of(entry.hits);
    }
    return out;
}

SuspectTable::Seen SuspectTable::accept(const protocol::Endpoint& peer, Clock::time_point now) {
    Seen out;
    const IpKey key = suspect_key(peer);
    Shard& shard = shard_for(key);
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto found = shard.entries.find(key);
    if (found == shard.entries.end()) return out;
    Entry& entry = found->second;
    out.known = true;
    if (now - entry.last_visit >= kVisitGap) {
        ++entry.visits;
        out.repeat_visit = entry.visits >= kRepeatVisits && entry.longest_session < kLongSession;
    }
    entry.last_visit = now;
    out.score = score_of(entry.hits, hours_between(entry.last, now), entry.real);
    return out;
}

double SuspectTable::score(const protocol::Endpoint& peer, Clock::time_point now) {
    const IpKey key = suspect_key(peer);
    Shard& shard = shard_for(key);
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto found = shard.entries.find(key);
    if (found == shard.entries.end()) return 0;
    return score_of(found->second.hits, hours_between(found->second.last, now), found->second.real);
}

bool SuspectTable::close_session(const protocol::Endpoint& peer, Clock::time_point auth_at,
                                 Clock::time_point now) {
    const IpKey key = suspect_key(peer);
    Shard& shard = shard_for(key);
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto found = shard.entries.find(key);
    if (found == shard.entries.end()) return false;
    Entry& entry = found->second;
    const auto length = std::chrono::duration_cast<std::chrono::seconds>(now - auth_at);
    entry.longest_session = std::max(entry.longest_session, length);
    if (entry.last_raw == Clock::time_point{}) return false;
    return entry.last_raw >= auth_at - kMultiModeWindow && entry.last_raw <= now;
}

std::vector<control::Statistics::SuspectInfo> SuspectTable::list(Clock::time_point now,
                                                                 std::int64_t unix_now,
                                                                 double watch_score,
                                                                 double ban_score) {
    (void)unix_now;
    std::vector<control::Statistics::SuspectInfo> out;
    for (auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        for (const auto& [key, entry] : shard.entries) {
            (void)key;
            control::Statistics::SuspectInfo info;
            info.ip = ip_text(entry.peer);
            info.hits = entry.hits;
            info.matches = matches_of(entry.hits);
            info.score = score_of(entry.hits, hours_between(entry.last, now), entry.real);
            info.real_client = entry.real;
            info.first_seen = entry.first_unix;
            info.last_seen = entry.last_unix;
            info.visits = entry.visits;
            info.user = entry.user;
            info.sni = entry.sni;
            info.platform = platform_name(entry.platform);
            info.tls = tls_text(entry.tls);
            info.ttl = entry.syn.ttl;
            info.window = entry.syn.window;
            info.mss = entry.syn.mss;
            info.wscale = entry.syn.wscale;
            info.layout = entry.syn.valid ? layout_text(entry.syn.layout) : "unknown";
            info.watched = watch_score > 0 && info.score >= watch_score;
            info.shadow_banned = ban_score > 0 && info.score >= ban_score;
            out.push_back(std::move(info));
        }
    }
    return out;
}

void SuspectTable::prune(Clock::time_point now, std::chrono::hours ttl) {
    for (auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        for (auto it = shard.entries.begin(); it != shard.entries.end();) {
            if (now - it->second.last > ttl) {
                it = shard.entries.erase(it);
            } else {
                ++it;
            }
        }
        if (shard.entries.empty()) shard.order.clear();
    }
}

} // namespace mtdd::detail

namespace mtdd {
namespace {

constexpr auto kProbeSessionMax = std::chrono::seconds(15);

std::int64_t suspect_unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

void Runtime::Impl::suspect(Client& client, control::SuspectSignal signal, std::string_view sni) {
    if (!config_.suspects) return;
    stats_.suspect_event(signal);
    detail::SuspectTable::Context context;
    context.peer = &client.peer;
    context.syn = &client.syn;
    context.platform = client.platform;
    context.user = client.user_name;
    context.sni = sni;
    const auto recorded = shared_->suspects.record(context, signal, Clock::now(), suspect_unix_now(),
                                                   static_cast<double>(config_.suspect_watch_score));
    if (client.watched) {
        watch_log(client, "suspect",
                  std::string("signal=") + control::to_string(signal) +
                      " score=" + std::to_string(static_cast<int>(recorded.score)) +
                      " matches=" + std::to_string(recorded.matches));
    }
    if (recorded.crossed_watch && shared_->suspects.watch_budget(Clock::now())) {
        char ip[INET6_ADDRSTRLEN] = {};
        ::inet_ntop(client.peer.ipv6 ? AF_INET6 : AF_INET, client.peer.address.data(), ip, sizeof(ip));
        std::string line = std::string("mtdd suspect: ip=") + ip +
                           " score=" + std::to_string(static_cast<int>(recorded.score)) +
                           " matches=" + std::to_string(recorded.matches) +
                           " signals=" + recorded.signals +
                           " platform=" + detail::platform_name(client.platform);
        if (!client.user_name.empty()) line += " user=" + client.user_name;
        line += " (per-stage log on)\n";
        (void)!::write(STDERR_FILENO, line.data(), line.size());
        // The rest of this connection is logged stage by stage too.
        if (!client.watched) {
            client.watched = true;
            client.watch_start = client.accepted_at;
        }
    }
}

void Runtime::Impl::suspect_first_bytes(Client& client) {
    if (!config_.suspects) return;
    // Only the 5-byte record header has been read: peek at what follows
    // (left in the socket) to tell a secret sent as text from a raw
    // obfuscated2 header or other junk.
    std::array<std::uint8_t, 96> head{};
    std::size_t have = std::min(client.hello.size(), head.size());
    std::memcpy(head.data(), client.hello.data(), have);
    if (client.fd.valid() && have < head.size()) {
        const ssize_t peeked = ::recv(client.fd.get(), head.data() + have, head.size() - have,
                                      MSG_PEEK | MSG_DONTWAIT);
        if (peeked > 0) have += static_cast<std::size_t>(peeked);
    }
    switch (detail::classify_raw_probe(std::span<const std::uint8_t>(head.data(), have))) {
        case detail::RawProbe::secret_text:
            suspect(client, control::SuspectSignal::secret_text);
            break;
        case detail::RawProbe::raw_obfuscated2:
            suspect(client, control::SuspectSignal::raw_obfuscated2);
            break;
        case detail::RawProbe::junk:
            suspect(client, control::SuspectSignal::junk);
            break;
    }
}

void Runtime::Impl::suspect_close(Client& client, Time now) {
    if (!config_.suspects) return;
    if (client.phase == Client::Phase::tls_hello && client.hello.empty() && client.read_eof) {
        // F: TCP connect and close with nothing sent.
        suspect(client, control::SuspectSignal::port_check);
        return;
    }
    if (client.auth_at == Time{} || client.user_name.empty()) return;
    // A: a valid secret, then only the start of a key exchange (req_pq) and
    // the session ends, and no connection from this address ever got past
    // req_pq (recently_real covers both an existing key and a key creation
    // that reached req_DH_params). A real client's losing race connection
    // stops at req_pq too, but its winning one marks the address real, which
    // retroactively clears this. A checker never advances past req_pq. Closes
    // the proxy caused itself do not count.
    const auto reason = client.close_reason;
    const bool server_side = reason == control::RelayCloseReason::shutdown ||
                             reason == control::RelayCloseReason::revoked ||
                             reason == control::RelayCloseReason::me_lost ||
                             reason == control::RelayCloseReason::backpressure ||
                             reason == control::RelayCloseReason::device_limit;
    // Gated on DC1: the RF audience always authorizes on DC2, so a req_pq to
    // DC1 that never reaches req_DH is not one of their clients racing.
    if (client.phase == Client::Phase::relay && !server_side && client.auth_key_id == 0 &&
        client.device_dc == 1 && !client.device_registered && client.zero_key_frames >= 1 &&
        !client.saw_req_dh && now - client.auth_at <= kProbeSessionMax) {
        suspect(client, control::SuspectSignal::probe_session);
    }
    // D: the same address sent raw obfuscated2 around this FakeTLS session.
    if (shared_->suspects.close_session(client.peer, client.auth_at, now)) {
        suspect(client, control::SuspectSignal::multi_mode);
    }
}

bool Runtime::Impl::suspect_shadow_ban(Client& client, Time now) {
    if (!config_.suspects || config_.suspect_ban_score == 0) return false;
    const double score = shared_->suspects.score(client.peer, now);
    if (score < static_cast<double>(config_.suspect_ban_score)) return false;
    stats_.suspect_shadow_banned();
    if (client.watched) {
        watch_log(client, "shadow_ban", "score=" + std::to_string(static_cast<int>(score)) +
                                             " valid secret sent to masking");
    }
    return true;
}

} // namespace mtdd

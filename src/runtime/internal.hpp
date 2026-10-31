// Private runtime reactor model. Included only by src/runtime/*.cpp.
//
// The reactor is deliberately single-threaded: every socket, timer, queue and
// protocol object below is owned by the thread executing Runtime::run().
#pragma once

#include "me_control.hpp"
#include "mtdd/config.hpp"
#include "mtdd/control.hpp"
#include "mtdd/io.hpp"
#include "mtdd/metadata.hpp"
#include "mtdd/protocol.hpp"
#include "mtdd/runtime.hpp"
#include "mtdd/runtime_support.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <mtdd/usage_state.hpp>

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/epoll.h>

namespace mtdd {

namespace detail {

// Socket read/write batches. The protocol review found that TLS records may be
// larger than 4 KiB, so a 32 KiB batch is used instead of a 4 KiB recv. It is
// still bounded, which keeps one event from monopolising the worker.
inline constexpr std::size_t kReadBatch = 32U * 1024U;
inline constexpr std::size_t kWriteBatch = 64U * 1024U;
// Fixed epoll wait batch. A 64-entry array forced a busy reactor back into
// epoll_wait for every 64 ready descriptors, which starved new handshakes under
// DC2 load. 512 amortises the syscall while keeping the array on the worker
// stack (a few KiB per reactor, independent of the connection count).
inline constexpr std::size_t kEpollBatch = 512;
// Sockets accepted per listener readiness event. Bounded so a connection burst
// cannot monopolise one reactor; the listen backlog holds the remainder.
inline constexpr std::size_t kAcceptBatch = 128;
// Masking-target DNS cache lifetime; probes are rare, so a blocking resolve
// on the reactor at TTL expiry is an acceptable trade-off (documented).
inline constexpr std::chrono::seconds kFallbackResolveTtl{300};
inline constexpr std::size_t kIdleRetainedBytes = 64U * 1024U;
// A client's coalesced ME answers are handed to its queue once they reach this
// size even before the ME read ends, bounding the per-read staging copy.
inline constexpr std::size_t kS2cBatchFlushBytes = 128U * 1024U;

// Releases a worker scratch buffer that grew for one large frame.
inline void trim_buffer(std::vector<std::uint8_t>& buffer) {
    if (buffer.capacity() > kIdleRetainedBytes) {
        std::vector<std::uint8_t>().swap(buffer);
    } else {
        buffer.clear();
    }
}

// Hot-path scratch reset shared by the ME and client worker paths. A per-message
// shrink would malloc/free (mmap/munmap above 128 KiB) for every media response,
// so only genuinely large capacity is released and 64 KiB is kept warm.
// Interior buffers are charged to the relay budget by capacity.
inline constexpr std::size_t kScratchShrinkBytes = 256U * 1024U;
inline constexpr std::size_t kScratchRetainBytes = 64U * 1024U;

inline void trim_scratch(std::vector<std::uint8_t>& buffer) {
    if (buffer.capacity() <= kScratchShrinkBytes) {
        buffer.clear();
        return;
    }
    std::vector<std::uint8_t> warm;
    warm.reserve(kScratchRetainBytes);
    buffer = std::move(warm);
}

// How many ready clients one ME event may drain before yielding. Bounded so a
// busy DC cannot monopolise the reactor; the remainder is re-armed by an
// explicit deadline (kMeReadyWakeDelay) when it can make progress without a
// readiness event.
inline constexpr std::size_t kMeReadyBatch = 64;
inline constexpr std::chrono::milliseconds kMeReadyWakeDelay{1};
// Concurrent dial/handshake budget per DC pool. The pool target follows demand,
// so a cold start or a load step would otherwise open every missing writer at
// once; a shortfall is filled as earlier attempts finish instead.
inline constexpr std::size_t kMePendingBatch = 4;
// Socket attempts admitted by one ensure_me() call. A pool target of 24 is
// reached over several ticks, and a synchronously failing endpoint cannot turn
// one call into a connect storm.
inline constexpr std::size_t kMeDialBatch = 4;
// TCP_USER_TIMEOUT for ME sockets (milliseconds).
inline constexpr unsigned kMeUserTimeoutMs = 30000;

// Bound for configured reactors. Fixed-size statistic arrays use the same cap.
inline constexpr std::size_t kMaxWorkers = 256;

// Replay cache: bounded global set of authenticated canonical ClientHello
// HMACs, retained for the FakeTLS timestamp horizon. One instance is shared by
// every reactor, so insert/evict/size synchronize on an internal mutex; the
// lock is taken once per handshake, never per relayed packet. The capacity is
// sized as kReplayRetention * a sustained authenticated-hello rate, because a
// saturated cache rejects every new unique handshake with reason="overload"
// (documented fail-closed behaviour) and is therefore a second overload cliff
// independent of the relay-buffer budget. 524288 covers ~2180 authenticated
// hellos/s for the full 240 s window (the live node admitted ~890/s at peak)
// and costs memory only as entries actually arrive (roughly 130 B/entry at
// saturation).
inline constexpr std::chrono::seconds kReplayRetention{240};
inline constexpr std::size_t kReplayCapacity = 524288;

// Snapshot/metadata checks happen on this cadence, not per packet.
inline constexpr std::chrono::milliseconds kPollInterval{150};

// Minimum interval between full FIN/read-EOF sweeps. The sweep is also forced
// by the 150 ms housekeeping tick and by an earlier exact EOF deadline, so an
// EOF close is bounded by this cadence without scanning every epoll batch.
inline constexpr std::chrono::milliseconds kEofSweepInterval{150};

// After the client's read EOF, how long a session whose only pending work is
// an unanswered ME request is kept for that reply.
inline constexpr std::chrono::milliseconds kEofReplyGrace{2000};

// After this much inactivity a client releases its empty per-connection
// buffers (output block, TLS/decoder reassembly capacity, staged TLS wire).
// Relay connections are mostly idle between bursts and there can be tens of
// thousands of them, so retained-but-idle capacity is trimmed instead of
// being charged to the global relay-buffer budget for the session lifetime.
// Only empty buffers are released: pending bytes are never touched.
inline constexpr std::chrono::seconds kIdleTrimAfter{1};

// Operation counters for the EOF drain. The reactor is single-threaded; relaxed
// atomics make test-side reads well-defined without affecting hot-path work
// (these are incremented per sweep/visit, not per packet).
struct EofDrainTelemetry {
    std::atomic<std::uint64_t> sweeps{0};
    std::atomic<std::uint64_t> visits{0};
    std::atomic<std::uint64_t> output_pumps{0};
    std::atomic<std::uint64_t> map_lookups{0};
    std::atomic<std::uint64_t> closes{0};
};

EofDrainTelemetry& eof_drain_telemetry() noexcept;

// Client object lifecycle counters. The reactor is single-threaded; relaxed
// atomics only make test-side reads well-defined. These are incremented once
// per connection, not per packet.
struct ClientLifecycleTelemetry {
    // Object source: fresh heap allocation vs. freelist reuse.
    std::atomic<std::uint64_t> allocations{0};
    std::atomic<std::uint64_t> reuses{0};
    std::atomic<std::uint64_t> releases{0};
    std::atomic<std::uint64_t> discards{0};
    // Addresses observed by the test seam, to prove identity reuse.
    std::atomic<std::uintptr_t> last_recycled{0};
    std::atomic<std::uintptr_t> last_reused{0};
    // Current freelist depth (bounded by config.max_connections and
    // kMaxPooledClients; zero after shutdown).
    std::atomic<std::uint64_t> pooled{0};
    // Post-auth retention guard: every transition into relay, and how many of
    // them still carried ClientHello capacity (must stay zero).
    std::atomic<std::uint64_t> relay_transitions{0};
    std::atomic<std::uint64_t> relay_with_hello_capacity{0};
};

ClientLifecycleTelemetry& client_lifecycle_telemetry() noexcept;

// Upper bound on recycled Client objects kept for reuse. Each object is 712 B,
// so the freelist costs at most ~5.6 MiB and is additionally bounded by
// config.max_connections.
inline constexpr std::size_t kMaxPooledClients = 8192;

// Budget headroom kept free for a single event's transient copies.
inline constexpr std::size_t kBudgetHeadroom = 128U * 1024U;

// A Direct DC read event may consume one full kReadBatch plus TLS/queue growth.
// The admission gate reserves this much, not an 8 KiB token, so a pass cannot
// overshoot the reservation by 4x.
inline constexpr std::size_t kDirectReadReservation = kReadBatch + kBudgetHeadroom / 2;

// Client and fallback socket reads must stop admitting data strictly before an
// ME read does. The ME session is shared by every client bound to it: if it is
// paused for budget while clients keep filling the remaining headroom, the
// writer stops receiving, its keepalive window sees no inbound bytes and the
// whole pool member (with all its clients) is failed.
inline constexpr std::size_t kClientReadReservation =
    kReadBatch + kBudgetHeadroom / 2 + 8U * 1024U;

// Test/benchmark-only override for the Direct Telegram DC endpoint. Production
// startup never installs one, so the compiled official address table is used
// unchanged. This exists so local integration tests and the loopback benchmark
// can point the Direct route at a fake DC without touching production config.
struct DirectEndpointOverride {
    std::string host;
    std::uint16_t port{443};
};
void set_direct_endpoint_override(std::optional<DirectEndpointOverride> value);
// Test-only: every automatic masking target (SNI name or tls_domain) dials
// this endpoint instead, so tests never resolve or reach the real domain.
void set_masking_endpoint_override(std::optional<DirectEndpointOverride> value);

// Test-only fault injection. Production never calls these; they let the local
// tests prove failure paths without touching sockets or real crypto.
//
// The Direct hook is a process-global counter: a single injected fault fires in
// exactly one reactor, which is deterministic while workers == 1. Tests that
// need a specific reactor use the per-reactor hook below.
void set_direct_event_throw_for_test(int count);
bool consume_direct_event_throw_for_test();
void set_remote_close_push_failure_for_test(int count);
bool consume_remote_close_push_failure_for_test();

// Test-only fatal-reactor injection. Arms the reactor with `worker_index` to
// throw a synthetic std::runtime_error from its 150 ms housekeeping tick, which
// exercises the "one reactor dies, every reactor stops, run() rethrows"
// contract. Per-reactor so it stays deterministic with N > 1. Production never
// calls it; the arm flag is a single relaxed atomic per reactor slot.
void set_reactor_fatal_for_test(int worker_index);
bool consume_reactor_fatal_for_test(std::size_t worker_index) noexcept;
void clear_reactor_fatal_for_test() noexcept;

// Bounded observation of the Direct EOF/FIN drain branch. Incremented when the
// FIN sweep performs the explicit direct_out pump.
struct DirectDrainTelemetry {
    std::atomic<std::uint64_t> pumps{0};
};
DirectDrainTelemetry& direct_drain_telemetry() noexcept;

// Single-consumer coalescing gate for Direct client->DC writes. Marking is
// idempotent: all records read in one reactor event become one pending flush.
// Clearing before the flush means a would-block retry is driven by EPOLLOUT,
// not an immediate spin or a second flush in the same event.
class DirectFlushGate {
public:
    void mark() noexcept { pending_ = true; }
    [[nodiscard]] bool take() noexcept {
        const bool was_pending = pending_;
        pending_ = false;
        return was_pending;
    }
    void clear() noexcept { pending_ = false; }
    [[nodiscard]] bool pending() const noexcept { return pending_; }

private:
    bool pending_{false};
};

// The ME layer wraps an inner MTProto message in 96 bytes of RPC header and
// frame padding. The client decoder limit is deliberately lower than
// config.max_frame_bytes so that a maximum client message always fits the ME
// frame budget instead of failing after it has been accepted.
inline constexpr std::size_t kMeFrameOverhead = 96;
// Frame length/CRC/CBC padding beyond the RPC header, used by both the C2S
// admission check and the encode-time budget check.
inline constexpr std::size_t kMeEncodeOverhead = 112;
// RPC_CLOSE_CONN payload is 12 bytes; with the 8-byte frame header, 4-byte CRC
// and CBC padding the encoded frame is exactly 32 bytes. Admitting this size
// before encode_close() keeps write_seq/CBC atomic if the frame cannot be
// staged.
inline constexpr std::size_t kEncodedCloseFrameBytes = 32;
// RPC_PING payload is 12 bytes and, like RPC_CLOSE_CONN, is padded to exactly
// 32 encoded bytes. The same pre-encode capacity admission applies: a ping must
// never advance write_seq/CBC if its frame cannot be staged.
inline constexpr std::size_t kEncodedPingFrameBytes = 32;
// When the writer is full, do not busy-poll the ping deadline; retry shortly.
// The pending-PONG deque needs no separate capacity constant: a send is only
// admitted while unanswered_pings < max_unanswered, and only an exact PONG
// match (which clears the whole prefix) or a liveness rescue grows it back to
// zero, so at most max_unanswered ids can ever be pending.
inline constexpr std::chrono::milliseconds kPingBusyRetry{200};
inline constexpr std::size_t kDecoderHeadroom = 128;

// Test-only override for the ME keepalive cadence. Production startup leaves it
// empty, so the compiled 25 s +/- 5 s policy is used unchanged. Tests must not
// wait 25 seconds for a liveness decision.
struct MePingTuning {
    std::chrono::milliseconds interval{25000};
    std::chrono::milliseconds jitter{5000};
    std::size_t max_unanswered{3};
    // Slow-writer containment. A ready writer whose newest PONG sample, or whose
    // oldest unanswered ping, is at least `slow_rtt` is "slow". One that stays
    // slow for `slow_evict_after` is retired from new-client admission and given
    // `slow_drain` for its bound clients, while the pool dials a replacement.
    // The shared stream is head-of-line blocked, so every client on such a
    // writer suffers together; averaging it into a DC gauge only hid it.
    std::chrono::milliseconds slow_rtt{3000};
    std::chrono::milliseconds slow_evict_after{60000};
    std::chrono::milliseconds slow_drain{20000};
    std::chrono::milliseconds slow_evict_gap{10000};
};
void set_me_ping_tuning_for_test(std::optional<MePingTuning> value);
MePingTuning me_ping_tuning();

// Metadata replacement grace period. A draining ME connection keeps serving
// only the clients already bound to it and is retired at zero clients or at
// this hard deadline, whichever comes first. Draining starts only after a
// successor connection of the same DC has reached ready, so readiness never
// depends on the draining connection. Tests shorten it so the forced close path
// is exercised without waiting five minutes.
inline constexpr std::chrono::seconds kMeDrainDeadline{300};
void set_me_drain_deadline_for_test(std::optional<std::chrono::seconds> value);
std::chrono::seconds me_drain_deadline();

using ConnId = protocol::MiddleEndSession::ConnId;

// Normalized peer key: first 16 bytes of Endpoint::wire20(). IPv4 is the
// IPv4-mapped form, so native IPv4 and IPv4-mapped IPv6 share one key; ports
// are ignored. Native IPv6 stays distinct.
using IpKey = std::array<std::uint8_t, 16>;

// Unique-IP counting key: IPv4 and IPv4-mapped addresses stay as they are; any
// other IPv6 address collapses to its /64, because privacy-address rotation
// hands one device many interface identifiers inside one prefix. Applied only
// at the counting boundary (make_ip_key), never to the stored peer address.
inline IpKey collapse_ip_key(IpKey key) noexcept {
    constexpr std::array<std::uint8_t, 12> mapped_prefix{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::equal(mapped_prefix.begin(), mapped_prefix.end(), key.begin())) return key;
    std::fill(key.begin() + 8, key.end(), std::uint8_t{0});
    return key;
}

struct IpKeyHash {
    std::size_t operator()(const IpKey& key) const noexcept {
        std::uint64_t hash = 0xcbf29ce484222325ULL;
        for (const auto byte : key) {
            hash ^= byte;
            hash *= 0x100000001b3ULL;
        }
        return static_cast<std::size_t>(hash);
    }
};

struct ConnIdHash {
    std::size_t operator()(const ConnId& id) const noexcept {
        std::uint64_t value = 0;
        for (const auto byte : id) value = (value << 8) | byte;
        return static_cast<std::size_t>(value * 0x9e3779b97f4a7c15ULL);
    }
};

// Bounded authenticated-ClientHello replay set. Saturation never evicts a live
// entry: new unique handshakes are rejected until entries age out.
struct ReplayHash {
    std::size_t operator()(const std::array<std::uint8_t, 32>& key) const noexcept {
        std::uint64_t hash = 0xcbf29ce484222325ULL;
        for (const auto byte : key) {
            hash ^= byte;
            hash *= 0x100000001b3ULL;
        }
        return static_cast<std::size_t>(hash);
    }
};

class ReplayCache {
public:
    enum class Outcome : std::uint8_t { accepted, duplicate, saturated };

    explicit ReplayCache(std::size_t capacity = kReplayCapacity) noexcept
        : capacity_(capacity) {}

    Outcome insert(const std::array<std::uint8_t, 32>& key,
                   std::chrono::steady_clock::time_point now);
    void evict(std::chrono::steady_clock::time_point now);
    std::size_t size() const noexcept;
    std::size_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept;

private:
    void evict_locked(std::chrono::steady_clock::time_point now);

    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::unordered_map<std::array<std::uint8_t, 32>, std::chrono::steady_clock::time_point,
                       ReplayHash>
        entries_;
    std::deque<std::pair<std::array<std::uint8_t, 32>, std::chrono::steady_clock::time_point>>
        order_;
};

// Coarse client platform (see platform.cpp for the reference fingerprints).
enum class Platform : std::uint8_t { undefined, apple, android, linux_desktop, windows };
enum class SynLayout : std::uint8_t { other, linux_stack, apple_stack, windows_stack };
enum class TlsTemplate : std::uint8_t { other, safari, chrome };
struct SynPrint {
    bool valid{false};
    std::uint8_t ttl{0};
    std::uint16_t window{0};
    std::uint16_t mss{0};
    std::int8_t wscale{-1};
    bool timestamps{false};
    SynLayout layout{SynLayout::other};
};
const char* platform_name(Platform platform) noexcept;
// `syn` is what TCP_SAVED_SYN returns: the IP header followed by the TCP header.
SynPrint parse_saved_syn(std::span<const std::uint8_t> syn) noexcept;
// `record` is the whole ClientHello TLS record, header included.
TlsTemplate classify_client_hello(std::span<const std::uint8_t> record) noexcept;
Platform classify_platform(const SynPrint& syn, TlsTemplate tls) noexcept;

// Config::watch_ips entry: IPv4 is stored IPv4-mapped, its prefix offset by 96.
struct WatchNet {
    std::array<std::uint8_t, 16> address{};
    std::uint8_t prefix{128};
};
std::optional<WatchNet> parse_watch_net(std::string_view text);
bool watch_net_contains(const WatchNet& net, const protocol::Endpoint& peer) noexcept;

// Per-IP suspicious-behaviour table (suspects.cpp), shared by all reactors.
// Touched on connection events only (accept, handshake outcome, close), never
// per packet. Sharded by address; bounded with FIFO eviction.
class SuspectTable {
public:
    using Clock = std::chrono::steady_clock;
    using Signal = control::SuspectSignal;
    struct Context {
        const protocol::Endpoint* peer{nullptr};
        const SynPrint* syn{nullptr};
        Platform platform{Platform::undefined};
        TlsTemplate tls{TlsTemplate::other};
        std::string_view user;
        std::string_view sni;
    };
    struct Recorded {
        double score{0};
        std::uint32_t matches{0};
        bool crossed_watch{false};  // first time at or above the watch score
        std::string signals;        // "probe_session,raw_obfuscated2"
    };
    struct Seen {
        bool known{false};
        double score{0};
        bool repeat_visit{false};  // this accept starts another short visit (G)
    };

    explicit SuspectTable(std::size_t capacity = 65536);
    // A connection from `peer` presented a non-zero auth_key_id: a real
    // client. Lock-free hashed slot, plus a flag on an existing entry.
    void mark_real(const protocol::Endpoint& peer, Clock::time_point now);
    bool recently_real(const protocol::Endpoint& peer, Clock::time_point now) const noexcept;
    // Global budget for automatic per-stage logging: false once
    // kWatchPerMinute connections were put under watch this minute.
    bool watch_budget(Clock::time_point now) noexcept;
    Recorded record(const Context& context, Signal signal, Clock::time_point now,
                    std::int64_t unix_now, double watch_score);
    // An accepted connection: counts visits of known addresses, returns the
    // current score. Never creates an entry.
    Seen accept(const protocol::Endpoint& peer, Clock::time_point now);
    double score(const protocol::Endpoint& peer, Clock::time_point now);
    // Multi-mode correlation (D): a FakeTLS session authenticated at
    // `auth_at` and closing now; true when the same address sent raw
    // obfuscated2 within 3 s of it. Also records the session length (G).
    bool close_session(const protocol::Endpoint& peer, Clock::time_point auth_at,
                       Clock::time_point now);
    std::vector<control::Statistics::SuspectInfo> list(Clock::time_point now,
                                                       std::int64_t unix_now,
                                                       double watch_score, double ban_score);
    void prune(Clock::time_point now, std::chrono::hours ttl);
    static double score_of(const std::array<std::uint32_t, control::kSuspectSignals>& hits,
                           double age_hours, bool real = false) noexcept;
    static constexpr std::uint32_t kWatchPerMinute = 30;
    static constexpr std::size_t kRealSlots = 1U << 16;

private:
    struct Entry {
        std::array<std::uint32_t, control::kSuspectSignals> hits{};
        Clock::time_point first{};
        Clock::time_point last{};
        Clock::time_point last_visit{};
        Clock::time_point last_raw{};       // last raw obfuscated2 (C)
        std::int64_t first_unix{0};
        std::int64_t last_unix{0};
        std::uint32_t visits{0};
        std::chrono::seconds longest_session{0};
        std::uint64_t sequence{0};
        bool watch_reported{false};
        bool real{false};
        protocol::Endpoint peer{};
        SynPrint syn{};
        Platform platform{Platform::undefined};
        TlsTemplate tls{TlsTemplate::other};
        std::string user;
        std::string sni;
    };
    struct Shard {
        std::mutex mutex;
        std::unordered_map<IpKey, Entry, IpKeyHash> entries;
        std::deque<std::pair<IpKey, std::uint64_t>> order;
        std::uint64_t sequence{0};
    };
    static constexpr std::size_t kShards = 16;
    Shard& shard_for(const IpKey& key) noexcept;
    std::size_t per_shard_;
    std::array<Shard, kShards> shards_;
    // (32-bit address tag << 32) | minute of the last real session.
    std::unique_ptr<std::atomic<std::uint64_t>[]> real_;
    std::atomic<std::int64_t> watch_minute_{0};
    std::atomic<std::uint32_t> watch_used_{0};
};
IpKey suspect_key(const protocol::Endpoint& peer) noexcept;

// What a non-TLS first segment looks like (B, C or H).
enum class RawProbe : std::uint8_t { secret_text, raw_obfuscated2, junk };
RawProbe classify_raw_probe(std::span<const std::uint8_t> bytes) noexcept;
// `name` is `domain` or a subdomain of it (case-insensitive, trailing dot ok).
bool domain_covers(std::string_view name, std::string_view domain);

// Leading client frames inspected for a non-zero auth_key_id. Key exchange
// (auth_key_id 0) takes a few frames; nothing after the first key is read.
inline constexpr std::uint8_t kDeviceScanFrames = 16;

// Per-user device table for max_devices. A device is identified by the MTProto
// auth_key_id its connections present, per signed DC (Android keeps a separate
// temporary key for media DCs). One app installation keeps one current key per
// signed DC, so the device count is the maximum over DCs. Only keys with an
// open connection hold a slot against the limit: over the limit, the least
// recently seen idle key is displaced, so a device that disconnected frees its
// slot at once and a rotated temporary key does not lock its own device out.
// Idle keys stay listed (and counted in the gauge) for `window`. Touched once
// per connection (admit/release) and by a periodic prune, never per packet.

class DeviceTable {
public:
    using Clock = std::chrono::steady_clock;
    enum class Admit : std::uint8_t { ok, limit };
    // Max over DCs of the listed keys, and of the keys with an open connection.
    struct Count {
        std::uint64_t recent{0};
        std::uint64_t connected{0};
    };

    Admit admit(const std::string& user, std::int16_t dc, std::uint64_t key,
                const protocol::Endpoint& peer, Platform platform, std::uint32_t max_devices,
                Clock::time_point now,
                std::chrono::seconds window, Count& devices);
    void release(const std::string& user, std::int16_t dc, std::uint64_t key,
                 Clock::time_point now, std::chrono::seconds window, Count& devices);
    // The keys of one user, for GET /v1/users/{name}/devices.
    std::vector<control::Statistics::DeviceInfo> list(const std::string& user,
                                                      Clock::time_point now,
                                                      std::chrono::seconds window);
    // Drops expired keys; reports the device count of every known user.
    void prune(Clock::time_point now, std::chrono::seconds window,
               std::vector<std::pair<std::string, Count>>& counts);

private:
    struct Key {
        std::uint64_t auth_key_id{0};
        std::int16_t dc{0};
        bool operator==(const Key&) const = default;
    };
    struct KeyHash {
        std::size_t operator()(const Key& key) const noexcept {
            return static_cast<std::size_t>(key.auth_key_id ^
                                            (static_cast<std::uint64_t>(
                                                 static_cast<std::uint16_t>(key.dc)) *
                                             0x9e3779b97f4a7c15ULL));
        }
    };
    struct Entry {
        std::uint32_t open{0};
        Clock::time_point last{};
        protocol::Endpoint peer{};
        Platform platform{Platform::undefined};
    };
    using Keys = std::unordered_map<Key, Entry, KeyHash>;
    static Count prune_locked(Keys& keys, Clock::time_point now,
                                      std::chrono::seconds window);

    std::mutex mutex_;
    std::unordered_map<std::string, Keys> users_;
};

// State shared by all reactors. Hot-path relay traffic never touches this
// object; only admission (connection/handshake reservation, replay cache,
// unique-IP accounting) and shutdown coordination do.
struct SharedState {
    SharedState(std::size_t worker_count, std::size_t budget_per_worker)
        : workers(worker_count == 0 ? 1 : worker_count),
          worker_budget(budget_per_worker) {}

    std::atomic<bool> stop{false};
    // Live-reloadable ME pool tunables (Runtime::set_tunables). Reactors pick
    // them up on their housekeeping tick when the generation changes.
    std::atomic<std::uint32_t> me_clients_per_writer{0};
    std::atomic<std::uint32_t> me_connections_per_dc{0};
    std::atomic<std::uint64_t> tunables_generation{0};
    // Media shaping (signed DC < 0, server-to-client bytes), bytes/s; 0 = off.
    // A limit is split evenly over the currently active media connections
    // (per user, and process-wide for the total cap).
    std::atomic<std::uint64_t> media_user_rate{0};
    std::atomic<std::uint64_t> media_total_rate{0};
    std::atomic<std::int64_t> active_media_total{0};
    std::atomic<std::uint64_t> active_media_generation{0};
    void set_media_rates(std::uint64_t user_rate, std::uint64_t total_rate) noexcept {
        media_user_rate.store(user_rate, std::memory_order_relaxed);
        media_total_rate.store(total_rate, std::memory_order_relaxed);
    }
    // SIGHUP handler installed before run(); invoked on the signal reactor.
    std::function<void()> reload_hook;
    DeviceTable devices;
    SuspectTable suspects;
    const std::size_t workers;
    const std::size_t worker_budget;
    ReplayCache replay;

    // Global admission counters. Reservations are CAS loops, so N reactors can
    // enforce one process-wide limit without a per-packet mutex.
    std::atomic<std::uint64_t> connections{0};
    std::atomic<std::uint64_t> handshakes{0};

    // Reactor wake eventfds, written by stop_all(). Guarded because a reactor
    // registers during construction while another may already be running.
    std::mutex wake_mutex;
    std::vector<int> wake_fds;

    // Global unique-IP accounting. Only authenticated admission and close touch
    // these maps, so a mutex here is not on the relay hot path.
    std::mutex ip_mutex;
    std::unordered_map<IpKey, std::uint32_t, IpKeyHash> unique_ip_counts;
    std::unordered_map<std::string,
                       std::unordered_map<IpKey, std::uint32_t, IpKeyHash>>
        user_unique_ip_counts;
    // Same maps restricted to connections that moved >= unique_ip_min_bytes
    // ("active"). Written only when a connection first crosses the threshold
    // and on close, under ip_mutex.
    std::unordered_map<IpKey, std::uint32_t, IpKeyHash> active_ip_counts;
    std::unordered_map<std::string,
                       std::unordered_map<IpKey, std::uint32_t, IpKeyHash>>
        user_active_ip_counts;

    // Number of reactors that have finished finalization. The last one clears
    // shared gauges (unique IPs, replay entries) before the process reports
    // shutdown state.
    std::atomic<std::size_t> exited{0};

    // Test/operations telemetry: accepted clients and replay rejections per
    // reactor, used to prove that SO_REUSEPORT actually distributes work.
    std::array<std::atomic<std::uint64_t>, kMaxWorkers> accepted_per_worker{};
    std::array<std::atomic<std::uint64_t>, kMaxWorkers> replay_rejected_per_worker{};

    bool try_connection(std::uint64_t limit) noexcept {
        if (limit == 0) {
            connections.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return reserve_below(connections, limit);
    }
    void release_connection() noexcept { connections.fetch_sub(1, std::memory_order_relaxed); }
    bool try_handshake(std::uint64_t limit) noexcept {
        if (limit == 0) {
            handshakes.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return reserve_below(handshakes, limit);
    }
    void release_handshake() noexcept { handshakes.fetch_sub(1, std::memory_order_relaxed); }

    void register_wake(int fd);
    // Removes a reactor's eventfd during teardown. Without this a later
    // stop_all() would write to a closed (possibly reused) descriptor.
    void unregister_wake(int fd) noexcept;
    void stop_all() noexcept;

private:
    static bool reserve_below(std::atomic<std::uint64_t>& counter,
                              std::uint64_t limit) noexcept {
        std::uint64_t current = counter.load(std::memory_order_relaxed);
        while (current < limit) {
            if (counter.compare_exchange_weak(current, current + 1,
                                              std::memory_order_relaxed,
                                              std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }
};

// Per-worker acceptance counters are part of SharedState; tests read them
// through Runtime::accepted_clients_per_worker()/replay_rejections_per_worker().

} // namespace detail

struct Runtime::Impl {
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;

    Impl(const Config& config, control::UserStore& users, control::Statistics& statistics,
         MetadataProvider& metadata, RevisionBarrier& barrier,
         std::shared_ptr<detail::SharedState> shared = nullptr,
         std::size_t worker_index = 0, bool reuse_port = false,
         bool signal_owner = true);
    ~Impl();
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    void run();
    void request_stop() noexcept;
    std::uint16_t port() const noexcept { return port_public_.load(std::memory_order_relaxed); }
    std::size_t worker_index() const noexcept { return worker_index_; }

    // ------------------------------------------------------------------
    // Objects
    // ------------------------------------------------------------------
    enum class Kind : std::uint8_t {
        client,
        me,
        listener,
        wake,
        signal,
        fallback_backend,
        direct_backend,
        me_ping
    };

    struct Target {
        Kind kind{Kind::listener};
        void* object{nullptr};
        // For fallback_backend: owner client token. Resolving through clients_
        // avoids dereferencing an object that was closed earlier in a batch.
        std::uint64_t owner{0};
    };

    struct MeConn;

    struct Client {
        enum class Phase : std::uint8_t { tls_hello, tls_handshake, relay, fallback };
        enum class Route : std::uint8_t { me, direct };
        enum class DeadlineKind : std::uint8_t {
            handshake,
            wait_me,
            idle,
            fallback_connect,
            fallback_idle
        };

        std::uint64_t token{};
        io::UniqueFd fd;
        protocol::Endpoint peer;
        Phase phase{Phase::tls_hello};
        Route route{Route::me};
        std::int16_t route_dc{0};
        std::vector<std::uint8_t> hello;
        std::optional<protocol::FakeTlsConnection> tls;
        std::optional<protocol::TransportDecoder> decoder;
        std::optional<io::ByteQueue> out;
        std::vector<std::uint8_t> s2c_wire; // ordered TLS wire not yet queued
        // ME answers for this client decoded during the current ME read,
        // coalesced into open TLS records and written once per read by
        // flush_s2c_batches(). Empty outside read_me().
        std::vector<std::uint8_t> s2c_batch;
        std::size_t s2c_open_record{protocol::FakeTlsConnection::kNoOpenRecord};
        bool in_s2c_batch{false};
        std::size_t s2c_offset{0};
        std::deque<protocol::TransportDecoder::Message> c2s;
        std::size_t c2s_capacity{0}; // allocated bytes of c2s message vectors
        std::string user_name;
        std::uint64_t generation{0};
        std::shared_ptr<control::UserMetrics> metrics;
        detail::ConnId conn_id{};
        MeConn* me{nullptr};
        DeadlineKind deadline_kind{DeadlineKind::handshake};
        Time last_activity{};
        std::uint32_t armed{0};
        std::size_t accounted{0};
        bool connection_counted{false};
        bool metrics_counted{false};
        bool handshake_pending{false};
        bool draining{false};
        bool budget_paused{false};
        bool in_me_queue{false};
        bool conn_registered{false};
        bool deferred{false};
        bool close_requested{false};
        // Rate limits are per user but enforced per connection: each active
        // connection gets an equal share of the user's limit (and of the media
        // limits) with its own GCRA state, so connections slow down evenly and
        // independently. rate_up/rate_down hold this connection's current
        // share in bytes/s (0 = unlimited); the hot path is one branch.
        std::uint64_t rate_up{0};
        std::uint64_t rate_down{0};
        std::uint64_t policy_up{0};    // user's configured total, bytes/s
        std::uint64_t policy_down{0};
        std::int64_t rate_tat_up{0};   // GCRA theoretical arrival time, ns
        std::int64_t rate_tat_down{0};
        // Payload bytes moved since the last 1 Hz pass. A limited connection
        // is counted active at its first bytes (counted_active) and uncounted
        // by the 1 Hz pass after a silent second, or on close.
        std::uint64_t window_bytes{0};
        bool counted_active{false};
        // Generations the current share was computed for (user, media total).
        std::uint64_t share_generation{0};
        std::uint64_t share_media_generation{0};
        // While set, reading from the source of that direction is disabled
        // (EPOLLIN removed); process_rate_resumes() re-arms it.
        bool rate_pause_c2s{false};
        bool rate_pause_s2c{false};
        bool rate_listed{false};
        // Raw-TLS fallback pair state (phase == fallback). `out` is the
        // backend->client queue; c2b is client->backend.
        io::UniqueFd backend;
        std::uint64_t backend_token{0};
        std::optional<io::ByteQueue> c2b;
        std::uint32_t backend_armed{0};
        bool backend_connecting{false};
        bool backend_eof{false};
        bool backend_fin_pending{false};
        Time backend_fin_at{};
        bool backend_budget_paused{false};
        bool backend_write_shutdown{false};
        bool client_write_shutdown{false};
        bool fallback_tracked{false};

        // Direct Telegram DC route (opt-in per signed DC). The client's FakeTLS
        // state stays independent; the direct socket owns its own obfuscated2
        // stream. The authenticated padded-intermediate bytes are relayed
        // verbatim, never decoded and re-framed.
        io::UniqueFd direct_fd;
        std::uint64_t direct_token{0};
        std::uint32_t direct_armed{0};
        bool direct_connecting{false};
        bool direct_eof{false};
        Time direct_eof_at{};
        // RDHUP only says a FIN is queued; like the client path, EOF is latched
        // only on recv()==0. While set, RDHUP is removed from the interest mask
        // (level-triggered) and EPOLLIN stays armed while the client queue has
        // room so the tail can be drained.
        bool direct_fin_pending{false};
        Time direct_fin_at{};
        // The DC->client budget gate refused a read event. While set EPOLLIN is
        // removed so a level-triggered reactor cannot spin on unread data.
        bool direct_budget_paused{false};
        std::optional<io::ByteQueue> direct_out;
        // One or more client records were appended since the last upstream
        // flush. The read event drains the whole client batch (up to kReadBatch)
        // and then flushes once, instead of one sendmsg per FakeTLS record.
        // Pending data always remains covered by EPOLLOUT.
        detail::DirectFlushGate direct_flush;
        std::unique_ptr<protocol::crypto::AesCtr> direct_encrypt;
        std::unique_ptr<protocol::crypto::AesCtr> direct_decrypt;

        bool ip_counted{false};
        detail::IpKey ip_key{};
        // Per-connection payload bytes (c2s+s2c) until the IP qualifies as
        // active; plain reactor-local fields, no lock or lookup per packet.
        bool ip_qualified{false};
        std::uint64_t ip_bytes{0};

        bool read_eof{false};   // recv()==0: socket read side is truly empty
        Time read_eof_at{};
        bool fin_pending{false}; // RDHUP observed: FIN queued, tail may remain
        Time fin_at{};
        bool drain_tracked{false};
        // No ME request correlation exists. This is a conservative heuristic:
        // true between forwarding any C2S message and the next S2C response.
        bool awaiting_reply{false};
        Time last_forward_at{};
        // First recorded reason this relay session is being closed for;
        // published once by close_client() for authenticated sessions.
        control::RelayCloseReason close_reason{control::RelayCloseReason::other};
        bool close_reason_set{false};
        // Signed DC < 0 (file/photo/video downloads): subject to media limits.
        bool media{false};
        // Device accounting (max_devices): the first non-zero auth_key_id the
        // connection presents, registered once in SharedState::devices.
        std::uint64_t auth_key_id{0};
        detail::SynPrint syn;           // from TCP_SAVED_SYN at accept
        // Config::watch_ips: this connection is logged stage by stage.
        bool watched{false};
        // Suspect detection (suspects.cpp): connection timeline and what the
        // first MTProto frames looked like.
        Time accepted_at{};
        Time auth_at{};            // FakeTLS authenticated, Time{} otherwise
        bool canary{false};        // authenticated as a bait user
        std::uint8_t zero_key_frames{0};  // frames with auth_key_id 0 (key exchange)
        bool saw_req_dh{false};    // key exchange went past req_pq
        std::uint8_t watch_frames{0};
        Time watch_start{};
        detail::Platform platform{detail::Platform::undefined};
        std::int16_t device_dc{0};      // signed DC
        std::uint32_t max_devices{0};   // user's policy, 0 = unlimited
        std::uint8_t device_scan_left{0};  // messages still inspected for a key
        bool device_registered{false};
        // Direct route: auth_key_id scan over the relayed padded-intermediate
        // stream (frame length prefix, then the MTProto message).
        std::uint32_t direct_scan_skip{0};
        std::uint8_t direct_scan_have{0};
        std::array<std::uint8_t, 12> direct_scan_head{};
    };

    struct StagedFrame {
        std::vector<std::uint8_t> bytes;
        std::size_t offset{0};
    };

    struct MeConn {
        enum class State : std::uint8_t { idle, connecting, handshaking, ready, backoff };

        std::int16_t dc{0};
        // Reactor-side metadata generation this connection was created for. A
        // newer generation drains every older one of the same DC, but only
        // after it has reached ready (see on_me_ready).
        std::uint64_t generation{0};
        std::uint64_t token{0};
        io::UniqueFd fd;
        State state{State::idle};
        std::size_t candidate{0};
        std::size_t attempt{0};
        Time next_attempt{};
        std::shared_ptr<const MeMetadata> meta;
        std::unique_ptr<protocol::MiddleEndSession> session;
        std::deque<StagedFrame> frames;
        std::size_t frame_bytes{0};
        std::optional<io::ByteQueue> out;
        std::deque<std::uint64_t> ready_clients;
        // Unique live clients currently present in ready_clients. depth minus
        // this value is the duplicate/stale-entry count (must stay zero).
        std::size_t queued_clients{0};
        std::uint64_t rx_bytes{0};
        std::uint64_t tx_bytes{0};
        // RPC_PROXY_ANS callbacks observed for this signed DC. "received" is
        // counted even when the conn id is unknown; only "delivered" means a
        // client actually got the answer.
        std::uint64_t ans_received{0};
        std::uint64_t ans_delivered{0};
        std::uint64_t ans_dropped_unknown{0};
        std::uint64_t ans_dropped_other{0};
        // Last published inbound control counters of THIS TCP connection.
        // Folded into the DC base when the connection is replaced so the
        // per-DC totals never move backwards.
        std::uint64_t control_close_conn{0};
        std::uint64_t control_close_ext{0};
        std::uint64_t control_unknown{0};
        std::uint64_t control_malformed{0};
        // Bounded RPC_CLOSE_CONN feedback for late/orphan answers and acks.
        // Queued from the decoder callback, flushed after feed() returns.
        detail::RemoteCloseControl remote_close;
        Time last_answer_at{};
        bool answer_seen{false};
        std::uint32_t armed{0};
        std::size_t accounted{0};
        bool attempted{false};
        bool failure_deferred{false};
        // The global relay-buffer budget refused a read event. EPOLLIN is
        // removed while set so a level-triggered reactor cannot spin on unread
        // socket data; unpause_clients_if_possible() re-arms it. Unlike a
        // client budget pause this never fails the shared ME session.
        bool budget_paused{false};
        // Worker-diagnostic counters for that pause. `budget_pauses` increments
        // once per false->true transition (not per refused read), `budget_resumes`
        // once when housekeeping clears it. `budget_paused_at` is the monotonic
        // start; `budget_pause_max_ms` retains the longest completed/ongoing
        // pause until the connection is folded into its DC base.
        std::uint64_t budget_pauses{0};
        std::uint64_t budget_resumes{0};
        Time budget_paused_at{};
        std::uint64_t budget_pause_max_ms{0};
        // Keepalive state. ping_token is a separate deadline token because
        // Deadlines allows exactly one deadline per token, and the ME token is
        // already used for handshake/retry/ready-wake scheduling.
        std::uint64_t ping_token{0};
        std::int64_t next_ping_id{1};
        std::deque<std::pair<std::int64_t, Time>> pending_pings;
        std::size_t unanswered_pings{0};
        // rx_bytes snapshot taken when the current unanswered-ping window
        // started. Any growth proves the peer is alive even when it ignores or
        // delays PONG, so a missing PONG alone never tears the connection down.
        std::uint64_t ping_window_rx{0};
        bool rtt_valid{false};
        double rtt_ema_us{0};
        // Newest raw PONG sample (not smoothed): the EMA reacts too slowly to
        // tell a fresh stall from an old one.
        std::uint64_t rtt_last_us{0};
        // First moment the writer was observed slow, Time{} while healthy.
        Time slow_since{};
        // First client request forwarded since the last answer (payload or
        // quick-ack) came back; Time{} once anything is answered. A missing PONG
        // alone does not mean clients are stalled (some ME hosts never PONG
        // while relaying fine), so retirement also requires this to be old.
        Time unanswered_since{};
        // Pool bookkeeping: live clients bound to this exact ME connection.
        // A connection failure closes only these clients; conn ids are
        // protocol-bound and cannot migrate to another ME socket.
        std::size_t clients{0};
        // Metadata replacement: no new client attaches once draining is set.
        // The connection is retired at zero clients or at the hard deadline.
        bool draining{false};
        bool scale_draining{false};
        Time draining_deadline{};
    };

    struct DcPool {
        // Newest metadata generation this pool has been asked to build.
        std::uint64_t desired_generation{0};
        // Newest generation that reached ready and is not draining: the working
        // set new clients attach to. Older generations drain after a newer one
        // becomes ready, so at most one successor generation is built at a
        // time and generations cannot accumulate.
        std::uint64_t serving_generation{0};
        std::size_t scale_target{1};
        Time next_scale{};
        Time low_load_since{};
        unsigned pressure_samples{0};
        std::uint64_t scale_up_total{0};
        std::uint64_t scale_down_total{0};
        std::uint64_t creation_failures_total{0};
        // Writers retired for sustained slow PONGs, and the earliest time the
        // next one may be retired (spreads replacement over several ticks).
        std::uint64_t slow_evictions_total{0};
        Time next_slow_evict{};
        // Inbound control counters accumulated from connections that were
        // already replaced or failed. Keeps mtdd_me_control_frames monotone per
        // DC across replacements.
        std::uint64_t control_close_conn{0};
        std::uint64_t control_close_ext{0};
        std::uint64_t control_unknown{0};
        std::uint64_t control_malformed{0};
        // Worker ME budget-pause totals folded from connections that already
        // left the pool. Published value is base + Σ live members, so the
        // counters stay monotone across replacements (same rule as bytes).
        std::uint64_t budget_pauses{0};
        std::uint64_t budget_resumes{0};
        std::uint64_t budget_pause_max_ms{0};
        // Socket bytes folded from connections that were already replaced or
        // failed. Published value is base + Σ live members, so
        // mtdd_me_{rx,tx}_bytes_total never moves backwards when the pool
        // rotates (see fold_me_counters).
        std::uint64_t rx_bytes{0};
        std::uint64_t tx_bytes{0};
        // unique_ptr keeps MeConn addresses stable across vector growth: open
        // epoll targets, sink callbacks and Client::me all store raw pointers.
        std::vector<std::unique_ptr<MeConn>> conns;
    };

    struct MeSink final : protocol::MiddleEndSession::Sink {
        MeSink(Impl* runtime, MeConn* connection) : impl(runtime), me(connection) {}
        void on_proxy_payload(const detail::ConnId& id,
                              std::span<const std::uint8_t> payload) override;
        void on_quick_ack(const detail::ConnId& id,
                          std::array<std::uint8_t, 4> confirm) override;
        void on_remote_close(const detail::ConnId& id) override;
        void on_pong(std::int64_t ping_id) override;

        Impl* impl;
        MeConn* me;
    };

    // ------------------------------------------------------------------
    // Setup / loop
    // ------------------------------------------------------------------
    void setup();
    void finalize();
    void mark_exited() noexcept;
    bool exit_requested() const noexcept {
        return stop_requested_.load(std::memory_order_relaxed) ||
               shared_->stop.load(std::memory_order_relaxed);
    }
    void begin_shutdown(Time now);
    void shutdown_pump(Time now);
    void handle_event(const Target& target, std::uint32_t events, Time now);
    void process_deadlines(Time now);
    int wait_timeout_ms(Time now) const;
    void housekeeping(Time now);

    std::uint64_t add_target(const Target& target);
    Target* find_target(std::uint64_t token);
    void remove_target(std::uint64_t token);
    void set_interest(std::uint64_t token, int fd, std::uint32_t& armed,
                      std::uint32_t desired);
    void update_client_interest(Client& client);
    void update_fallback_client_interest(Client& client);
    void update_fallback_backend_interest(Client& client);
    void update_me_interest(MeConn& me);
    void update_listener_interest();

    // ------------------------------------------------------------------
    // Budget
    // ------------------------------------------------------------------
    bool budget_allows(std::size_t extra) const;
    void reaccount(Client& client);
    void reaccount(MeConn& me);
    void reaccount_shared();
    void forget_accounting(std::size_t accounted);
    std::size_t shared_bytes() const noexcept;
    void unpause_clients_if_possible(Time now);

    // ------------------------------------------------------------------
    // Users / metadata / readiness
    // ------------------------------------------------------------------
    void poll_users(Time now);
    void poll_metadata(Time now);
    void apply_user_snapshot(bool initial);
    // Per-user policy runtime (src/runtime/policy.cpp).
    void load_client_rates(Client& client, const control::UserRecord& user);
    void charge_rate(Client& client, control::Direction direction, std::uint64_t bytes,
                     Time now);
    void process_rate_resumes(Time now);
    void sweep_user_policy(Time now);
    void recompute_ready();
    void start_warming(Time now);
    void advance_warming(Time now);
    std::uint64_t enabled_user_count() const noexcept;
    void set_ready(bool ready);

    // ------------------------------------------------------------------
    // Clients
    // ------------------------------------------------------------------
    void accept_clients(Time now);
    // `peer` is the address accept4() returned; nullopt falls back to
    // getpeername().
    Client* make_client(io::UniqueFd fd, Time now, control::RejectReason& failure,
                        std::optional<io::Endpoint> peer = std::nullopt);
    // Client object pool. acquire_client() returns a default-constructed,
    // fully reset Client; recycle_client() returns one after close_client has
    // removed every external reference, and is noexcept.
    std::unique_ptr<Client> acquire_client();
    void recycle_client(std::unique_ptr<Client> client) noexcept;
    void release_client_pool() noexcept;
    void handle_client(Client& client, std::uint32_t events, Time now);
    void read_client(Client& client, Time now);
    void consume_client_bytes(Client& client, std::span<const std::uint8_t> wire, Time now);
    void process_client_hello(Client& client, Time now);
    bool authenticate_hello(Client& client, std::span<const std::uint8_t> record,
                            Time now, protocol::ClientHelloInfo& info,
                            const control::UserRecord*& user);
    void begin_client_tls(Client& client, const control::UserRecord& user,
                          protocol::ClientHelloInfo&& info, std::span<const std::uint8_t> record,
                          Time now);
    void feed_client_tls(Client& client, std::span<const std::uint8_t> wire, Time now);
    void client_tls_ready(Client& client, Time now);
    void pump_client_out(Client& client);
    bool push_client_wire(Client& client, std::span<const std::uint8_t> wire,
                          bool rearm_interest = true);
    bool client_wants_write(const Client& client) const noexcept;
    void pump_c2s(Client& client, Time now);
    // Direct Telegram DC route (opt-in, authenticated clients only).
    bool direct_route_enabled(std::int16_t dc) const noexcept;
    bool start_direct(Client& client, std::int16_t dc, Time now);
    void on_direct_connected(Client& client, Time now);
    void pump_direct_c2s(Client& client);
    void flush_direct(Client& client);
    void read_direct_backend(Client& client, Time now);
    void handle_direct_backend(Client& client, std::uint32_t events, Time now);
    void update_direct_interest(Client& client);
    void finish_direct_eof(Time now);
    void schedule_client_deadline(Client& client, Time now);
    void on_client_deadline(Client& client, Time now);
    void touch(Client& client, Time now) { client.last_activity = now; }
    void apply_shared_tunables();
    // max_devices: record the connection's auth key; false = over the limit
    // (the client is already being closed).
    bool register_device(Client& client, std::uint64_t auth_key_id, Time now);
    bool scan_direct_auth_key(Client& client, std::span<const std::uint8_t> plain, Time now);
    void release_device(Client& client, Time now) noexcept;
    void publish_devices(Time now);
    // Config::watch_ips investigation log (watch.cpp). Callers check
    // client.watched first; nothing here runs for other connections.
    void watch_accept(Client& client, Time now);
    void watch_log(const Client& client, std::string_view event, std::string_view detail);
    void watch_hello(const Client& client, std::span<const std::uint8_t> record);
    void watch_frame(Client& client, std::span<const std::uint8_t> payload, std::size_t length);
    void watch_close(const Client& client);
    // Records a suspect signal for this connection's address (suspects.cpp).
    void suspect(Client& client, control::SuspectSignal signal, std::string_view sni = {});
    void suspect_first_bytes(Client& client);
    void suspect_close(Client& client, Time now);
    bool suspect_shadow_ban(Client& client, Time now);
    Time next_suspect_prune_{};
    // Fair-share rate limits: recompute this connection's share, and publish
    // this reactor's active-connection counts (1 Hz, from the gauge pass).
    void recompute_rate_share(Client& client) noexcept;
    bool rate_limited(const Client& client) const noexcept;
    void set_counted_active(Client& client, bool active) noexcept;
    // Hot path: one add, plus one shared increment when a limited connection
    // becomes active.
    void note_activity(Client& client, std::size_t bytes) noexcept {
        client.window_bytes += bytes;
        if (!client.counted_active && rate_limited(client)) set_counted_active(client, true);
    }
    void reject_close(Client& client, control::RejectReason reason,
                      std::optional<control::HandshakeResult> handshake);
    void close_client(std::uint64_t token, bool record_pending_handshake = true);
    // Appends the current ME read's coalesced answers to every touched client
    // and writes them with one direct flush each (EPOLLOUT only on EAGAIN).
    void flush_s2c_batches();
    // write_now=false only queues (safe inside an ME decoder callback, where a
    // socket error must not close the client and re-enter the ME session).
    bool finish_s2c_batch(Client& client, bool write_now = true);
    static void note_close(Client& client, control::RelayCloseReason reason) noexcept {
        if (client.close_reason_set) return;
        client.close_reason_set = true;
        client.close_reason = reason;
    }
    void close_client(std::uint64_t token, control::RelayCloseReason reason);
    void close_fallback_backend(Client& client);
    enum class IpCountResult { ok, failure, limit };
    IpCountResult count_client_unique_ip(Client& client,
                                         std::optional<std::uint32_t> max_unique_ips);
    void decrement_client_unique_ip(Client& client) noexcept;
    // Hot path: a bool test once qualified, otherwise one add and compare.
    void note_ip_payload(Client& client, std::uint64_t bytes) {
        if (client.ip_qualified || !client.ip_counted) return;
        client.ip_bytes += bytes;
        if (client.ip_bytes >= config_.unique_ip_min_bytes) qualify_client_unique_ip(client);
    }
    void qualify_client_unique_ip(Client& client);
    void refresh_ip_history();
    void defer_close(std::uint64_t token);
    void defer_close_conn(const detail::ConnId& id);
    bool fallback_enabled() const noexcept;
    bool masking_enabled() const noexcept;  // automatic SNI masking for probes
    std::string ensure_fallback_address(Time now, std::string_view host);
    bool start_fallback(Client& client, std::span<const std::uint8_t> prefetched, Time now);
    void handle_fallback_client(Client& client, std::uint32_t events, Time now);
    void handle_fallback_backend(Client& client, std::uint32_t events, Time now);
    void read_fallback_client(Client& client, Time now);
    void read_fallback_backend(Client& client, Time now);
    void on_fallback_connected(Client& client, Time now);
    void pump_fallback_c2b(Client& client);
    void pump_fallback_b2c(Client& client);
    void finish_fallback_pairs(Time now);
    void on_fallback_deadline(Client& client, Time now);
    bool append_fallback_bytes(Client& client, io::ByteQueue& queue,
                               std::span<const std::uint8_t> bytes);
    void process_deferred();
    void latch_fin_pending(Client& client, Time now);
    void latch_read_eof(Client& client, Time now);
    void finish_eof_clients(Time now, bool force = false);
    void trim_idle_client(Client& client);
    void record_handshake(Client& client, control::HandshakeResult result);
    void attach_to_me(Client& client, MeConn& me);

    // ------------------------------------------------------------------
    // Middle-End pool
    // ------------------------------------------------------------------
    MeConn* ensure_me(std::int16_t dc, Time now);
    MeConn* pick_me(std::int16_t dc) noexcept;
    std::size_t me_generation_count(const DcPool& pool,
                                    std::uint64_t generation) const noexcept;
    void erase_me_from_pool(DcPool& pool, MeConn* me) noexcept;
    void publish_me_pool(std::int16_t dc) noexcept;
    // Cumulative per-DC socket bytes: folded pool base + live members.
    void publish_me_io(std::int16_t dc) noexcept;
    // Age of the newest RPC_PROXY_ANS of a live pool member, or an explicit
    // "no live member has answered" publication.
    void publish_me_answer_age(std::int16_t dc, Time now) noexcept;
    void publish_me_rtt(std::int16_t dc) noexcept;
    void publish_me_control(std::int16_t dc) noexcept;
    void fold_me_control(MeConn& me) noexcept;
    // Retires every per-connection mirror that feeds a cumulative per-DC series
    // (control counters and socket bytes) into the pool base, then zeroes the
    // mirrors. Called exactly once, when the connection leaves the pool: a
    // failed connection keeps its slot (and its byte mirror) across retries.
    void fold_me_counters(MeConn& me) noexcept;
    void reap_me_pool(Time now);
    void evict_slow_me_writers(Time now);
    void scale_me_pool(std::int16_t dc, Time now);
    void retire_me(MeConn& me);
    // Successor-first metadata replacement: build the new generation, keep the
    // working generation serving until the successor is ready, and only then
    // drain the older one.
    void advance_me_generation(std::int16_t dc, Time now);
    void drain_me_generations_below(DcPool& pool, std::uint64_t keep, Time now);
    void drain_me_pool(std::int16_t dc, Time now);
    // Rollback when the successor dies after taking over: the previous
    // generation is still draining and ready, so it is promoted back intact
    // instead of leaving the node not-ready while it relays traffic.
    bool restore_me_serving_generation();
    bool me_candidates(std::int16_t dc, std::vector<MeEndpoint>& out) const;
    void connect_me(MeConn& me, Time now);
    void on_me_connected(MeConn& me, Time now);
    void fail_me(MeConn& me, Time now);
    void defer_me_failure(MeConn& me);
    std::size_t me_frame_capacity() const noexcept;
    void handle_me(MeConn& me, std::uint32_t events, Time now);
    void read_me(MeConn& me, Time now);
    void on_me_ready(MeConn& me, Time now);
    void schedule_me_retry(MeConn& me, Time now);
    bool push_me_bytes(MeConn& me, std::span<const std::uint8_t> bytes);
    bool push_me_frame(MeConn& me, std::vector<std::uint8_t>&& frame);
    void pump_me_out(MeConn& me);
    void pump_me_ready_queue(MeConn& me, Time now);
    void enqueue_ready(Client& client);
    void arm_me_ready_wake(MeConn& me, Time now);
    void publish_me_queue(MeConn& me);
    // One-reactor, one-DC budget/read diagnostics for the 1 Hz gauge tick.
    // Bounded traversal of the existing pool; never called per packet.
    void publish_me_worker_diagnostics(std::int16_t dc, Time now) noexcept;
    void deliver_payload(MeConn& me, const detail::ConnId& id,
                         std::span<const std::uint8_t> payload, Time now);
    void deliver_quick_ack(MeConn& me, const detail::ConnId& id,
                           std::array<std::uint8_t, 4> confirm, Time now);
    void queue_remote_close(MeConn& me, const detail::ConnId& id);
    void flush_remote_closes(MeConn& me);
    void close_me_clients(MeConn& me);
    void shutdown_me(MeConn& me);
    void schedule_me_ping(MeConn& me, Time now);
    void on_me_ping_deadline(MeConn& me, Time now);
    void send_me_ping(MeConn& me, Time now);
    void handle_me_pong(MeConn& me, std::int64_t ping_id, Time now);

    static std::optional<protocol::Endpoint>
    to_protocol_endpoint(const io::Endpoint& endpoint);

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------
    Config config_;
    detail::MePingTuning ping_tuning_;
    control::UserStore& users_;
    control::Statistics& stats_;
    MetadataProvider& metadata_;
    RevisionBarrier& barrier_;
    std::shared_ptr<detail::SharedState> shared_;
    std::size_t worker_index_{0};
    bool reuse_port_{false};
    bool signal_owner_{true};
    protocol::RandomFn random_;

    io::UniqueFd epoll_;
    io::UniqueFd wake_;
    io::UniqueFd listener_;
    io::UniqueFd signal_;
    std::uint64_t listener_token_{0};
    std::uint64_t wake_token_{0};
    std::uint64_t signal_token_{0};
    std::uint32_t listener_events_{0};
    std::uint32_t wake_events_{0};
    std::uint32_t signal_events_{0};

    std::unordered_map<std::uint64_t, Target> targets_;
    std::unordered_map<std::uint64_t, std::unique_ptr<Client>> clients_;
    // Recycled Client objects. Ownership is owned here; entries are deleted by
    // release_client_pool() during finalization.
    std::vector<Client*> free_clients_;
    std::size_t client_pool_limit_{0};
    std::map<std::int16_t, DcPool> me_pool_;
    // Masking-target DNS cache keyed by hostname; refreshed on probe when
    // older than kFallbackResolveTtl. Literal IPs bypass it entirely.
    std::string fallback_cache_host_;
    std::string fallback_address_;
    Time fallback_resolved_at_{};
    // Stable identity for deferred failures and deadline/target lookups. Raw
    // pointers are valid while the owning DcPool holds the connection.
    std::unordered_map<std::uint64_t, MeConn*> me_by_token_;
    std::unordered_map<detail::ConnId, std::uint64_t, detail::ConnIdHash> clients_by_conn_;

    Deadlines deadlines_;

    std::shared_ptr<const control::UserSnapshot> users_snapshot_;
    std::vector<std::uint64_t> s2c_batch_tokens_;
    std::size_t accept_burst_{1};
    Time next_device_prune_{};
    std::vector<detail::WatchNet> watch_;
    // sweep_user_policy(): users with an expiry or quota, by name, valid for
    // policy_index_snapshot_ (held so the record pointers stay valid).
    std::shared_ptr<const control::UserSnapshot> policy_index_snapshot_;
    std::unordered_map<std::string, const control::UserRecord*> policy_index_;
    std::vector<std::uint64_t> policy_doomed_;
    std::uint64_t tunables_seen_{0};
    // Pre-keyed ClientHello HMAC per enabled user of hello_keys_snapshot_
    // (held so the UserRecord pointers stay valid). Rebuilt on snapshot change.
    std::shared_ptr<const control::UserSnapshot> hello_keys_snapshot_;
    std::vector<protocol::crypto::HmacSha256Key> hello_keys_;
    std::vector<const protocol::crypto::HmacSha256Key*> hello_key_ptrs_;
    std::vector<const control::UserRecord*> hello_key_users_;
    std::shared_ptr<const MeMetadata> metadata_snapshot_;
    std::size_t enabled_users_{0};
    bool warming_{false};
    std::vector<std::int16_t> warm_dcs_;

    std::size_t budget_used_{0};
    std::size_t shared_accounted_{0};
    std::size_t client_count_{0};
    std::size_t handshake_count_{0};

    std::vector<std::uint8_t> read_buffer_;
    std::vector<std::uint8_t> plain_buffer_;
    std::vector<std::uint8_t> frame_buffer_;
    std::vector<std::uint8_t> wire_buffer_;
    std::vector<std::uint8_t> to_me_buffer_;

    std::vector<std::uint64_t> deferred_closes_;
    std::vector<std::uint64_t> deferred_me_failures_;
    std::vector<std::uint64_t> paused_clients_;
    std::vector<std::uint64_t> rate_clients_;  // tokens with a rate pause flag set
    std::vector<std::uint64_t> rate_remaining_;
    Time next_rate_resume_{Time::max()};
    std::vector<std::uint64_t> eof_clients_;
    // Scratch storage for the sweep's survivor list: swapped with eof_clients_
    // so a steady-state sweep allocates nothing.
    std::vector<std::uint64_t> eof_remaining_;
    std::vector<std::uint64_t> fallback_clients_;
    std::vector<std::uint64_t> fallback_remaining_; // sweep scratch, reused
    std::vector<std::uint64_t> direct_eof_clients_;
    std::map<std::int16_t, std::uint64_t> direct_accepted_;
    std::map<std::int16_t, std::uint64_t> direct_connect_fail_;
    std::map<std::int16_t, std::uint64_t> direct_tx_bytes_;
    std::map<std::int16_t, std::uint64_t> direct_rx_bytes_;

    Time next_poll_{};
    Time next_gauge_{};
    // Housekeeping lateness vs. the scheduled next_poll_ deadline. Sampled on
    // the existing 150 ms tick; published with the 1 Hz worker diagnostics.
    std::uint64_t housekeeping_lateness_ms_{0};
    std::uint64_t housekeeping_lateness_max_ms_{0};
    // Sweep cadence and the earliest FIN/read-EOF expiry. The latter is also
    // published to wait_timeout_ms so the reactor wakes for a deadline even
    // without traffic.
    Time next_eof_sweep_{};
    Time next_eof_deadline_{Time::max()};
    Time shutdown_deadline_{};

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> started_{false};
    std::atomic<std::uint16_t> port_public_{0};
    bool stopping_{false};
    bool finalized_{false};
    bool signal_registered_{false};

    std::mutex exit_mutex_;
    std::condition_variable exit_changed_;
    bool exited_{false};

    std::uint64_t next_token_{100};
    // Monotone reactor generation counter for ME metadata replacements (see
    // advance_me_generation). Kept separate from MeMetadata::generation because
    // the provider bumps its generation for a pure proxy_for reorder, which must
    // not trigger a replacement.
    std::uint64_t next_me_generation_{0};
};

// Public facade state: resolves the configured worker count, owns N independent
// reactors and the thread that drives each one. Defined here (not in the public
// header) so Runtime::Impl stays a private implementation detail.
struct Runtime::RuntimeState {
    RuntimeState(const Config& config, control::UserStore& users,
                 control::Statistics& statistics, MetadataProvider& metadata,
                 RevisionBarrier& barrier);
    ~RuntimeState();
    RuntimeState(const RuntimeState&) = delete;
    RuntimeState& operator=(const RuntimeState&) = delete;

    void run();
    void request_stop() noexcept;
    std::uint16_t port() const noexcept;
    std::size_t worker_count() const noexcept { return workers; }
    void finish_run() noexcept;
    std::vector<std::uint64_t> accepted_clients_per_worker() const;
    std::vector<std::uint64_t> replay_rejections_per_worker() const;
    void set_tunables(std::uint32_t me_clients_per_writer, std::uint32_t me_connections_per_dc);
    void set_media_limits(std::uint64_t user_kbps, std::uint64_t total_kbps) noexcept;
    void on_reload(std::function<void()> hook);

private:
    void run_impl();

public:
    std::size_t workers{1};
    std::shared_ptr<detail::SharedState> shared;
    std::vector<std::unique_ptr<Impl>> reactors;
    std::vector<std::thread> threads;
    // Quota counter persistence (no-op without Config::usage_state_path).
    std::unique_ptr<control::UsageStateKeeper> usage_keeper;
    control::Statistics* statistics_{nullptr};
    // A concurrent destructor must not clear reactors/threads while run() is
    // still starting or joining workers. The destructor requests stop first,
    // then waits here for run() to publish its terminal state.
    std::mutex run_mutex_;
    std::condition_variable run_done_;
    bool started_{false};
    bool finished_{false};
};

} // namespace mtdd

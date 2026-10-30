// mtdd management/control plane: durable user store, runtime statistics, and
// an authenticated loopback HTTP API / Prometheus exporter.
//
// This header is self-contained (no libevent, OpenSSL, or nlohmann/json types
// leak into the public API) so the runtime can depend on it without pulling in
// libevent. Implementation lives in src/control/.
#pragma once

#include "mtdd/ip_history.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace mtdd::control {

// ---------------------------------------------------------------------------
// Shared constants and errors
// ---------------------------------------------------------------------------

inline constexpr size_t kSecretBytes = 16;
inline constexpr size_t kSecretHexChars = 32;
inline constexpr size_t kMaxNameLength = 64;
inline constexpr uint32_t kMaxConnectionsLimit = 1'000'000;
inline constexpr size_t kMaxUsersLimit = 100'000;
inline constexpr uint64_t kMaxUsersFileBytesLimit = 64ull * 1024 * 1024;

enum class ErrorCode {
  invalid_name,
  invalid_secret,
  invalid_field,
  unknown_field,
  invalid_json,
  invalid_request,
  duplicate_name,
  duplicate_secret,
  not_found,
  revision_conflict,
  limit_exceeded,
  invalid_file,
  unsupported_version,
  file_too_large,
  permission_denied,
  symlink_rejected,
  io_error,
  bind_failed,
  invalid_config,
};

const char* to_string(ErrorCode code) noexcept;

struct Error {
  ErrorCode code{ErrorCode::invalid_config};
  std::string message;
  // True only when a post-rename failure made the durable outcome unknown:
  // the new file may be visible even though in-memory state was not published.
  bool uncertain{false};
};

// Minimal result type (C++20 has no std::expected). Value or Error.
template <typename T>
class Result {
 public:
  Result(T value) : state_(std::in_place_index<0>, std::move(value)) {}  // NOLINT
  Result(Error error) : state_(std::in_place_index<1>, std::move(error)) {}  // NOLINT

  bool ok() const noexcept { return state_.index() == 0; }
  explicit operator bool() const noexcept { return ok(); }

  T& value() & {
    require_value();
    return std::get<0>(state_);
  }
  const T& value() const& {
    require_value();
    return std::get<0>(state_);
  }
  T&& value() && {
    require_value();
    return std::get<0>(std::move(state_));
  }

  const Error& error() const& {
    require_error();
    return std::get<1>(state_);
  }
  Error& error() & {
    require_error();
    return std::get<1>(state_);
  }

 private:
  void require_value() const {
    if (!ok()) throw std::logic_error("mtdd::control::Result: not a value");
  }
  void require_error() const {
    if (ok()) throw std::logic_error("mtdd::control::Result: not an error");
  }

  std::variant<T, Error> state_;
};

// ---------------------------------------------------------------------------
// Users and immutable snapshots
// ---------------------------------------------------------------------------

// max_connections == nullopt means "unlimited"; 0 is rejected so null is the
// only unlimited spelling.
inline constexpr size_t kMaxNoteBytes = 256;
inline constexpr uint64_t kMaxQuotaBytes = 1ull << 60;
inline constexpr uint32_t kMaxUniqueIpsLimit = 1'000'000;
inline constexpr uint64_t kMinRateLimitBytesPerSecond = 1024;
inline constexpr uint64_t kMaxRateLimitBytesPerSecond = 100'000'000'000ull;
inline constexpr int64_t kMaxExpiresAt = 253402300799;  // 9999-12-31T23:59:59Z

// Optional per-user limits. nullopt / empty note means "not set". Any set
// field makes the users file version 2; without them it stays version 1 so a
// previous binary can still read it.
struct UserPolicy {
  std::optional<int64_t> expires_at;  // Unix seconds, UTC
  std::optional<uint64_t> data_quota_bytes;  // c2s + s2c payload
  std::optional<uint32_t> max_unique_ips;    // concurrent distinct client IPs
  // Shaping in payload bytes per second, shared by all of the user's
  // connections: up = client to Telegram, down = Telegram to client.
  std::optional<uint64_t> rate_limit_up_bytes_per_sec;
  std::optional<uint64_t> rate_limit_down_bytes_per_sec;
  std::string note;  // admin free text, <= kMaxNoteBytes of printable UTF-8

  bool empty() const noexcept {
    return !expires_at && !data_quota_bytes && !max_unique_ips &&
           !rate_limit_up_bytes_per_sec && !rate_limit_down_bytes_per_sec &&
           note.empty();
  }
  bool operator==(const UserPolicy&) const = default;
};

// Explicit-null-aware patch: outer nullopt = unchanged, inner nullopt = clear.
template <typename T>
using Patch = std::optional<std::optional<T>>;

struct UserPolicyPatch {
  Patch<int64_t> expires_at;
  Patch<uint64_t> data_quota_bytes;
  Patch<uint32_t> max_unique_ips;
  Patch<uint64_t> rate_limit_up_bytes_per_sec;
  Patch<uint64_t> rate_limit_down_bytes_per_sec;
  std::optional<std::string> note;  // "" clears

  bool empty() const noexcept {
    return !expires_at && !data_quota_bytes && !max_unique_ips &&
           !rate_limit_up_bytes_per_sec && !rate_limit_down_bytes_per_sec &&
           !note;
  }
};

struct UserRecord {
  std::string name;
  // 32 lowercase hexadecimal characters. Sensitive: never serialize through
  // the management API; only workers and the store may see it.
  std::string secret_hex;
  bool enabled{true};
  std::optional<uint32_t> max_connections;
  // Auth generation, allocated from the globally monotonic persisted revision
  // for create/disable/rotate. It therefore never repeats, even after a user is
  // deleted and a new user with the same name is created. Deletion invalidates
  // sessions by absence from the snapshot. Runtime authorizes a session only if
  // both name and generation match the current immutable snapshot.
  uint64_t generation{1};
  UserPolicy policy;
};

struct UserSnapshot {
  uint64_t revision{0};
  std::vector<UserRecord> users;  // sorted by name

  const UserRecord* find(std::string_view name) const noexcept {
    for (const auto& user : users) {
      if (user.name == name) return &user;
    }
    return nullptr;
  }
};

using AckHook = std::function<bool(uint64_t revision, std::chrono::milliseconds timeout)>;

struct StoreOptions {
  size_t max_users{10'000};
  uint64_t max_file_bytes{4ull * 1024 * 1024};
  // Modes are intentionally owner-only; group/other bits are rejected.
  // An existing users file must be owned by geteuid() and have no group/other
  // permission bits; otherwise open() fails closed with permission_denied.
  uint32_t file_mode{0600};
  uint32_t dir_mode{0700};
  bool create_directories{true};
  // Called after the new revision is durably written and published in memory,
  // before the mutation returns. Must not access reactor state directly; the
  // runtime typically waits on a condition variable for its worker loop.
  AckHook ack_hook;
  std::chrono::milliseconds ack_timeout{1000};
};

struct CreateUserRequest {
  std::string name;
  std::optional<std::string> secret;  // omitted => generate via RAND_bytes
  bool enabled{true};
  std::optional<uint32_t> max_connections;  // nullopt => unlimited
  UserPolicy policy;
  std::optional<uint64_t> if_match;         // optional optimistic concurrency
};

struct UpdateUserRequest {
  std::string name;
  std::optional<bool> enabled;       // nullopt => unchanged
  bool set_max_connections{false};   // distinguishes absent from explicit null
  std::optional<uint32_t> max_connections;  // nullopt + set_* => unlimited
  UserPolicyPatch policy;
  std::optional<uint64_t> if_match;
};

struct DeleteUserRequest {
  std::string name;
  std::optional<uint64_t> if_match;
};

struct RotateSecretRequest {
  std::string name;
  std::optional<std::string> secret;  // omitted => generated
  std::optional<uint64_t> if_match;
};

struct MutationOutcome {
  uint64_t revision{0};
  // applied == false && pending == true: durable+published, but the runtime has
  // not acknowledged observing this revision within the bounded timeout.
  bool applied{true};
  bool pending{false};
  UserRecord user;  // empty name for delete
  bool deleted{false};
  std::optional<std::string> secret_once;
};

// Durable, atomic, single-file user store. All mutations are serialized.
// I/O failures never publish partial state. A failure after rename reports
// Error::uncertain == true and leaves the in-memory snapshot unchanged.
class UserStore {
 public:
  static Result<UserStore> open(std::string path, StoreOptions options = {});

  UserStore(UserStore&&) noexcept;
  UserStore& operator=(UserStore&&) noexcept;
  ~UserStore();
  UserStore(const UserStore&) = delete;
  UserStore& operator=(const UserStore&) = delete;

  std::shared_ptr<const UserSnapshot> snapshot() const noexcept;
  const std::string& path() const noexcept;

  Result<MutationOutcome> create_user(const CreateUserRequest& request);
  Result<MutationOutcome> update_user(const UpdateUserRequest& request);
  Result<MutationOutcome> delete_user(const DeleteUserRequest& request);
  Result<MutationOutcome> rotate_secret(const RotateSecretRequest& request);

  static Result<std::string> generate_secret();
  static bool is_valid_name(std::string_view name) noexcept;
  static bool is_valid_secret_hex(std::string_view secret) noexcept;
  // Range and content checks shared by the API and the users file parser;
  // returns a human-readable reason on failure.
  static std::optional<std::string> validate_policy(const UserPolicy& policy);

 private:
  struct Impl;
  explicit UserStore(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Runtime statistics
// ---------------------------------------------------------------------------

enum class RejectReason {
  overload,
  rate_limited,
  auth_failed,
  handshake_timeout,
  invalid_request,
  other,
  // Per-user policy rejections (UserPolicy / UserRecord::max_connections).
  user_connection_limit,
  user_expired,
  user_quota_exceeded,
  user_ip_limit,
};

enum class HandshakeResult { success, failure, timeout, replay };
// Why an authenticated relay session ended. First recorded reason wins.
enum class RelayCloseReason : uint8_t {
  other,
  client_eof,      // peer half-closed and the session drained
  client_error,    // recv/send error (reset, broken pipe)
  client_timeout,  // ETIMEDOUT: TCP keepalive / TCP_USER_TIMEOUT found a dead peer
  idle_timeout,
  me_lost,         // the bound ME writer failed or was retired
  backpressure,    // buffer budget or queue limit
  remote_close,    // ME sent RPC_CLOSE_CONN
  revoked,         // user disabled, deleted or rotated
  shutdown,
};
inline constexpr std::size_t kRelayCloseReasons = 10;
enum class Direction { client_to_server, server_to_client };
enum class BufferState { queued, pending_write, relay };
enum class MeResult { success, failure, timeout };
// Outcome of one RPC_PROXY_ANS received from the signed-DC peer. "received" is
// counted at the callback, so it stays distinct from delivery to a client.
enum class MeAnswerResult { received, delivered, dropped_unknown, dropped_other };
enum class ApiRoute {
  health,
  ready,
  status,
  users,
  user,
  user_links,
  rotate_secret,
  metrics,
  unknown,
  system_info,
  config,
  stats_summary,
  stats_me,
  stats_users,
  events,
  user_enable,
  user_disable,
  user_reset_quota,
};
enum class ApiMethod { get, post, patch, delete_, other };

const char* to_string(RejectReason reason) noexcept;
const char* to_string(HandshakeResult result) noexcept;
const char* to_string(Direction direction) noexcept;
const char* to_string(BufferState state) noexcept;
const char* to_string(MeResult result) noexcept;
const char* to_string(ApiRoute route) noexcept;
const char* to_string(ApiMethod method) noexcept;

struct UserMetricsSnapshot {
  uint64_t active_connections{0};
  // Online IPs counted at authenticated handshake ("seen").
  uint64_t unique_ips_active{0};
  // Online IPs whose connections moved >= unique_ip_min_bytes ("active").
  uint64_t unique_ips_qualified{0};
  uint64_t payload_c2s_bytes{0};
  uint64_t payload_s2c_bytes{0};
  // c2s + s2c payload bytes counted against UserPolicy::data_quota_bytes.
  uint64_t quota_used_bytes{0};
  // Unix seconds of the last reset_quota(); 0 = never reset.
  int64_t quota_reset_at{0};
};

struct MeDcSnapshot {
  bool connected{false};
  // How many reactors currently hold a ready ME connection for this DC. With
  // `workers` > 1 each reactor opens its own pooled ME connection, so this is
  // the honest topology gauge (`mtdd_me_ready_reactors`); `connected` stays a
  // boolean convenience and `connections` is the socket count.
  uint64_t reactors_connected{0};
  uint64_t reconnects_total{0};
  uint64_t requests_success{0};
  uint64_t requests_failure{0};
  uint64_t requests_timeout{0};
  // Ready-queue and staging truth (enqueued work, never a delivery claim).
  uint64_t ready_queue_depth{0};
  uint64_t ready_queue_clients{0};
  uint64_t frames_queued_bytes{0};
  uint64_t out_queued_bytes{0};
  // Actual RPC_PROXY_ANS observations, from the ME callback.
  uint64_t proxy_ans_received_total{0};
  uint64_t proxy_ans_delivered_total{0};
  uint64_t proxy_ans_dropped_unknown_total{0};
  uint64_t proxy_ans_dropped_other_total{0};
  bool proxy_ans_seen{false};
  uint64_t last_proxy_ans_age_seconds{0};
  // Inbound RPC control constructors observed per DC. Cumulative gauges: a
  // replaced connection folds its counters into the DC base, so the series
  // never moves backwards (see publish_me_control).
  uint64_t control_close_conn{0};
  uint64_t control_close_ext{0};
  uint64_t control_unknown{0};
  uint64_t control_malformed{0};
  // Socket bytes since process start, accumulated per batch.
  uint64_t rx_bytes_total{0};
  uint64_t tx_bytes_total{0};
  // Per-DC ME pool size and health (task: multi-connection ME pool).
  uint64_t connections{0};
  uint64_t ready_connections{0};
  uint64_t pool_target{0};
  uint64_t bound_clients{0};
  uint64_t scale_up_total{0};
  uint64_t scale_down_total{0};
  uint64_t creation_failures_total{0};
  // Keepalive: mean EMA RTT of the ready pool members and lifetime counters.
  uint64_t ping_rtt_us{0};
  uint64_t pings_sent_total{0};
  uint64_t pongs_received_total{0};
  uint64_t ping_timeouts_total{0};
  // Liveness windows that expired without PONG but with inbound progress.
  uint64_t ping_stalls_total{0};
  // Direct Telegram DC fallback (opt-in). Direct cannot carry the ME ad-tag.
  uint64_t direct_active{0};
  // Established upstream connections (SO_ERROR==0), not connect attempts.
  uint64_t direct_accepted_total{0};
  uint64_t direct_connect_fail_total{0};
  uint64_t direct_rx_bytes_total{0};
  uint64_t direct_tx_bytes_total{0};
  // Cumulative transitions into the Direct DC->client budget pause. One per
  // pause, never one per reactor iteration.
  uint64_t direct_budget_pauses_total{0};
};

// Per-reactor ME budget/read diagnostics. Unlike MeDcSnapshot these values are
// NOT summed across reactors: one locally exhausted worker must stay visible
// even when another worker has budget slack. Labels stay bounded (13 DC slots).
struct MeWorkerSnapshot {
  uint64_t connections{0};
  uint64_t ready_connections{0};
  // Established ME sockets whose current epoll interest mask contains EPOLLIN.
  uint64_t read_armed_connections{0};
  // ME reads refused by this reactor's budget (EPOLLIN removed while paused).
  uint64_t budget_paused_connections{0};
  // Clients multiplexed on those paused ME sockets: the user-visible blast
  // radius of a worker-local pause.
  uint64_t bound_clients_on_paused{0};
  uint64_t budget_pauses_total{0};
  uint64_t budget_resumes_total{0};
  // Oldest currently paused read, and the largest pause observed (including a
  // still-running one). Milliseconds because housekeeping retries every 150 ms.
  uint64_t current_pause_age_ms{0};
  uint64_t max_pause_age_ms{0};
  // Worst-writer view. The DC RTT gauge is a mean, so one head-of-line blocked
  // writer disappears into it; these expose it directly.
  // Largest of: newest PONG sample, age of the oldest unanswered ping.
  uint64_t worst_writer_rtt_us{0};
  // Ready writers currently flagged slow, and writers retired for it.
  uint64_t slow_writers{0};
  uint64_t slow_evictions_total{0};
};

// Fixed per-worker diagnostics. `heartbeat_age_ms` is computed by snapshot()
// from a monotonic timestamp the reactor publishes, so a stalled worker cannot
// appear current just because the control thread read an old value.
struct WorkerSnapshot {
  uint64_t budget_used_bytes{0};
  uint64_t budget_limit_bytes{0};
  uint64_t active_clients{0};
  uint64_t handshakes_pending{0};
  bool heartbeat_seen{false};
  uint64_t heartbeat_age_ms{0};
  // Lateness of the reactor's 150 ms housekeeping tick vs. its scheduled
  // deadline: last observed and maximum since startup.
  uint64_t housekeeping_lateness_ms{0};
  uint64_t housekeeping_lateness_max_ms{0};
  std::map<std::string, MeWorkerSnapshot> me_dcs;  // bounded signed DC labels
};

struct StatisticsSnapshot {
  std::string build_version;
  uint64_t uptime_seconds{0};
  bool ready{false};
  uint64_t connections_accepted_total{0};
  uint64_t connections_active{0};
  uint64_t active_unique_ips{0};     // online, counted at handshake ("seen")
  uint64_t qualified_unique_ips{0};  // online, past the byte threshold ("active")
  uint64_t unique_ip_min_bytes{0};
  uint64_t connections_rejected_total{0};
  std::map<std::string, uint64_t> rejected_by_reason;
  std::map<std::string, uint64_t> handshakes_by_result;
  std::map<std::string, UserMetricsSnapshot> users;
  std::array<uint64_t, 3> buffer_bytes{};  // indexed by BufferState
  uint64_t buffer_budget_used{0};          // global relay-buffer budget in use
  uint64_t handshakes_pending{0};          // clients holding a handshake slot
  uint64_t client_pool_objects{0};         // recycled Client objects held
  uint64_t client_allocations_total{0};    // fresh Client object allocations
  uint64_t client_reuses_total{0};         // Client objects taken from freelist
  uint64_t backpressure_c2s_total{0};
  uint64_t backpressure_s2c_total{0};
  std::array<uint64_t, kRelayCloseReasons> relay_closes_total{};
  uint64_t media_throttled_total{0};
  uint64_t replay_cache_entries{0};
  uint64_t api_requests_total{0};
  uint64_t me_pending_buffer_bytes{0};
  std::map<std::string, MeDcSnapshot> me_dcs;  // bounded signed DC labels
  // Indexed by worker. The aggregate fields above keep their historical summed
  // meaning; this vector exposes the local values an aggregate hides.
  std::vector<WorkerSnapshot> workers;
  IpHistorySnapshot unique_ip_history;
  uint64_t ip_history_observation_failures{0};
};

// Connection-lifetime handle. All operations are lock-free atomics; workers may
// hold one for the lifetime of a connection and update it per accepted payload
// without a mutex.
class UserMetrics {
 public:
  void connection_opened() noexcept;
  // Atomically reserves one connection slot if the current count is below
  // `limit`. Replaces the check-then-open sequence, which could exceed a global
  // per-user limit when two reactors admitted the same user concurrently.
  bool try_connection_open(uint64_t limit) noexcept;
  void connection_closed() noexcept;
  // Also adds `bytes` to the quota counter, so every payload call site is
  // quota-accounted without a second call.
  void add_payload(Direction direction, uint64_t bytes) noexcept;

  // Quota counter (c2s + s2c payload). Not reset by connection churn.
  uint64_t quota_used_bytes() const noexcept;
  void set_quota_used_bytes(uint64_t value) noexcept;
  // Startup restore of a persisted counter: both fields at once.
  void restore_quota(uint64_t used_bytes, int64_t reset_at) noexcept;
  // Zeroes the counter and records the wall-clock reset time (unix seconds).
  void reset_quota() noexcept;
  int64_t quota_reset_at() const noexcept;

  // Per-user token bucket (one per direction), shared by every connection of
  // the user on every reactor. Implemented as a GCRA "theoretical arrival
  // time" in steady-clock nanoseconds, so it is one lock-free atomic per
  // direction and a rate change needs no bucket state migration.
  // Charges `bytes` against `rate_bytes_per_sec` (0 = unlimited, no-op).
  // Always succeeds (debt model): returns the steady-clock time in ns at which
  // the direction may be read again, or 0 if no pause is needed.
  int64_t rate_consume(Direction direction, uint64_t bytes,
                       uint64_t rate_bytes_per_sec, int64_t now_ns) noexcept;
  // Same pause computation without charging anything.
  int64_t rate_resume_at(Direction direction, uint64_t rate_bytes_per_sec,
                         int64_t now_ns) const noexcept;
  // Burst allowance in bytes for a rate: max(rate, 64 KiB).
  static uint64_t rate_burst_bytes(uint64_t rate_bytes_per_sec) noexcept;
  // Connections of this user that moved payload in the last second (all, and
  // media DCs only), summed over reactors. Rate limits are split by these.
  void add_active_connections(int64_t all, int64_t media) noexcept;
  int64_t active_rate_connections() const noexcept;
  int64_t active_media_connections() const noexcept;
  // Bumped on every active-count change, so connections can refresh their
  // share as soon as the split changes instead of on the next 1 Hz pass.
  uint64_t active_generation() const noexcept;

  uint64_t active_connections() const noexcept;
  void set_active_unique_ips(uint64_t value) noexcept;
  uint64_t active_unique_ips() const noexcept;
  void set_qualified_unique_ips(uint64_t value) noexcept;
  uint64_t qualified_unique_ips() const noexcept;
  uint64_t payload_c2s_bytes() const noexcept;
  uint64_t payload_s2c_bytes() const noexcept;

 private:
  std::atomic<uint64_t> active_{0};
  std::atomic<uint64_t> unique_ips_{0};
  std::atomic<uint64_t> qualified_ips_{0};
  std::atomic<uint64_t> payload_c2s_{0};
  std::atomic<uint64_t> payload_s2c_{0};
  // Quota usage is (c2s + s2c) - quota_base_: the hot path pays only the
  // existing per-direction counter, and reset/restore just move the base.
  std::atomic<int64_t> quota_base_{0};
  std::atomic<int64_t> quota_reset_at_{0};
  // Own cache line: rate buckets are written by every reactor serving the user.
  alignas(64) std::atomic<int64_t> rate_tat_[2]{};
  std::atomic<int64_t> active_rate_conns_{0};
  std::atomic<int64_t> active_media_conns_{0};
  std::atomic<uint64_t> active_generation_{0};
};

// Thread-safe. Label sets are bounded by construction (enums and fixed label
// normalization); there is no unbounded "reason"/path/IP map.
class Statistics {
 public:
  explicit Statistics(size_t max_tracked_users = 10'000);
  ~Statistics();
  Statistics(const Statistics&) = delete;
  Statistics& operator=(const Statistics&) = delete;
  Statistics(Statistics&&) noexcept;
  Statistics& operator=(Statistics&&) noexcept;

  // Startup-only, before worker threads or the control server run. Worker
  // gauges are summed (or OR-ed/min-ed where a sum is meaningless) in snapshot;
  // the non-worker gauge setters below target worker 0 for compatibility.
  // Also monotonically raises the cumulative-slot high-water bound; shrinking
  // the count never lowers it.
  void configure_workers(std::size_t workers) noexcept;

  void set_ready(bool ready) noexcept;
  void set_ready(std::size_t worker, bool ready) noexcept;
  bool ready() const noexcept;
  void set_build_info(std::string version);

  // Global connection counters.
  void connection_accepted() noexcept;
  void connection_closed() noexcept;
  void connection_rejected(RejectReason reason) noexcept;
  void handshake(HandshakeResult result) noexcept;

  // Returns nullptr for names outside the store's [A-Za-z0-9_.-]{1,64}
  // contract or once max_tracked_users is reached. Callers keep the shared
  // handle for the connection lifetime.
  std::shared_ptr<UserMetrics> user(std::string_view name);
  void forget_user(std::string_view name) noexcept;

  void set_active_unique_ips(uint64_t value) noexcept;
  // Online IPs past the byte threshold; see Config::unique_ip_min_bytes.
  void set_qualified_unique_ips(uint64_t value) noexcept;
  void set_unique_ip_min_bytes(uint64_t value) noexcept;

  // Startup-only, once, before the reactor/control threads run. An empty path
  // is memory-only. Construction may throw a generic startup/read error.
  void enable_ip_history(std::string path = {});
  // False when history is disabled. Exceptions are contained and counted.
  bool rotate_ip_history(int64_t unix_seconds) noexcept;
  // Canonical 16-byte IP without port. False when disabled or the keyed HLL
  // update failed. Never affects proxy clients.
  bool observe_ip_history(const std::array<std::uint8_t, 16>& ip) noexcept;
  // Same, for the "active" sketches (IP passed the byte threshold).
  bool observe_ip_history_active(const std::array<std::uint8_t, 16>& ip) noexcept;

  void set_buffer_bytes(BufferState state, uint64_t bytes) noexcept;
  void set_buffer_bytes(std::size_t worker, BufferState state, uint64_t bytes) noexcept;
  void set_buffer_budget_used(uint64_t bytes) noexcept;
  void set_buffer_budget_used(std::size_t worker, uint64_t bytes) noexcept;
  void set_handshakes_pending(uint64_t value) noexcept;
  void set_handshakes_pending(std::size_t worker, uint64_t value) noexcept;
  void set_client_pool(uint64_t pooled, uint64_t allocations, uint64_t reuses) noexcept;
  void set_client_pool(std::size_t worker, uint64_t pooled, uint64_t allocations,
                       uint64_t reuses) noexcept;
  void add_backpressure(Direction direction) noexcept;
  void relay_closed(RelayCloseReason reason) noexcept;
  // Media shaping held a client (one count per throttle episode).
  void media_throttled() noexcept;
  void set_replay_cache_entries(uint64_t entries) noexcept;
  void set_replay_cache_entries(std::size_t worker, uint64_t entries) noexcept;

  // Per-reactor diagnostics. These are deliberately separate from the summed
  // buffer_budget_used/handshake gauges above: an aggregate can look healthy
  // while one reactor is at its local budget limit. `budget_limit_bytes` is
  // that reactor's partition, not the process-wide setting.
  void set_worker_diagnostics(std::size_t worker, uint64_t budget_used_bytes,
                              uint64_t budget_limit_bytes,
                              uint64_t active_clients,
                              uint64_t handshakes_pending) noexcept;
  // Stamps the reactor's liveness with the current monotonic clock. snapshot()
  // derives the age, so the value cannot go stale simply by being re-read.
  void set_worker_heartbeat(std::size_t worker) noexcept;
  // Test seam / explicit timestamp form of the same monotonic nanosecond value.
  void set_worker_heartbeat_at(std::size_t worker, uint64_t monotonic_ns) noexcept;
  // Housekeeping lateness vs. the scheduled 150 ms deadline (milliseconds).
  void set_worker_housekeeping_lateness(std::size_t worker, uint64_t last_ms,
                                        uint64_t max_ms) noexcept;

  void api_request(ApiRoute route, ApiMethod method, int status) noexcept;

  // ME connectivity is reported per bounded signed DC label:
  // -203, -5..-1, 1..5, 203. Any other DC id is aggregated under "other".
  void me_connected(int dc, bool connected) noexcept;
  void me_connected(std::size_t worker, int dc, bool connected) noexcept;
  void me_reconnect(int dc) noexcept;
  void me_request(int dc, MeResult result) noexcept;
  // Per-reactor variants: the cumulative request counter is accumulated in the
  // reactor's fixed statistics slot (worker % 256) so independent reactors do
  // not contend for one cache line. The legacy two-argument forms above keep
  // writing slot 0 for compatibility. snapshot() sums every slot up to a
  // monotonic high-water bound of ever-touched/addressable slots (never shrunk
  // by configure_workers), so the totals are exact regardless of how many
  // workers are currently active and untouched capacity is not scanned.
  void me_request(std::size_t worker, int dc, MeResult result) noexcept;
  // Cumulative answer outcome for one signed DC. Called once per received
  // RPC_PROXY_ANS, never per payload byte.
  void me_answer(int dc, MeAnswerResult result) noexcept;
  void me_answer(std::size_t worker, int dc, MeAnswerResult result) noexcept;
  // Inbound control-constructor counts for one signed DC. Absolute values
  // (gauges) accumulated by the reactor across replacements: a replaced
  // connection folds its counters into the DC base, so the series never moves
  // backwards and me_connected(false) never clears it.
  void me_control(int dc, uint64_t close_conn, uint64_t close_ext,
                  uint64_t unknown, uint64_t malformed) noexcept;
  void me_control(std::size_t worker, int dc, uint64_t close_conn,
                  uint64_t close_ext, uint64_t unknown,
                  uint64_t malformed) noexcept;
  // Current queue/staging gauges for one signed DC. Called per pump turn.
  void me_queue(int dc, uint64_t depth, uint64_t clients,
                uint64_t frames_bytes, uint64_t out_bytes) noexcept;
  void me_queue(std::size_t worker, int dc, uint64_t depth, uint64_t clients,
                uint64_t frames_bytes, uint64_t out_bytes) noexcept;
  // Direct Telegram DC fallback gauges/counters, same bounded DC labels.
  void me_direct(int dc, uint64_t active, uint64_t accepted, uint64_t connect_fail,
                 uint64_t rx_bytes, uint64_t tx_bytes) noexcept;
  void me_direct(std::size_t worker, int dc, uint64_t active, uint64_t accepted,
                 uint64_t connect_fail, uint64_t rx_bytes,
                 uint64_t tx_bytes) noexcept;
  void direct_budget_pause(int dc) noexcept;
  // Cumulative ME socket bytes. Called per read/write batch.
  void me_io(int dc, uint64_t rx_bytes_total, uint64_t tx_bytes_total) noexcept;
  void me_io(std::size_t worker, int dc, uint64_t rx_bytes_total,
             uint64_t tx_bytes_total) noexcept;
  // Seconds since the last received answer; only rendered when one was seen.
  void me_last_answer_age(int dc, uint64_t age_seconds) noexcept;
  void me_last_answer_age(std::size_t worker, int dc,
                          uint64_t age_seconds) noexcept;
  // Publishes "no live ME connection has answered for this DC": snapshot()
  // then reports proxy_ans_seen=false and Prometheus omits the age gauge,
  // matching every other gauge that has no data yet.
  void me_last_answer_clear(int dc) noexcept;
  void me_last_answer_clear(std::size_t worker, int dc) noexcept;
  // Per-DC pool gauges: total connections and currently ready connections.
  // They are reactor-owned gauges: with N reactors snapshot() sums the pools,
  // so `connections` is the process-wide ME socket count for the DC.
  void me_pool(int dc, uint64_t connections, uint64_t ready) noexcept;
  void me_pool(std::size_t worker, int dc, uint64_t connections,
               uint64_t ready) noexcept;
  // One reactor's ME budget/read diagnostics for one signed DC. Same fixed
  // label set and `values` shape as MeWorkerSnapshot; never summed with peers.
  void me_worker(std::size_t worker, int dc,
                 const MeWorkerSnapshot& values) noexcept;
  void me_pool_scaling(std::size_t worker, int dc, uint64_t target,
                       uint64_t clients, uint64_t up, uint64_t down,
                       uint64_t failures) noexcept;
  // Keepalive counters/gauges. me_ping_pong records one answered ping; the RTT
  // gauge is published separately by me_ping_rtt as the mean EMA of the DC's
  // ready pool members, so a single member cannot drive the DC value. Counters
  // are process-lifetime and accumulate in slot 0; the RTT gauge is
  // per-reactor and averaged across reactors in snapshot().
  void me_ping_sent(int dc) noexcept;
  void me_ping_pong(int dc, uint64_t rtt_us) noexcept;
  void me_ping_rtt(int dc, uint64_t rtt_us) noexcept;
  void me_ping_rtt(std::size_t worker, int dc, uint64_t rtt_us) noexcept;
  // Liveness windows that expired without PONG but were rescued by inbound
  // traffic, i.e. the peer is alive but ignores/delays RPC_PING.
  void me_ping_stall(int dc) noexcept;
  // Liveness windows that expired with neither PONG nor a single inbound byte:
  // the connection was declared dead and replaced.
  void me_ping_timeout(int dc) noexcept;
  void me_pending_buffer_bytes(uint64_t bytes) noexcept;
  void me_pending_buffer_bytes(std::size_t worker, uint64_t bytes) noexcept;

  StatisticsSnapshot snapshot() const;
  std::string prometheus_text() const;

  static std::string escape_label(std::string_view value);

 private:
  bool observe_history(const std::array<std::uint8_t, 16>& ip, bool active) noexcept;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// HTTP control server
// ---------------------------------------------------------------------------

// A listener either serves the management API (/v1/*, plus the deprecated
// /metrics alias for the admin token) or only the Prometheus exporter.
enum class HttpRole { api, metrics };

struct HttpOptions {
  HttpRole role{HttpRole::api};
  std::string public_host;
  uint16_t public_port{0};
  std::string tls_domain;
  std::string bind_address{"127.0.0.1"};
  uint16_t port{0};  // 0 => ephemeral, actual port from start()
  // Required; never persisted or logged by this module. Supplied by the leader
  // from the environment.
  // api role: admin token, required. Ignored by the metrics role.
  std::string bearer_token;
  // api role, optional: GET-only token; never sees /links or /metrics.
  std::string read_token;
  // metrics role, optional: when empty the listener relies on allow_networks
  // alone, which then must not be empty.
  std::string metrics_token;
  // CIDR allowlist of peer addresses ("127.0.0.0/8", "::1"). Empty => any
  // peer that holds a valid token. Refused peers get 403 before auth.
  std::vector<std::string> allow_networks;
  size_t max_body_bytes{64 * 1024};
  size_t max_header_bytes{16 * 1024};
  // Max retained HTTP connections (1..4096). Each accepted connection gets an
  // identity and an absolute pre-request deadline; over-cap accept-batch
  // survivors are shut down and answer 503. The listener is paused at the cap
  // and the kernel backlog is limited to it.
  size_t max_connections{64};
  // Absolute deadline for a connection to deliver its first complete request;
  // afterwards libevent's read/write inactivity timeout applies.
  std::chrono::milliseconds request_deadline{5000};
  double rate_limit_per_second{100.0};
  double rate_limit_burst{200.0};
  double global_rate_limit_per_second{1000.0};
  double global_rate_limit_burst{2000.0};
  size_t rate_limit_sources{256};
  // api role: pre-rendered JSON objects served by GET /v1/config and merged
  // into GET /v1/system/info. Built by the leader from Config with every token
  // and the ad_tag left out; empty means "{}".
  std::string config_json;
  std::string system_info_json;
};

class ControlServer {
 public:
  ControlServer(UserStore& store, Statistics& stats, HttpOptions options);
  ~ControlServer();
  ControlServer(const ControlServer&) = delete;
  ControlServer& operator=(const ControlServer&) = delete;

  // Binds and starts the event loop thread. Returns the bound port.
  Result<uint16_t> start();
  // Stops the loop and joins the thread. Idempotent.
  void stop() noexcept;

  bool running() const noexcept;
  uint16_t port() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace mtdd::control

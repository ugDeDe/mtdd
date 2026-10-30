// Thread-safe runtime statistics with bounded label sets and Prometheus text
// rendering. No per-packet locks: connection-lifetime handles use atomics.
#include <mtdd/control.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mtdd::control {
namespace {

constexpr size_t kRejectReasonCount = 10;
constexpr size_t kHandshakeResultCount = 4;
constexpr size_t kBufferStateCount = 3;
constexpr size_t kApiRouteCount = 18;
constexpr size_t kApiMethodCount = 5;
constexpr size_t kApiStatusCount = 14;
constexpr size_t kMeSlotCount = 13;  // -203, -5..-1, 1..5, 203, other

constexpr std::array<const char*, kRejectReasonCount> kRejectLabels = {
    "overload", "rate_limited", "auth_failed",
    "handshake_timeout", "invalid_request", "other",
    "user_connection_limit", "user_expired", "user_quota_exceeded",
    "user_ip_limit"};

constexpr std::array<const char*, kHandshakeResultCount> kHandshakeLabels = {
    "success", "failure", "timeout", "replay"};

constexpr std::array<const char*, kBufferStateCount> kBufferLabels = {
    "queued", "pending_write", "relay"};

constexpr std::array<const char*, kApiRouteCount> kApiRouteLabels = {
    "/v1/health", "/v1/ready", "/v1/status", "/v1/users",
    "/v1/users/{name}", "/v1/users/{name}/rotate-secret", "/metrics", "unknown",
    "/v1/users/{name}/links", "/v1/system/info", "/v1/config",
    "/v1/stats/summary", "/v1/stats/me", "/v1/stats/users", "/v1/events",
    "/v1/users/{name}/enable", "/v1/users/{name}/disable",
    "/v1/users/{name}/reset-quota"};

constexpr std::array<const char*, kApiMethodCount> kApiMethodLabels = {
    "GET", "POST", "PATCH", "DELETE", "OTHER"};

// Bounded status labels. Unknown statuses are aggregated under 500.
constexpr std::array<int, kApiStatusCount> kApiStatusCodes = {
    200, 201, 202, 400, 401, 403, 404, 405, 409, 412, 413, 429, 500, 503};
constexpr std::array<const char*, kApiStatusCount> kApiStatusLabels = {
    "200", "201", "202", "400", "401", "403", "404",
    "405", "409", "412", "413", "429", "500", "503"};

constexpr std::array<const char*, kMeSlotCount> kMeLabels = {
    "-203", "-5", "-4", "-3", "-2", "-1", "1",
    "2",    "3",  "4",  "5",  "203", "other"};

size_t reject_index(RejectReason reason) {
  switch (reason) {
    case RejectReason::overload: return 0;
    case RejectReason::rate_limited: return 1;
    case RejectReason::auth_failed: return 2;
    case RejectReason::handshake_timeout: return 3;
    case RejectReason::invalid_request: return 4;
    case RejectReason::other: return 5;
    case RejectReason::user_connection_limit: return 6;
    case RejectReason::user_expired: return 7;
    case RejectReason::user_quota_exceeded: return 8;
    case RejectReason::user_ip_limit: return 9;
  }
  return 5;
}

size_t handshake_index(HandshakeResult result) {
  switch (result) {
    case HandshakeResult::success: return 0;
    case HandshakeResult::failure: return 1;
    case HandshakeResult::timeout: return 2;
    case HandshakeResult::replay: return 3;
  }
  return 1;
}

size_t buffer_index(BufferState state) {
  switch (state) {
    case BufferState::queued: return 0;
    case BufferState::pending_write: return 1;
    case BufferState::relay: return 2;
  }
  return 0;
}

size_t route_index(ApiRoute route) {
  switch (route) {
    case ApiRoute::health: return 0;
    case ApiRoute::ready: return 1;
    case ApiRoute::status: return 2;
    case ApiRoute::users: return 3;
    case ApiRoute::user: return 4;
    case ApiRoute::rotate_secret: return 5;
    case ApiRoute::metrics: return 6;
    case ApiRoute::unknown: return 7;
    case ApiRoute::user_links: return 8;
    case ApiRoute::system_info: return 9;
    case ApiRoute::config: return 10;
    case ApiRoute::stats_summary: return 11;
    case ApiRoute::stats_me: return 12;
    case ApiRoute::stats_users: return 13;
    case ApiRoute::events: return 14;
    case ApiRoute::user_enable: return 15;
    case ApiRoute::user_disable: return 16;
    case ApiRoute::user_reset_quota: return 17;
  }
  return 7;
}

size_t method_index(ApiMethod method) {
  switch (method) {
    case ApiMethod::get: return 0;
    case ApiMethod::post: return 1;
    case ApiMethod::patch: return 2;
    case ApiMethod::delete_: return 3;
    case ApiMethod::other: return 4;
  }
  return 4;
}

size_t status_index(int status) {
  for (size_t i = 0; i < kApiStatusCodes.size(); ++i) {
    if (kApiStatusCodes[i] == status) return i;
  }
  for (size_t i = 0; i < kApiStatusCodes.size(); ++i) {
    if (kApiStatusCodes[i] == 500) return i;
  }
  return 0;
}

size_t api_cell(ApiRoute route, ApiMethod method, int status) {
  return (route_index(route) * kApiMethodCount + method_index(method)) *
             kApiStatusCount +
         status_index(status);
}

// Bounded signed DC set: -203, -5..-1, 1..5, 203; anything else is "other".
size_t me_slot(int dc) {
  if (dc == -203) return 0;
  if (dc >= -5 && dc <= -1) return static_cast<size_t>(dc + 6);
  if (dc >= 1 && dc <= 5) return static_cast<size_t>(dc + 5);
  if (dc == 203) return 11;
  return kMeSlotCount - 1;
}

void append_metric(std::ostringstream& out, std::string_view name,
                   std::string_view labels, uint64_t value) {
  out << name;
  if (!labels.empty()) out << '{' << labels << '}';
  out << ' ' << value << '\n';
}

uint64_t monotonic_ns() noexcept {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

std::string worker_label(std::size_t worker) {
  return "worker=\"" + std::to_string(worker) + "\"";
}

}  // namespace

const char* to_string(RejectReason reason) noexcept {
  return kRejectLabels[reject_index(reason)];
}
const char* to_string(HandshakeResult result) noexcept {
  return kHandshakeLabels[handshake_index(result)];
}
const char* to_string(Direction direction) noexcept {
  return direction == Direction::client_to_server ? "c2s" : "s2c";
}
const char* to_string(BufferState state) noexcept {
  return kBufferLabels[buffer_index(state)];
}
const char* to_string(ApiRoute route) noexcept {
  return kApiRouteLabels[route_index(route)];
}
const char* to_string(ApiMethod method) noexcept {
  return kApiMethodLabels[method_index(method)];
}
const char* to_string(MeResult result) noexcept {
  switch (result) {
    case MeResult::success: return "success";
    case MeResult::failure: return "failure";
    case MeResult::timeout: return "timeout";
  }
  return "failure";
}

void UserMetrics::connection_opened() noexcept {
  active_.fetch_add(1, std::memory_order_relaxed);
}
bool UserMetrics::try_connection_open(uint64_t limit) noexcept {
  uint64_t current = active_.load(std::memory_order_relaxed);
  while (current < limit) {
    if (active_.compare_exchange_weak(current, current + 1,
                                      std::memory_order_relaxed,
                                      std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}
void UserMetrics::connection_closed() noexcept {
  uint64_t current = active_.load(std::memory_order_relaxed);
  while (current > 0 &&
         !active_.compare_exchange_weak(current, current - 1,
                                        std::memory_order_relaxed)) {
  }
}
void UserMetrics::add_payload(Direction direction, uint64_t bytes) noexcept {
  if (direction == Direction::client_to_server) {
    payload_c2s_.fetch_add(bytes, std::memory_order_relaxed);
  } else {
    payload_s2c_.fetch_add(bytes, std::memory_order_relaxed);
  }
}
namespace {
int64_t payload_total(const std::atomic<uint64_t>& c2s, const std::atomic<uint64_t>& s2c) noexcept {
  return static_cast<int64_t>(c2s.load(std::memory_order_relaxed) +
                              s2c.load(std::memory_order_relaxed));
}
} // namespace
uint64_t UserMetrics::quota_used_bytes() const noexcept {
  const int64_t used = payload_total(payload_c2s_, payload_s2c_) -
                       quota_base_.load(std::memory_order_relaxed);
  return used > 0 ? static_cast<uint64_t>(used) : 0;
}
void UserMetrics::set_quota_used_bytes(uint64_t value) noexcept {
  quota_base_.store(payload_total(payload_c2s_, payload_s2c_) - static_cast<int64_t>(value),
                    std::memory_order_relaxed);
}
void UserMetrics::restore_quota(uint64_t used_bytes, int64_t reset_at) noexcept {
  set_quota_used_bytes(used_bytes);
  quota_reset_at_.store(reset_at, std::memory_order_relaxed);
}
void UserMetrics::reset_quota() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  quota_reset_at_.store(
      static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(now).count()),
      std::memory_order_relaxed);
  set_quota_used_bytes(0);
}
int64_t UserMetrics::quota_reset_at() const noexcept {
  return quota_reset_at_.load(std::memory_order_relaxed);
}

namespace {
constexpr uint64_t kRateMinBurstBytes = 64 * 1024;
constexpr int64_t kRateMaxCostNs = 1'000'000'000'000'000;  // ~11.5 days

int64_t rate_ns_for(uint64_t bytes, uint64_t rate) noexcept {
  const long double ns = static_cast<long double>(bytes) * 1e9L /
                         static_cast<long double>(rate);
  if (ns >= static_cast<long double>(kRateMaxCostNs)) return kRateMaxCostNs;
  return static_cast<int64_t>(ns);
}
}  // namespace

void UserMetrics::add_active_connections(int64_t all, int64_t media) noexcept {
  if (all != 0) active_rate_conns_.fetch_add(all, std::memory_order_relaxed);
  if (media != 0) active_media_conns_.fetch_add(media, std::memory_order_relaxed);
  if (all != 0 || media != 0) active_generation_.fetch_add(1, std::memory_order_relaxed);
}
uint64_t UserMetrics::active_generation() const noexcept {
  return active_generation_.load(std::memory_order_relaxed);
}
int64_t UserMetrics::active_rate_connections() const noexcept {
  return active_rate_conns_.load(std::memory_order_relaxed);
}
int64_t UserMetrics::active_media_connections() const noexcept {
  return active_media_conns_.load(std::memory_order_relaxed);
}
uint64_t UserMetrics::rate_burst_bytes(uint64_t rate_bytes_per_sec) noexcept {
  return std::max(rate_bytes_per_sec, kRateMinBurstBytes);
}
int64_t UserMetrics::rate_consume(Direction direction, uint64_t bytes,
                                  uint64_t rate_bytes_per_sec,
                                  int64_t now_ns) noexcept {
  if (rate_bytes_per_sec == 0) return 0;
  auto& tat = rate_tat_[direction == Direction::client_to_server ? 0 : 1];
  const int64_t cost = rate_ns_for(bytes, rate_bytes_per_sec);
  int64_t current = tat.load(std::memory_order_relaxed);
  int64_t next = 0;
  do {
    next = std::max(current, now_ns) + cost;
  } while (!tat.compare_exchange_weak(current, next, std::memory_order_relaxed,
                                      std::memory_order_relaxed));
  const int64_t resume =
      next - rate_ns_for(rate_burst_bytes(rate_bytes_per_sec), rate_bytes_per_sec);
  return resume > now_ns ? resume : 0;
}
int64_t UserMetrics::rate_resume_at(Direction direction, uint64_t rate_bytes_per_sec,
                                    int64_t now_ns) const noexcept {
  if (rate_bytes_per_sec == 0) return 0;
  const int64_t tat =
      rate_tat_[direction == Direction::client_to_server ? 0 : 1].load(
          std::memory_order_relaxed);
  const int64_t resume =
      tat - rate_ns_for(rate_burst_bytes(rate_bytes_per_sec), rate_bytes_per_sec);
  return resume > now_ns ? resume : 0;
}
uint64_t UserMetrics::active_connections() const noexcept {
  return active_.load(std::memory_order_relaxed);
}
void UserMetrics::set_active_unique_ips(uint64_t value) noexcept {
  unique_ips_.store(value, std::memory_order_relaxed);
}
uint64_t UserMetrics::active_unique_ips() const noexcept {
  return unique_ips_.load(std::memory_order_relaxed);
}
void UserMetrics::set_qualified_unique_ips(uint64_t value) noexcept {
  qualified_ips_.store(value, std::memory_order_relaxed);
}
uint64_t UserMetrics::qualified_unique_ips() const noexcept {
  return qualified_ips_.load(std::memory_order_relaxed);
}
void UserMetrics::set_devices(uint64_t recent, uint64_t connected) noexcept {
  devices_.store(recent, std::memory_order_relaxed);
  devices_connected_.store(connected, std::memory_order_relaxed);
}
uint64_t UserMetrics::devices() const noexcept {
  return devices_.load(std::memory_order_relaxed);
}
uint64_t UserMetrics::devices_connected() const noexcept {
  return devices_connected_.load(std::memory_order_relaxed);
}
uint64_t UserMetrics::payload_c2s_bytes() const noexcept {
  return payload_c2s_.load(std::memory_order_relaxed);
}
uint64_t UserMetrics::payload_s2c_bytes() const noexcept {
  return payload_s2c_.load(std::memory_order_relaxed);
}

struct Statistics::Impl {
  static constexpr size_t kMaxWorkers = 256;

  struct MeSlot {
    std::atomic<bool> connected{false};
    std::atomic<uint64_t> reconnects{0};
    std::atomic<uint64_t> requests_success{0};
    std::atomic<uint64_t> requests_failure{0};
    std::atomic<uint64_t> requests_timeout{0};
    std::atomic<uint64_t> ready_depth{0};
    std::atomic<uint64_t> ready_clients{0};
    std::atomic<uint64_t> frames_bytes{0};
    std::atomic<uint64_t> out_bytes{0};
    std::atomic<uint64_t> ans_received{0};
    std::atomic<uint64_t> ans_delivered{0};
    std::atomic<uint64_t> ans_dropped_unknown{0};
    std::atomic<uint64_t> ans_dropped_other{0};
    std::atomic<bool> ans_seen{false};
    std::atomic<uint64_t> last_ans_age{0};
    std::atomic<uint64_t> control_close_conn{0};
    std::atomic<uint64_t> control_close_ext{0};
    std::atomic<uint64_t> control_unknown{0};
    std::atomic<uint64_t> control_malformed{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> tx_bytes{0};
    // Per-reactor ME pool gauges (melife). snapshot() sums the pool sizes and
    // ready counts, so N reactors never collapse into one pool.
    std::atomic<uint64_t> pool_connections{0};
    std::atomic<uint64_t> pool_ready{0};
    std::atomic<uint64_t> pool_target{0};
    std::atomic<uint64_t> bound_clients{0};
    std::atomic<uint64_t> scale_up{0};
    std::atomic<uint64_t> scale_down{0};
    std::atomic<uint64_t> creation_failures{0};
    // Keepalive: per-reactor DC gauge plus process-lifetime counters.
    std::atomic<uint64_t> ping_sent{0};
    std::atomic<uint64_t> ping_pong{0};
    std::atomic<uint64_t> ping_stall{0};
    std::atomic<uint64_t> ping_timeout{0};
    std::atomic<uint64_t> ping_rtt_us{0};
    std::atomic<bool> ping_rtt_valid{false};
    std::atomic<uint64_t> direct_active{0};
    std::atomic<uint64_t> direct_accepted{0};
    std::atomic<uint64_t> direct_fail{0};
    std::atomic<uint64_t> direct_rx{0};
    std::atomic<uint64_t> direct_tx{0};
    std::atomic<uint64_t> direct_budget_pauses{0};
  };

  // Per-reactor ME budget/read diagnostics. Deliberately NOT folded into
  // MeSlot: MeSlot is aggregated across reactors by snapshot(), while these
  // values must stay attributable to one worker.
  struct MeWorkerGauges {
    std::atomic<uint64_t> connections{0};
    std::atomic<uint64_t> ready_connections{0};
    std::atomic<uint64_t> read_armed_connections{0};
    std::atomic<uint64_t> budget_paused_connections{0};
    std::atomic<uint64_t> bound_clients_on_paused{0};
    std::atomic<uint64_t> budget_pauses{0};
    std::atomic<uint64_t> budget_resumes{0};
    std::atomic<uint64_t> current_pause_age_ms{0};
    std::atomic<uint64_t> max_pause_age_ms{0};
    std::atomic<uint64_t> worst_writer_rtt_us{0};
    std::atomic<uint64_t> slow_writers{0};
    std::atomic<uint64_t> slow_evictions{0};
  };

  // Gauges owned by one reactor. snapshot() sums them (boolean OR for
  // `connected`, max for the shared replay-cache size, min for the last-answer
  // age). ME request/answer outcome counters are reactor-sharded into the
  // writer's fixed slot (worker % kMaxWorkers); the remaining process-lifetime
  // ME counters have no owning reactor and are accumulated in slot 0 with
  // atomics. snapshot() sums the sharded fields over the monotonic
  // high-water bound of ever-addressable/touched slots, so each increment is
  // counted exactly once without a fixed 256-slot sweep.
  struct WorkerGauges {
    std::atomic<bool> ready{false};
    std::array<std::atomic<uint64_t>, kBufferStateCount> buffer_bytes;
    std::atomic<uint64_t> buffer_budget_used{0};
    std::atomic<uint64_t> budget_limit_bytes{0};
    std::atomic<uint64_t> active_clients{0};
    std::atomic<uint64_t> handshakes_pending{0};
    std::atomic<uint64_t> client_pool_objects{0};
    std::atomic<uint64_t> replay_cache{0};
    std::atomic<uint64_t> me_pending_bytes{0};
    // Monotonic liveness. heartbeat_ns is a steady_clock epoch timestamp
    // (0 = never published); snapshot() derives the age against its own clock.
    std::atomic<uint64_t> heartbeat_ns{0};
    std::atomic<uint64_t> housekeeping_lateness_ms{0};
    std::atomic<uint64_t> housekeeping_lateness_max_ms{0};
    std::array<MeSlot, kMeSlotCount> me;  // zero-initialized by MeSlot defaults
    std::array<MeWorkerGauges, kMeSlotCount> me_worker;
  };

  Impl(size_t max_tracked_users, std::chrono::steady_clock::time_point start)
      : started_at(start), max_users(std::min(max_tracked_users, kMaxUsersLimit)) {
    if (max_users == 0) max_users = 1;
    for (auto& worker : gauges) {
      for (auto& counter : worker.buffer_bytes) counter.store(0);
    }
    for (auto& counter : rejected_by_reason) counter.store(0);
    for (auto& counter : handshakes) counter.store(0);
    for (auto& cell : api_cells) cell.store(0);
  }

  // Covers `slot` (an index, not a count) for later snapshot sweeps. The
  // caller has already published its relaxed increment; the release RMW below
  // orders that increment before the raised bound becomes visible to a
  // snapshot that acquire-loads it. Already-covered slots do not RMW.
  void publish_slot(size_t slot) noexcept {
    raise_high_water(slot + 1);
  }

  void raise_high_water(size_t required) noexcept {
    required = std::min(required, kMaxWorkers);
    size_t bound = shard_high_water.slots.load(std::memory_order_relaxed);
    while (required > bound &&
           !shard_high_water.slots.compare_exchange_weak(
               bound, required, std::memory_order_release,
               std::memory_order_relaxed)) {
    }
  }

  std::chrono::steady_clock::time_point started_at;
  std::atomic<size_t> worker_count{1};
  // Monotonic high-water bound (1..kMaxWorkers) of fixed counter slots that a
  // writer may have used: raised by configure_workers() and lazily by the
  // sharded ME counter overloads on first use of their slot. It never shrinks,
  // so shrinking the worker count cannot hide cumulative history. Only writers
  // on a not-yet-covered slot perform a RMW; the steady-state hot path is one
  // relaxed load that stays read-mostly. The release publication of a raised
  // bound pairs with the acquire load in snapshot(): a slot increment that
  // happened before the raise is visible to readers that observe the new bound.
  // alignas(64) keeps the shared hot read off the line of gauges[0], which is
  // written per packet by worker 0.
  struct alignas(64) ShardHighWater {
    std::atomic<size_t> slots{1};  // slot 0 always exists (legacy API)
  };
  ShardHighWater shard_high_water{};
  std::array<WorkerGauges, kMaxWorkers> gauges;
  mutable std::mutex build_mutex;
  std::string build_version;
  std::atomic<uint64_t> accepted{0};
  std::atomic<uint64_t> active{0};
  std::atomic<uint64_t> unique_ips{0};
  std::atomic<uint64_t> qualified_ips{0};
  std::atomic<uint64_t> unique_ip_min_bytes{0};
  std::atomic<uint64_t> rejected{0};
  mutable std::mutex users_mutex;
  std::unordered_map<std::string, std::shared_ptr<UserMetrics>> users;
  size_t max_users;
  std::atomic<uint64_t> client_allocations{0};
  std::atomic<uint64_t> client_reuses{0};
  std::atomic<uint64_t> backpressure_c2s{0};
  std::atomic<uint64_t> backpressure_s2c{0};
  std::array<std::atomic<uint64_t>, kRelayCloseReasons> relay_closes{};
  std::atomic<uint64_t> media_throttled{0};
  std::array<std::atomic<uint64_t>, kApiRouteCount * kApiMethodCount * kApiStatusCount>
      api_cells;
  std::atomic<uint64_t> api_total{0};
  std::array<std::atomic<uint64_t>, kRejectReasonCount> rejected_by_reason;
  std::array<std::atomic<uint64_t>, kHandshakeResultCount> handshakes;
  std::unique_ptr<IpHistory> ip_history;
  std::atomic<uint64_t> ip_history_failures{0};
};


Statistics::Statistics(size_t max_tracked_users)
    : impl_(std::make_unique<Impl>(max_tracked_users,
                                   std::chrono::steady_clock::now())) {}

Statistics::~Statistics() = default;
Statistics::Statistics(Statistics&&) noexcept = default;
Statistics& Statistics::operator=(Statistics&&) noexcept = default;

void Statistics::configure_workers(std::size_t workers) noexcept {
  if (workers == 0) workers = 1;
  if (workers > Statistics::Impl::kMaxWorkers) {
    workers = Statistics::Impl::kMaxWorkers;
  }
  impl_->worker_count.store(workers, std::memory_order_relaxed);
  // Addressable worker slots are part of the cumulative sweep bound even
  // before their first write; the bound never shrinks on reconfiguration.
  impl_->raise_high_water(workers);
}

void Statistics::set_ready(bool ready) noexcept {
  impl_->gauges[0].ready.store(ready, std::memory_order_relaxed);
}
void Statistics::set_ready(std::size_t worker, bool ready) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].ready.store(ready, std::memory_order_relaxed);
}
bool Statistics::ready() const noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  for (std::size_t worker = 0; worker < count; ++worker) {
    if (!impl_->gauges[worker].ready.load(std::memory_order_relaxed)) return false;
  }
  return true;
}
void Statistics::set_build_info(std::string version) {
  std::lock_guard<std::mutex> lock(impl_->build_mutex);
  impl_->build_version = std::move(version);
}

void Statistics::connection_accepted() noexcept {
  impl_->accepted.fetch_add(1, std::memory_order_relaxed);
  impl_->active.fetch_add(1, std::memory_order_relaxed);
}
void Statistics::connection_closed() noexcept {
  uint64_t current = impl_->active.load(std::memory_order_relaxed);
  while (current > 0 &&
         !impl_->active.compare_exchange_weak(current, current - 1,
                                              std::memory_order_relaxed)) {
  }
}
void Statistics::connection_rejected(RejectReason reason) noexcept {
  impl_->rejected.fetch_add(1, std::memory_order_relaxed);
  impl_->rejected_by_reason[reject_index(reason)].fetch_add(
      1, std::memory_order_relaxed);
}
void Statistics::handshake(HandshakeResult result) noexcept {
  impl_->handshakes[handshake_index(result)].fetch_add(1,
                                                       std::memory_order_relaxed);
}

std::shared_ptr<UserMetrics> Statistics::user(std::string_view name) {
  // Do not let unvalidated caller input create attacker-chosen label series.
  if (!UserStore::is_valid_name(name)) return nullptr;
  std::lock_guard<std::mutex> lock(impl_->users_mutex);
  const auto existing = impl_->users.find(std::string(name));
  if (existing != impl_->users.end()) return existing->second;
  if (impl_->users.size() >= impl_->max_users) return nullptr;
  auto metrics = std::make_shared<UserMetrics>();
  impl_->users.emplace(std::string(name), metrics);
  return metrics;
}

void Statistics::forget_user(std::string_view name) noexcept {
  std::lock_guard<std::mutex> lock(impl_->users_mutex);
  impl_->users.erase(std::string(name));
}

void Statistics::set_active_unique_ips(uint64_t value) noexcept {
  impl_->unique_ips.store(value, std::memory_order_relaxed);
}

void Statistics::set_qualified_unique_ips(uint64_t value) noexcept {
  impl_->qualified_ips.store(value, std::memory_order_relaxed);
}

void Statistics::set_unique_ip_min_bytes(uint64_t value) noexcept {
  impl_->unique_ip_min_bytes.store(value, std::memory_order_relaxed);
}

void Statistics::enable_ip_history(std::string path) {
  if (impl_->ip_history) {
    throw std::logic_error("IP history is already enabled");
  }
  impl_->ip_history =
      std::make_unique<IpHistory>(std::filesystem::path(std::move(path)));
}

bool Statistics::rotate_ip_history(int64_t unix_seconds) noexcept {
  if (!impl_->ip_history) return false;
  try {
    return impl_->ip_history->rotate(unix_seconds);
  } catch (...) {
    impl_->ip_history_failures.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
}

bool Statistics::observe_ip_history(const std::array<std::uint8_t, 16>& ip) noexcept {
  return observe_history(ip, false);
}

bool Statistics::observe_ip_history_active(
    const std::array<std::uint8_t, 16>& ip) noexcept {
  return observe_history(ip, true);
}

bool Statistics::observe_history(const std::array<std::uint8_t, 16>& ip,
                                 bool active) noexcept {
  if (!impl_->ip_history) return false;
  try {
    const bool observed = active ? impl_->ip_history->observe_active(ip)
                                 : impl_->ip_history->observe(ip);
    if (!observed) {
      impl_->ip_history_failures.fetch_add(1, std::memory_order_relaxed);
    }
    return observed;
  } catch (...) {
    impl_->ip_history_failures.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
}

void Statistics::set_buffer_bytes(BufferState state, uint64_t bytes) noexcept {
  set_buffer_bytes(0, state, bytes);
}
void Statistics::set_buffer_bytes(std::size_t worker, BufferState state,
                                  uint64_t bytes) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].buffer_bytes[buffer_index(state)].store(
      bytes, std::memory_order_relaxed);
}
void Statistics::set_buffer_budget_used(uint64_t bytes) noexcept {
  set_buffer_budget_used(0, bytes);
}
void Statistics::set_buffer_budget_used(std::size_t worker,
                                        uint64_t bytes) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].buffer_budget_used.store(
      bytes, std::memory_order_relaxed);
}
void Statistics::set_handshakes_pending(uint64_t value) noexcept {
  set_handshakes_pending(0, value);
}
void Statistics::set_handshakes_pending(std::size_t worker,
                                        uint64_t value) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].handshakes_pending.store(
      value, std::memory_order_relaxed);
}
void Statistics::set_client_pool(uint64_t pooled, uint64_t allocations,
                                 uint64_t reuses) noexcept {
  set_client_pool(0, pooled, allocations, reuses);
}
void Statistics::set_client_pool(std::size_t worker, uint64_t pooled,
                                 uint64_t allocations,
                                 uint64_t reuses) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].client_pool_objects.store(
      pooled, std::memory_order_relaxed);
  // Allocation/reuse counters are process-lifetime telemetry shared by every
  // reactor; store the latest cumulative value instead of summing N copies.
  impl_->client_allocations.store(allocations, std::memory_order_relaxed);
  impl_->client_reuses.store(reuses, std::memory_order_relaxed);
}
void Statistics::media_throttled() noexcept {
  impl_->media_throttled.fetch_add(1, std::memory_order_relaxed);
}

void Statistics::relay_closed(RelayCloseReason reason) noexcept {
  const auto index = static_cast<std::size_t>(reason);
  if (index < kRelayCloseReasons) impl_->relay_closes[index].fetch_add(1, std::memory_order_relaxed);
}

void Statistics::add_backpressure(Direction direction) noexcept {
  if (direction == Direction::client_to_server) {
    impl_->backpressure_c2s.fetch_add(1, std::memory_order_relaxed);
  } else {
    impl_->backpressure_s2c.fetch_add(1, std::memory_order_relaxed);
  }
}
void Statistics::set_replay_cache_entries(uint64_t entries) noexcept {
  set_replay_cache_entries(0, entries);
}
void Statistics::set_replay_cache_entries(std::size_t worker,
                                          uint64_t entries) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].replay_cache.store(
      entries, std::memory_order_relaxed);
}

void Statistics::set_worker_diagnostics(std::size_t worker,
                                        uint64_t budget_used_bytes,
                                        uint64_t budget_limit_bytes,
                                        uint64_t active_clients,
                                        uint64_t handshakes_pending) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& gauges = impl_->gauges[worker % count];
  gauges.buffer_budget_used.store(budget_used_bytes,
                                  std::memory_order_relaxed);
  gauges.budget_limit_bytes.store(budget_limit_bytes,
                                  std::memory_order_relaxed);
  gauges.active_clients.store(active_clients, std::memory_order_relaxed);
  gauges.handshakes_pending.store(handshakes_pending,
                                  std::memory_order_relaxed);
}

void Statistics::set_worker_heartbeat(std::size_t worker) noexcept {
  set_worker_heartbeat_at(worker, monotonic_ns());
}

void Statistics::set_worker_heartbeat_at(std::size_t worker,
                                         uint64_t monotonic_ns_value) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].heartbeat_ns.store(
      monotonic_ns_value, std::memory_order_relaxed);
}

void Statistics::set_worker_housekeeping_lateness(std::size_t worker,
                                                  uint64_t last_ms,
                                                  uint64_t max_ms) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& gauges = impl_->gauges[worker % count];
  gauges.housekeeping_lateness_ms.store(last_ms, std::memory_order_relaxed);
  gauges.housekeeping_lateness_max_ms.store(max_ms, std::memory_order_relaxed);
}

void Statistics::api_request(ApiRoute route, ApiMethod method, int status) noexcept {
  impl_->api_total.fetch_add(1, std::memory_order_relaxed);
  impl_->api_cells[api_cell(route, method, status)].fetch_add(
      1, std::memory_order_relaxed);
}

void Statistics::me_connected(int dc, bool connected) noexcept {
  me_connected(0, dc, connected);
}
void Statistics::me_connected(std::size_t worker, int dc,
                              bool connected) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  // Only the connectivity flag. Inbound control counters are cumulative per DC
  // and owned by the reactor (which folds replaced connections into a base), so
  // a disconnected transition must not erase them.
  slot.connected.store(connected, std::memory_order_relaxed);
}
void Statistics::me_reconnect(int dc) noexcept {
  // The reconnect counter is not reactor-owned, so every reactor accumulates it
  // in slot 0. snapshot() sums slots exactly once, and the increments are
  // atomic, so N reactors cannot multiply a total. Request/answer outcomes are
  // sharded separately by worker (see me_request/me_answer below).
  impl_->gauges[0].me[me_slot(dc)].reconnects.fetch_add(
      1, std::memory_order_relaxed);
}
void Statistics::me_request(int dc, MeResult result) noexcept {
  me_request(0, dc, result);
}
void Statistics::me_request(std::size_t worker, int dc,
                            MeResult result) noexcept {
  // Route by the fixed statistics capacity, not by the configured worker
  // count: a worker id that was valid before a reconfiguration must keep its
  // slot. The slot is published to the monotonic high-water bound after the
  // increment, so snapshot() can stop at the highest slot ever touched and the
  // steady state costs one relaxed load instead of a per-packet RMW.
  const std::size_t shard = worker % Impl::kMaxWorkers;
  auto& slot = impl_->gauges[shard].me[me_slot(dc)];
  switch (result) {
    case MeResult::success:
      slot.requests_success.fetch_add(1, std::memory_order_relaxed);
      break;
    case MeResult::failure:
      slot.requests_failure.fetch_add(1, std::memory_order_relaxed);
      break;
    case MeResult::timeout:
      slot.requests_timeout.fetch_add(1, std::memory_order_relaxed);
      break;
  }
  impl_->publish_slot(shard);
}
void Statistics::me_answer(int dc, MeAnswerResult result) noexcept {
  me_answer(0, dc, result);
}
void Statistics::me_answer(std::size_t worker, int dc,
                           MeAnswerResult result) noexcept {
  const std::size_t shard = worker % Impl::kMaxWorkers;
  auto& slot = impl_->gauges[shard].me[me_slot(dc)];
  switch (result) {
    case MeAnswerResult::received:
      slot.ans_received.fetch_add(1, std::memory_order_relaxed);
      break;
    case MeAnswerResult::delivered:
      slot.ans_delivered.fetch_add(1, std::memory_order_relaxed);
      break;
    case MeAnswerResult::dropped_unknown:
      slot.ans_dropped_unknown.fetch_add(1, std::memory_order_relaxed);
      break;
    case MeAnswerResult::dropped_other:
      slot.ans_dropped_other.fetch_add(1, std::memory_order_relaxed);
      break;
  }
  impl_->publish_slot(shard);
}
void Statistics::me_control(int dc, uint64_t close_conn, uint64_t close_ext,
                            uint64_t unknown, uint64_t malformed) noexcept {
  me_control(0, dc, close_conn, close_ext, unknown, malformed);
}
void Statistics::me_control(std::size_t worker, int dc, uint64_t close_conn,
                            uint64_t close_ext, uint64_t unknown,
                            uint64_t malformed) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.control_close_conn.store(close_conn, std::memory_order_relaxed);
  slot.control_close_ext.store(close_ext, std::memory_order_relaxed);
  slot.control_unknown.store(unknown, std::memory_order_relaxed);
  slot.control_malformed.store(malformed, std::memory_order_relaxed);
}
void Statistics::me_queue(int dc, uint64_t depth, uint64_t clients,
                          uint64_t frames_bytes, uint64_t out_bytes) noexcept {
  me_queue(0, dc, depth, clients, frames_bytes, out_bytes);
}
void Statistics::me_queue(std::size_t worker, int dc, uint64_t depth,
                          uint64_t clients, uint64_t frames_bytes,
                          uint64_t out_bytes) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.ready_depth.store(depth, std::memory_order_relaxed);
  slot.ready_clients.store(clients, std::memory_order_relaxed);
  slot.frames_bytes.store(frames_bytes, std::memory_order_relaxed);
  slot.out_bytes.store(out_bytes, std::memory_order_relaxed);
}
void Statistics::direct_budget_pause(int dc) noexcept {
  impl_->gauges[0].me[me_slot(dc)].direct_budget_pauses.fetch_add(
      1, std::memory_order_relaxed);
}
void Statistics::me_direct(int dc, uint64_t active, uint64_t accepted,
                           uint64_t connect_fail, uint64_t rx_bytes,
                           uint64_t tx_bytes) noexcept {
  me_direct(0, dc, active, accepted, connect_fail, rx_bytes, tx_bytes);
}
void Statistics::me_direct(std::size_t worker, int dc, uint64_t active,
                           uint64_t accepted, uint64_t connect_fail,
                           uint64_t rx_bytes, uint64_t tx_bytes) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.direct_active.store(active, std::memory_order_relaxed);
  slot.direct_accepted.store(accepted, std::memory_order_relaxed);
  slot.direct_fail.store(connect_fail, std::memory_order_relaxed);
  slot.direct_rx.store(rx_bytes, std::memory_order_relaxed);
  slot.direct_tx.store(tx_bytes, std::memory_order_relaxed);
}
void Statistics::me_io(int dc, uint64_t rx_bytes_total,
                       uint64_t tx_bytes_total) noexcept {
  me_io(0, dc, rx_bytes_total, tx_bytes_total);
}
void Statistics::me_io(std::size_t worker, int dc, uint64_t rx_bytes_total,
                       uint64_t tx_bytes_total) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.rx_bytes.store(rx_bytes_total, std::memory_order_relaxed);
  slot.tx_bytes.store(tx_bytes_total, std::memory_order_relaxed);
}
void Statistics::me_last_answer_age(int dc, uint64_t age_seconds) noexcept {
  me_last_answer_age(0, dc, age_seconds);
}
void Statistics::me_last_answer_age(std::size_t worker, int dc,
                                    uint64_t age_seconds) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.last_ans_age.store(age_seconds, std::memory_order_relaxed);
  slot.ans_seen.store(true, std::memory_order_relaxed);
}
void Statistics::me_last_answer_clear(int dc) noexcept {
  me_last_answer_clear(0, dc);
}
void Statistics::me_last_answer_clear(std::size_t worker, int dc) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  // Order matters for a concurrent reader: drop the age first, then the flag,
  // so a snapshot can never pair "seen" with a stale age. The other order can
  // only produce "not seen", which is the value we are publishing anyway.
  slot.last_ans_age.store(0, std::memory_order_relaxed);
  slot.ans_seen.store(false, std::memory_order_relaxed);
}
void Statistics::me_pool(int dc, uint64_t connections, uint64_t ready) noexcept {
  me_pool(0, dc, connections, ready);
}
void Statistics::me_pool(std::size_t worker, int dc, uint64_t connections,
                         uint64_t ready) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.pool_connections.store(connections, std::memory_order_relaxed);
  slot.pool_ready.store(ready, std::memory_order_relaxed);
}
void Statistics::me_worker(std::size_t worker, int dc,
                           const MeWorkerSnapshot& values) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me_worker[me_slot(dc)];
  slot.connections.store(values.connections, std::memory_order_relaxed);
  slot.ready_connections.store(values.ready_connections,
                               std::memory_order_relaxed);
  slot.read_armed_connections.store(values.read_armed_connections,
                                    std::memory_order_relaxed);
  slot.budget_paused_connections.store(values.budget_paused_connections,
                                       std::memory_order_relaxed);
  slot.bound_clients_on_paused.store(values.bound_clients_on_paused,
                                     std::memory_order_relaxed);
  slot.budget_pauses.store(values.budget_pauses_total,
                           std::memory_order_relaxed);
  slot.budget_resumes.store(values.budget_resumes_total,
                            std::memory_order_relaxed);
  slot.current_pause_age_ms.store(values.current_pause_age_ms,
                                  std::memory_order_relaxed);
  slot.max_pause_age_ms.store(values.max_pause_age_ms,
                              std::memory_order_relaxed);
  slot.worst_writer_rtt_us.store(values.worst_writer_rtt_us,
                                 std::memory_order_relaxed);
  slot.slow_writers.store(values.slow_writers, std::memory_order_relaxed);
  slot.slow_evictions.store(values.slow_evictions_total,
                            std::memory_order_relaxed);
}
void Statistics::me_pool_scaling(std::size_t worker, int dc, uint64_t target,
                                 uint64_t clients, uint64_t up, uint64_t down,
                                 uint64_t failures) noexcept {
  const auto count = impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.pool_target.store(target, std::memory_order_relaxed);
  slot.bound_clients.store(clients, std::memory_order_relaxed);
  slot.scale_up.store(up, std::memory_order_relaxed);
  slot.scale_down.store(down, std::memory_order_relaxed);
  slot.creation_failures.store(failures, std::memory_order_relaxed);
}
void Statistics::me_ping_sent(int dc) noexcept {
  impl_->gauges[0].me[me_slot(dc)].ping_sent.fetch_add(1, std::memory_order_relaxed);
}
void Statistics::me_ping_pong(int dc, uint64_t rtt_us) noexcept {
  // Only the counter is process-lifetime; the RTT gauge is reactor-owned and
  // published by me_ping_rtt()/publish_me_rtt() as the pool aggregate.
  (void)rtt_us;
  impl_->gauges[0].me[me_slot(dc)].ping_pong.fetch_add(1, std::memory_order_relaxed);
}
void Statistics::me_ping_rtt(int dc, uint64_t rtt_us) noexcept {
  me_ping_rtt(0, dc, rtt_us);
}
void Statistics::me_ping_rtt(std::size_t worker, int dc, uint64_t rtt_us) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  auto& slot = impl_->gauges[worker % count].me[me_slot(dc)];
  slot.ping_rtt_us.store(rtt_us, std::memory_order_relaxed);
  slot.ping_rtt_valid.store(true, std::memory_order_relaxed);
}
void Statistics::me_ping_stall(int dc) noexcept {
  impl_->gauges[0].me[me_slot(dc)].ping_stall.fetch_add(1, std::memory_order_relaxed);
}
void Statistics::me_ping_timeout(int dc) noexcept {
  impl_->gauges[0].me[me_slot(dc)].ping_timeout.fetch_add(1, std::memory_order_relaxed);
}
void Statistics::me_pending_buffer_bytes(uint64_t bytes) noexcept {
  me_pending_buffer_bytes(0, bytes);
}
void Statistics::me_pending_buffer_bytes(std::size_t worker,
                                         uint64_t bytes) noexcept {
  const std::size_t count =
      impl_->worker_count.load(std::memory_order_relaxed);
  impl_->gauges[worker % count].me_pending_bytes.store(
      bytes, std::memory_order_relaxed);
}

StatisticsSnapshot Statistics::snapshot() const {
  StatisticsSnapshot out;
  {
    std::lock_guard<std::mutex> lock(impl_->build_mutex);
    out.build_version = impl_->build_version;
  }
  out.uptime_seconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - impl_->started_at)
          .count());
  out.ready = ready();
  const std::size_t workers =
      impl_->worker_count.load(std::memory_order_relaxed);
  // Cumulative request/answer shards are swept once per snapshot up to the
  // monotonic high-water bound of touched/addressable slots, not the full
  // fixed capacity. The single acquire load pairs with the release raises in
  // publish_slot()/configure_workers(), so slots covered by the observed bound
  // are visible to the relaxed loads below.
  const std::size_t cumulative_slots = std::min(
      impl_->shard_high_water.slots.load(std::memory_order_acquire),
      Impl::kMaxWorkers);
  out.connections_accepted_total =
      impl_->accepted.load(std::memory_order_relaxed);
  out.connections_active = impl_->active.load(std::memory_order_relaxed);
  out.active_unique_ips = impl_->unique_ips.load(std::memory_order_relaxed);
  out.qualified_unique_ips = impl_->qualified_ips.load(std::memory_order_relaxed);
  out.unique_ip_min_bytes =
      impl_->unique_ip_min_bytes.load(std::memory_order_relaxed);
  out.connections_rejected_total =
      impl_->rejected.load(std::memory_order_relaxed);
  for (size_t i = 0; i < kRejectReasonCount; ++i) {
    const uint64_t value =
        impl_->rejected_by_reason[i].load(std::memory_order_relaxed);
    if (value != 0) out.rejected_by_reason[kRejectLabels[i]] = value;
  }
  for (size_t i = 0; i < kHandshakeResultCount; ++i) {
    const uint64_t value = impl_->handshakes[i].load(std::memory_order_relaxed);
    if (value != 0) out.handshakes_by_result[kHandshakeLabels[i]] = value;
  }
  {
    std::lock_guard<std::mutex> lock(impl_->users_mutex);
    for (const auto& [name, metrics] : impl_->users) {
      UserMetricsSnapshot entry;
      entry.active_connections = metrics->active_connections();
      entry.unique_ips_active = metrics->active_unique_ips();
      entry.unique_ips_qualified = metrics->qualified_unique_ips();
      entry.devices = metrics->devices();
      entry.devices_connected = metrics->devices_connected();
      entry.payload_c2s_bytes = metrics->payload_c2s_bytes();
      entry.payload_s2c_bytes = metrics->payload_s2c_bytes();
      entry.quota_used_bytes = metrics->quota_used_bytes();
      entry.quota_reset_at = metrics->quota_reset_at();
      out.users.emplace(name, entry);
    }
  }
  for (size_t i = 0; i < kBufferStateCount; ++i) out.buffer_bytes[i] = 0;
  uint64_t buffer_budget_used = 0;
  uint64_t handshakes_pending = 0;
  uint64_t client_pool_objects = 0;
  uint64_t replay_entries = 0;
  uint64_t me_pending_bytes = 0;
  out.workers.resize(workers);
  const uint64_t now_ns = monotonic_ns();
  for (std::size_t worker = 0; worker < workers; ++worker) {
    const auto& gauges = impl_->gauges[worker];
    for (size_t i = 0; i < kBufferStateCount; ++i) {
      out.buffer_bytes[i] += gauges.buffer_bytes[i].load(std::memory_order_relaxed);
    }
    const uint64_t worker_budget_used =
        gauges.buffer_budget_used.load(std::memory_order_relaxed);
    buffer_budget_used += worker_budget_used;
    const uint64_t worker_handshakes =
        gauges.handshakes_pending.load(std::memory_order_relaxed);
    handshakes_pending += worker_handshakes;
    client_pool_objects +=
        gauges.client_pool_objects.load(std::memory_order_relaxed);
    // The replay cache is shared by every reactor, so all workers publish the
    // same size: take the maximum instead of summing N copies.
    replay_entries = std::max(
        replay_entries, gauges.replay_cache.load(std::memory_order_relaxed));
    me_pending_bytes +=
        gauges.me_pending_bytes.load(std::memory_order_relaxed);

    WorkerSnapshot& worker_out = out.workers[worker];
    worker_out.budget_used_bytes = worker_budget_used;
    worker_out.budget_limit_bytes =
        gauges.budget_limit_bytes.load(std::memory_order_relaxed);
    worker_out.active_clients =
        gauges.active_clients.load(std::memory_order_relaxed);
    worker_out.handshakes_pending = worker_handshakes;
    const uint64_t heartbeat_ns =
        gauges.heartbeat_ns.load(std::memory_order_relaxed);
    if (heartbeat_ns != 0) {
      worker_out.heartbeat_seen = true;
      // Clamp a timestamp from the future to zero rather than underflowing.
      worker_out.heartbeat_age_ms =
          now_ns > heartbeat_ns ? (now_ns - heartbeat_ns) / 1'000'000 : 0;
    }
    worker_out.housekeeping_lateness_ms =
        gauges.housekeeping_lateness_ms.load(std::memory_order_relaxed);
    worker_out.housekeeping_lateness_max_ms =
        gauges.housekeeping_lateness_max_ms.load(std::memory_order_relaxed);
    for (size_t i = 0; i < kMeSlotCount; ++i) {
      const auto& source = gauges.me_worker[i];
      MeWorkerSnapshot& target = worker_out.me_dcs[kMeLabels[i]];
      target.connections =
          source.connections.load(std::memory_order_relaxed);
      target.ready_connections =
          source.ready_connections.load(std::memory_order_relaxed);
      target.read_armed_connections =
          source.read_armed_connections.load(std::memory_order_relaxed);
      target.budget_paused_connections =
          source.budget_paused_connections.load(std::memory_order_relaxed);
      target.bound_clients_on_paused =
          source.bound_clients_on_paused.load(std::memory_order_relaxed);
      target.budget_pauses_total =
          source.budget_pauses.load(std::memory_order_relaxed);
      target.budget_resumes_total =
          source.budget_resumes.load(std::memory_order_relaxed);
      target.current_pause_age_ms =
          source.current_pause_age_ms.load(std::memory_order_relaxed);
      target.max_pause_age_ms =
          source.max_pause_age_ms.load(std::memory_order_relaxed);
      target.worst_writer_rtt_us =
          source.worst_writer_rtt_us.load(std::memory_order_relaxed);
      target.slow_writers =
          source.slow_writers.load(std::memory_order_relaxed);
      target.slow_evictions_total =
          source.slow_evictions.load(std::memory_order_relaxed);
    }
  }
  out.backpressure_c2s_total =
      impl_->backpressure_c2s.load(std::memory_order_relaxed);
  out.backpressure_s2c_total =
      impl_->backpressure_s2c.load(std::memory_order_relaxed);
  for (std::size_t index = 0; index < kRelayCloseReasons; ++index) {
    out.relay_closes_total[index] = impl_->relay_closes[index].load(std::memory_order_relaxed);
  }
  out.media_throttled_total = impl_->media_throttled.load(std::memory_order_relaxed);
  out.replay_cache_entries = replay_entries;
  out.api_requests_total = impl_->api_total.load(std::memory_order_relaxed);
  out.me_pending_buffer_bytes = me_pending_bytes;
  out.buffer_budget_used = buffer_budget_used;
  out.handshakes_pending = handshakes_pending;
  out.client_pool_objects = client_pool_objects;
  out.client_allocations_total =
      impl_->client_allocations.load(std::memory_order_relaxed);
  out.client_reuses_total =
      impl_->client_reuses.load(std::memory_order_relaxed);
  if (impl_->ip_history) out.unique_ip_history = impl_->ip_history->snapshot();
  out.ip_history_observation_failures =
      impl_->ip_history_failures.load(std::memory_order_relaxed);
  for (size_t i = 0; i < kMeSlotCount; ++i) {
    MeDcSnapshot entry;
    bool answer_seen = false;
    uint64_t min_answer_age = 0;
    uint64_t rtt_sum = 0;
    uint64_t rtt_samples = 0;
    for (std::size_t worker = 0; worker < workers; ++worker) {
      const auto& slot = impl_->gauges[worker].me[i];
      // One ME pool per reactor: pool sizes and ready members add up, while
      // the reactor count is the number of slots that currently have a ready
      // connection (the honest multi-reactor topology gauge).
      const bool slot_connected = slot.connected.load(std::memory_order_relaxed);
      entry.connected = entry.connected || slot_connected;
      if (slot_connected) ++entry.reactors_connected;
      entry.connections +=
          slot.pool_connections.load(std::memory_order_relaxed);
      entry.ready_connections +=
          slot.pool_ready.load(std::memory_order_relaxed);
      entry.pool_target += slot.pool_target.load(std::memory_order_relaxed);
      entry.bound_clients += slot.bound_clients.load(std::memory_order_relaxed);
      entry.scale_up_total += slot.scale_up.load(std::memory_order_relaxed);
      entry.scale_down_total += slot.scale_down.load(std::memory_order_relaxed);
      entry.creation_failures_total += slot.creation_failures.load(std::memory_order_relaxed);
      // Only reactors whose pool currently has a ready member contribute to
      // the DC RTT mean: an emptied pool keeps its last value for diagnostics
      // but must not dilute the aggregate.
      if (slot.ping_rtt_valid.load(std::memory_order_relaxed) &&
          slot.pool_ready.load(std::memory_order_relaxed) != 0) {
        rtt_sum += slot.ping_rtt_us.load(std::memory_order_relaxed);
        ++rtt_samples;
      }
      entry.pings_sent_total +=
          slot.ping_sent.load(std::memory_order_relaxed);
      entry.pongs_received_total +=
          slot.ping_pong.load(std::memory_order_relaxed);
      entry.ping_timeouts_total +=
          slot.ping_timeout.load(std::memory_order_relaxed);
      entry.ping_stalls_total +=
          slot.ping_stall.load(std::memory_order_relaxed);
      entry.reconnects_total +=
          slot.reconnects.load(std::memory_order_relaxed);
      entry.ready_queue_depth +=
          slot.ready_depth.load(std::memory_order_relaxed);
      entry.ready_queue_clients +=
          slot.ready_clients.load(std::memory_order_relaxed);
      entry.frames_queued_bytes +=
          slot.frames_bytes.load(std::memory_order_relaxed);
      entry.out_queued_bytes +=
          slot.out_bytes.load(std::memory_order_relaxed);
      if (slot.ans_seen.load(std::memory_order_relaxed)) {
        const uint64_t age =
            slot.last_ans_age.load(std::memory_order_relaxed);
        if (!answer_seen || age < min_answer_age) min_answer_age = age;
        answer_seen = true;
      }
      entry.control_close_conn +=
          slot.control_close_conn.load(std::memory_order_relaxed);
      entry.control_close_ext +=
          slot.control_close_ext.load(std::memory_order_relaxed);
      entry.control_unknown +=
          slot.control_unknown.load(std::memory_order_relaxed);
      entry.control_malformed +=
          slot.control_malformed.load(std::memory_order_relaxed);
      entry.rx_bytes_total +=
          slot.rx_bytes.load(std::memory_order_relaxed);
      entry.tx_bytes_total +=
          slot.tx_bytes.load(std::memory_order_relaxed);
      entry.direct_active +=
          slot.direct_active.load(std::memory_order_relaxed);
      entry.direct_accepted_total +=
          slot.direct_accepted.load(std::memory_order_relaxed);
      entry.direct_connect_fail_total +=
          slot.direct_fail.load(std::memory_order_relaxed);
      entry.direct_rx_bytes_total +=
          slot.direct_rx.load(std::memory_order_relaxed);
      entry.direct_tx_bytes_total +=
          slot.direct_tx.load(std::memory_order_relaxed);
      entry.direct_budget_pauses_total +=
          slot.direct_budget_pauses.load(std::memory_order_relaxed);
    }
    // Request/answer outcomes are cumulative and were written into the
    // reactor's fixed slot (worker % 256). They are not gauges of the current
    // worker set, so sweep up to the monotonic high-water bound: shrinking the
    // worker count must not hide history, while untouched high slots cost
    // nothing. Summing outside the active loop keeps the totals independent of
    // reconfiguration.
    for (std::size_t worker = 0; worker < cumulative_slots; ++worker) {
      const auto& cumulative = impl_->gauges[worker].me[i];
      entry.requests_success +=
          cumulative.requests_success.load(std::memory_order_relaxed);
      entry.requests_failure +=
          cumulative.requests_failure.load(std::memory_order_relaxed);
      entry.requests_timeout +=
          cumulative.requests_timeout.load(std::memory_order_relaxed);
      entry.proxy_ans_received_total +=
          cumulative.ans_received.load(std::memory_order_relaxed);
      entry.proxy_ans_delivered_total +=
          cumulative.ans_delivered.load(std::memory_order_relaxed);
      entry.proxy_ans_dropped_unknown_total +=
          cumulative.ans_dropped_unknown.load(std::memory_order_relaxed);
      entry.proxy_ans_dropped_other_total +=
          cumulative.ans_dropped_other.load(std::memory_order_relaxed);
    }
    entry.ping_rtt_us = rtt_samples == 0 ? 0 : rtt_sum / rtt_samples;
    entry.proxy_ans_seen = answer_seen;
    entry.last_proxy_ans_age_seconds = answer_seen ? min_answer_age : 0;
    out.me_dcs.emplace(kMeLabels[i], entry);
  }
  return out;
}

std::string Statistics::escape_label(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char c : value) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

std::string Statistics::prometheus_text() const {
  const StatisticsSnapshot snapshot = this->snapshot();
  std::ostringstream out;

  out << "# HELP mtdd_build_info Build information.\n";
  out << "# TYPE mtdd_build_info gauge\n";
  out << "mtdd_build_info{version=\""
      << escape_label(snapshot.build_version) << "\"} 1\n";
  append_metric(out, "mtdd_uptime_seconds", "", snapshot.uptime_seconds);
  append_metric(out, "mtdd_connections_active", "", snapshot.connections_active);
  out << "# HELP mtdd_unique_ips_active Online unique client IPs (IPv6 as /64) "
         "whose connections moved at least mtdd_unique_ips_min_bytes of payload.\n";
  out << "# TYPE mtdd_unique_ips_active gauge\n";
  append_metric(out, "mtdd_unique_ips_active", "", snapshot.qualified_unique_ips);
  out << "# HELP mtdd_unique_ips_seen Online unique client IPs (IPv6 as /64) "
         "counted at authenticated handshake, before any traffic.\n";
  out << "# TYPE mtdd_unique_ips_seen gauge\n";
  append_metric(out, "mtdd_unique_ips_seen", "", snapshot.active_unique_ips);
  out << "# HELP mtdd_unique_ips_min_bytes Payload bytes (c2s+s2c) a connection "
         "must move before its IP counts as active.\n";
  out << "# TYPE mtdd_unique_ips_min_bytes gauge\n";
  append_metric(out, "mtdd_unique_ips_min_bytes", "", snapshot.unique_ip_min_bytes);
  const auto& history = snapshot.unique_ip_history;
  append_metric(out, "mtdd_unique_ips_estimate", "period=\"hour\"", history.hour);
  append_metric(out, "mtdd_unique_ips_estimate", "period=\"day\"", history.day);
  append_metric(out, "mtdd_unique_ips_estimate", "period=\"week\"", history.week);
  out << "# HELP mtdd_unique_ips_active_estimate HyperLogLog estimate of unique "
         "client IPs that passed the byte threshold in the calendar period.\n";
  out << "# TYPE mtdd_unique_ips_active_estimate gauge\n";
  append_metric(out, "mtdd_unique_ips_active_estimate", "period=\"hour\"",
                history.hour_active);
  append_metric(out, "mtdd_unique_ips_active_estimate", "period=\"day\"",
                history.day_active);
  append_metric(out, "mtdd_unique_ips_active_estimate", "period=\"week\"",
                history.week_active);
  append_metric(out, "mtdd_unique_ips_period_start_seconds", "period=\"hour\"",
                static_cast<uint64_t>(history.hour_started_at));
  append_metric(out, "mtdd_unique_ips_period_start_seconds", "period=\"day\"",
                static_cast<uint64_t>(history.day_started_at));
  append_metric(out, "mtdd_unique_ips_period_start_seconds", "period=\"week\"",
                static_cast<uint64_t>(history.week_started_at));
  append_metric(out, "mtdd_unique_ips_collection_started_seconds", "",
                static_cast<uint64_t>(history.collection_started_at));
  append_metric(out, "mtdd_unique_ips_checkpoint_failures_total", "",
                history.persistence_failures);
  append_metric(out, "mtdd_unique_ips_observation_failures_total", "",
                snapshot.ip_history_observation_failures);
  append_metric(out, "mtdd_connections_accepted_total", "",
                snapshot.connections_accepted_total);
  for (const auto& [reason, value] : snapshot.rejected_by_reason) {
    append_metric(out, "mtdd_connections_rejected_total",
                  "reason=\"" + escape_label(reason) + "\"", value);
  }
  for (const auto& [result, value] : snapshot.handshakes_by_result) {
    append_metric(out, "mtdd_handshakes_total",
                  "result=\"" + escape_label(result) + "\"", value);
  }
  out << "# HELP mtdd_user_quota_used_bytes Payload bytes (c2s+s2c) counted "
         "against the user's data quota since the last quota reset.\n";
  out << "# TYPE mtdd_user_quota_used_bytes gauge\n";
  for (const auto& [name, metrics] : snapshot.users) {
    const std::string label = "user=\"" + escape_label(name) + "\"";
    append_metric(out, "mtdd_user_quota_used_bytes", label,
                  metrics.quota_used_bytes);
  }
  for (const auto& [name, metrics] : snapshot.users) {
    const std::string label = "user=\"" + escape_label(name) + "\"";
    append_metric(out, "mtdd_user_connections_active", label,
                  metrics.active_connections);
    append_metric(out, "mtdd_user_unique_ips_active", label,
                  metrics.unique_ips_qualified);
    append_metric(out, "mtdd_user_unique_ips_seen", label,
                  metrics.unique_ips_active);
    append_metric(out, "mtdd_user_devices", label, metrics.devices);
    append_metric(out, "mtdd_user_devices_connected", label, metrics.devices_connected);
    append_metric(out, "mtdd_user_payload_bytes_received_total",
                  label + ",direction=\"c2s\"", metrics.payload_c2s_bytes);
    append_metric(out, "mtdd_user_payload_bytes_received_total",
                  label + ",direction=\"s2c\"", metrics.payload_s2c_bytes);
  }
  for (size_t i = 0; i < kBufferStateCount; ++i) {
    append_metric(out, "mtdd_buffer_bytes",
                  std::string("state=\"") + kBufferLabels[i] + "\"",
                  snapshot.buffer_bytes[i]);
  }
  {
    static constexpr std::array<const char*, kRelayCloseReasons> kNames{
        "other",   "client_eof",   "client_error", "client_timeout", "idle_timeout",
        "me_lost", "backpressure", "remote_close", "revoked",        "shutdown",
        "device_limit"};
    for (std::size_t index = 0; index < kRelayCloseReasons; ++index) {
      append_metric(out, "mtdd_relay_closes_total",
                    std::string("reason=\"") + kNames[index] + "\"",
                    snapshot.relay_closes_total[index]);
    }
  }
  append_metric(out, "mtdd_media_throttled_total", "", snapshot.media_throttled_total);
  if (snapshot.backpressure_c2s_total != 0) {
    append_metric(out, "mtdd_backpressure_events_total", "direction=\"c2s\"",
                  snapshot.backpressure_c2s_total);
  }
  if (snapshot.backpressure_s2c_total != 0) {
    append_metric(out, "mtdd_backpressure_events_total", "direction=\"s2c\"",
                  snapshot.backpressure_s2c_total);
  }
  append_metric(out, "mtdd_replay_cache_entries",
                "", snapshot.replay_cache_entries);

  for (size_t r = 0; r < kApiRouteCount; ++r) {
    for (size_t m = 0; m < kApiMethodCount; ++m) {
      for (size_t s = 0; s < kApiStatusCount; ++s) {
        const uint64_t value =
            impl_->api_cells[(r * kApiMethodCount + m) * kApiStatusCount + s]
                .load(std::memory_order_relaxed);
        if (value == 0) continue;
        std::string labels = "route=\"";
        labels += kApiRouteLabels[r];
        labels += "\",method=\"";
        labels += kApiMethodLabels[m];
        labels += "\",status=\"";
        labels += kApiStatusLabels[s];
        labels += "\"";
        append_metric(out, "mtdd_api_requests_total", labels, value);
      }
    }
  }

  for (size_t i = 0; i < kMeSlotCount; ++i) {
    const auto found = snapshot.me_dcs.find(kMeLabels[i]);
    if (found == snapshot.me_dcs.end()) continue;
    const MeDcSnapshot& me = found->second;
    const std::string dc_label = std::string("dc=\"") + kMeLabels[i] + "\"";
    append_metric(out, "mtdd_me_connected", dc_label, me.connected ? 1 : 0);
    // ME sockets across every reactor's pool: the historical meaning of this
    // series (under `workers` it counted ME connections, not reactors). With N
    // reactors and `me_connections_per_dc` M this is N*M while the pool is full.
    append_metric(out, "mtdd_me_connections", dc_label, me.connections);
    // Reactors that currently hold a ready ME connection for this DC. This is a
    // topology gauge, not a connection count; it used to be published under
    // `mtdd_me_connections` between workers and melife.
    append_metric(out, "mtdd_me_ready_reactors", dc_label,
                  me.reactors_connected);
    // Deprecated alias of mtdd_me_connections, kept for dashboards written
    // against the intermediate pool-split naming.
    append_metric(out, "mtdd_me_pool_connections", dc_label, me.connections);
    append_metric(out, "mtdd_me_pool_ready", dc_label, me.ready_connections);
    append_metric(out, "mtdd_me_pool_target", dc_label, me.pool_target);
    append_metric(out, "mtdd_me_bound_clients", dc_label, me.bound_clients);
    append_metric(out, "mtdd_me_scale_up_total", dc_label, me.scale_up_total);
    append_metric(out, "mtdd_me_scale_down_total", dc_label, me.scale_down_total);
    append_metric(out, "mtdd_me_creation_failures_total", dc_label, me.creation_failures_total);
    if (me.pings_sent_total != 0) {
      append_metric(out, "mtdd_me_pings_total",
                    dc_label + ",result=\"sent\"", me.pings_sent_total);
    }
    if (me.pongs_received_total != 0) {
      append_metric(out, "mtdd_me_pings_total",
                    dc_label + ",result=\"pong\"", me.pongs_received_total);
    }
    if (me.ping_timeouts_total != 0) {
      append_metric(out, "mtdd_me_pings_total",
                    dc_label + ",result=\"timeout\"", me.ping_timeouts_total);
    }
    if (me.ping_stalls_total != 0) {
      append_metric(out, "mtdd_me_pings_total",
                    dc_label + ",result=\"stalled\"", me.ping_stalls_total);
    }
    if (me.pongs_received_total != 0) {
      append_metric(out, "mtdd_me_ping_rtt_us", dc_label, me.ping_rtt_us);
    }
    if (me.reconnects_total != 0) {
      append_metric(out, "mtdd_me_reconnects_total", dc_label,
                    me.reconnects_total);
    }
    const std::pair<const char*, uint64_t> requests[] = {
        {"success", me.requests_success},
        {"failure", me.requests_failure},
        {"timeout", me.requests_timeout},
    };
    for (const auto& [result, value] : requests) {
      if (value == 0) continue;
      append_metric(out, "mtdd_me_requests_total",
                    dc_label + ",result=\"" + result + "\"", value);
    }
    append_metric(out, "mtdd_me_ready_queue_depth", dc_label,
                  me.ready_queue_depth);
    append_metric(out, "mtdd_me_ready_queue_clients", dc_label,
                  me.ready_queue_clients);
    append_metric(out, "mtdd_me_frames_queued_bytes", dc_label,
                  me.frames_queued_bytes);
    append_metric(out, "mtdd_me_out_queued_bytes", dc_label,
                  me.out_queued_bytes);
    // Answer counters are the only delivery claim; queue gauges are not.
    const std::pair<const char*, uint64_t> answers[] = {
        {"received", me.proxy_ans_received_total},
        {"delivered", me.proxy_ans_delivered_total},
    };
    for (const auto& [result, value] : answers) {
      if (value == 0) continue;
      append_metric(out, "mtdd_me_proxy_ans_total",
                    dc_label + ",result=\"" + result + "\"", value);
    }
    const std::pair<const char*, uint64_t> dropped[] = {
        {"unknown_client", me.proxy_ans_dropped_unknown_total},
        {"other", me.proxy_ans_dropped_other_total},
    };
    for (const auto& [reason, value] : dropped) {
      if (value == 0) continue;
      append_metric(out, "mtdd_me_proxy_ans_dropped_total",
                    dc_label + ",reason=\"" + reason + "\"", value);
    }
    if (me.proxy_ans_seen) {
      append_metric(out, "mtdd_me_last_proxy_ans_age_seconds", dc_label,
                    me.last_proxy_ans_age_seconds);
    }
    // Inbound control constructors accumulated per DC. Counters: a replaced
    // connection folds its mirror into the DC base, so the series is monotone.
    const std::pair<const char*, uint64_t> control[] = {
        {"close_conn", me.control_close_conn},
        {"close_ext", me.control_close_ext},
        {"unknown", me.control_unknown},
        {"malformed", me.control_malformed},
    };
    for (const auto& [kind, value] : control) {
      if (value == 0) continue;
      append_metric(out, "mtdd_me_control_frames",
                    dc_label + ",type=\"" + kind + "\"", value);
    }
    if (me.rx_bytes_total != 0) {
      append_metric(out, "mtdd_me_rx_bytes_total", dc_label,
                    me.rx_bytes_total);
    }
    if (me.tx_bytes_total != 0) {
      append_metric(out, "mtdd_me_tx_bytes_total", dc_label,
                    me.tx_bytes_total);
    }
    append_metric(out, "mtdd_direct_active", dc_label, me.direct_active);
    if (me.direct_accepted_total != 0) {
      append_metric(out, "mtdd_direct_accepted_total", dc_label,
                    me.direct_accepted_total);
    }
    if (me.direct_connect_fail_total != 0) {
      append_metric(out, "mtdd_direct_connect_fail_total", dc_label,
                    me.direct_connect_fail_total);
    }
    if (me.direct_rx_bytes_total != 0) {
      append_metric(out, "mtdd_direct_rx_bytes_total", dc_label,
                    me.direct_rx_bytes_total);
    }
    if (me.direct_tx_bytes_total != 0) {
      append_metric(out, "mtdd_direct_tx_bytes_total", dc_label,
                    me.direct_tx_bytes_total);
    }
    if (me.direct_budget_pauses_total != 0) {
      append_metric(out, "mtdd_direct_budget_pauses_total", dc_label,
                    me.direct_budget_pauses_total);
    }
  }
  // Per-worker diagnostics. These are not alternatives to the summed gauges:
  // the aggregate can hide one reactor at its local budget limit. Worker and DC
  // labels are fixed; no addresses, client ids or payloads are exposed.
  for (size_t w = 0; w < snapshot.workers.size(); ++w) {
    const WorkerSnapshot& worker = snapshot.workers[w];
    const std::string label = worker_label(w);
    append_metric(out, "mtdd_worker_budget_used_bytes", label,
                  worker.budget_used_bytes);
    append_metric(out, "mtdd_worker_budget_limit_bytes", label,
                  worker.budget_limit_bytes);
    append_metric(out, "mtdd_worker_active_clients", label,
                  worker.active_clients);
    append_metric(out, "mtdd_worker_handshakes_pending", label,
                  worker.handshakes_pending);
    if (worker.heartbeat_seen) {
      append_metric(out, "mtdd_worker_heartbeat_age_ms", label,
                    worker.heartbeat_age_ms);
    }
    append_metric(out, "mtdd_worker_housekeeping_lateness_ms", label,
                  worker.housekeeping_lateness_ms);
    append_metric(out, "mtdd_worker_housekeeping_lateness_max_ms", label,
                  worker.housekeeping_lateness_max_ms);
    for (size_t i = 0; i < kMeSlotCount; ++i) {
      const auto found = worker.me_dcs.find(kMeLabels[i]);
      if (found == worker.me_dcs.end()) continue;
      const MeWorkerSnapshot& me = found->second;
      const std::string me_label =
          label + ",dc=\"" + kMeLabels[i] + "\"";
      append_metric(out, "mtdd_worker_me_connections", me_label,
                    me.connections);
      append_metric(out, "mtdd_worker_me_ready", me_label,
                    me.ready_connections);
      // Actual epoll read interest of this reactor's ME sockets, not a
      // derived expectation: a paused read is absent from the mask.
      append_metric(out, "mtdd_worker_me_read_armed", me_label,
                    me.read_armed_connections);
      append_metric(out, "mtdd_worker_me_budget_paused", me_label,
                    me.budget_paused_connections);
      append_metric(out, "mtdd_worker_me_paused_bound_clients", me_label,
                    me.bound_clients_on_paused);
      append_metric(out, "mtdd_worker_me_budget_pauses_total", me_label,
                    me.budget_pauses_total);
      append_metric(out, "mtdd_worker_me_budget_resumes_total", me_label,
                    me.budget_resumes_total);
      append_metric(out, "mtdd_worker_me_pause_current_ms", me_label,
                    me.current_pause_age_ms);
      append_metric(out, "mtdd_worker_me_pause_max_ms", me_label,
                    me.max_pause_age_ms);
      append_metric(out, "mtdd_worker_me_worst_writer_rtt_us", me_label,
                    me.worst_writer_rtt_us);
      append_metric(out, "mtdd_worker_me_slow_writers", me_label,
                    me.slow_writers);
      append_metric(out, "mtdd_worker_me_slow_evictions_total", me_label,
                    me.slow_evictions_total);
    }
  }
  append_metric(out, "mtdd_me_pending_buffer_bytes", "",
                snapshot.me_pending_buffer_bytes);
  append_metric(out, "mtdd_buffer_budget_bytes", "",
                snapshot.buffer_budget_used);
  append_metric(out, "mtdd_handshakes_pending", "",
                snapshot.handshakes_pending);
  append_metric(out, "mtdd_client_pool_objects", "",
                snapshot.client_pool_objects);
  append_metric(out, "mtdd_client_allocations_total", "",
                snapshot.client_allocations_total);
  append_metric(out, "mtdd_client_reuses_total", "",
                snapshot.client_reuses_total);
  return out.str();
}

}  // namespace mtdd::control

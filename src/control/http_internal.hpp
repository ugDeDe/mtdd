// Internal helpers for the control HTTP server (not part of the public API).
#pragma once

#include <mtdd/control.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <initializer_list>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

struct evhttp_request;

namespace mtdd::control::detail {

using SteadyClock = std::chrono::steady_clock;
using json = nlohmann::json;

struct HttpError {
  int status{500};
  std::string type{"io_error"};
  std::string message{"internal error"};
};

struct RouteInfo {
  ApiRoute route{ApiRoute::unknown};
  std::string name;
};

struct BodyRead {
  json value;
  std::optional<HttpError> error;
};

class TokenBucket {
 public:
  TokenBucket() = default;
  TokenBucket(double rate, double burst) { configure(rate, burst); }

  void configure(double rate, double burst);
  bool allow(SteadyClock::time_point now);

 private:
  void refill(SteadyClock::time_point now);

  double rate_{0.0};
  double burst_{0.0};
  double tokens_{0.0};
  SteadyClock::time_point last_{};
  bool initialized_{false};
};

// Fixed-capacity, least-recently-used-evicted per-source limiter. The table is
// bounded, so a flood of distinct source addresses cannot grow memory.
class SourceRateLimiter {
 public:
  SourceRateLimiter(size_t capacity, double rate, double burst);

  bool allow(uint64_t key, SteadyClock::time_point now);

 private:
  struct Entry {
    uint64_t key{0};
    double tokens{0.0};
    SteadyClock::time_point last{};
    bool used{false};
  };

  std::vector<Entry> entries_;
  size_t capacity_;
  double rate_;
  double burst_;
};

// Stable hash of the source address only (never the port), used as the bounded
// limiter key. Falls back to the textual peer if no sockaddr is available.
uint64_t peer_key(evhttp_request* request);

// IPv4-mapped IPv6 network; IPv4 prefixes are stored offset by 96 bits.
struct IpNetwork {
  std::array<uint8_t, 16> address{};
  uint8_t prefix{128};
};

// "a.b.c.d[/n]" or "x::y[/n]"; a bare address is a single host.
std::optional<IpNetwork> parse_ip_network(std::string_view text);
// Empty allowlist admits everyone; unknown peer families are refused.
bool source_allowed(const std::vector<IpNetwork>& allow,
                    evhttp_request* request);

std::string trim_copy(std::string_view value);
bool ascii_iequals(std::string_view a, std::string_view b);
bool constant_time_equal(std::string_view a, std::string_view b) noexcept;

ApiMethod parse_method(evhttp_request* request);
RouteInfo classify_route(evhttp_request* request);
bool method_allowed(ApiRoute route, ApiMethod method);

std::optional<HttpError> check_allowed_fields(
    const json& object, std::initializer_list<std::string_view> allowed);
std::optional<HttpError> parse_max_connections(const json& value,
                                               std::optional<uint32_t>& out);
std::optional<HttpError> parse_if_match(evhttp_request* request,
                                        std::optional<uint64_t>& out);
HttpError map_store_error(const Error& error);

inline constexpr std::initializer_list<std::string_view> kPolicyFields = {
    "expires_at", "data_quota_bytes", "max_unique_ips",
    "rate_limit_up_bytes_per_sec", "rate_limit_down_bytes_per_sec", "note"};

// RFC 3339 with Z or a numeric offset; fractional seconds are truncated.
std::optional<int64_t> parse_rfc3339(std::string_view text);
std::string format_rfc3339(int64_t unix_seconds);
// Type checks only; ranges are validated by UserStore::validate_policy.
std::optional<HttpError> parse_policy_patch(const json& body, UserPolicyPatch& out);
UserPolicy apply_policy_patch(const UserPolicyPatch& patch);
json policy_json(const UserPolicy& policy);

json user_json(const UserRecord& user, const StatisticsSnapshot& stats);

// Query string as key -> value. Unknown keys, duplicates and malformed
// percent-encoding are a 400 so typos never silently change a listing.
using Query = std::vector<std::pair<std::string, std::string>>;
std::optional<HttpError> parse_query(evhttp_request* request,
                                     std::initializer_list<std::string_view> allowed,
                                     Query& out);
const std::string* query_value(const Query& query, std::string_view key);
std::optional<HttpError> query_uint(const Query& query, std::string_view key,
                                    uint64_t min, uint64_t max, uint64_t& out);

// Request id of the request being handled on this thread (0 = none). Every
// JSON response carries it as "request_id" next to "ok"; X-Request-Id too.
void set_request_id(uint64_t id) noexcept;
uint64_t current_request_id() noexcept;
uint64_t next_request_id() noexcept;

// Reads and strictly validates an optional JSON object body with a bounded size.
BodyRead read_body(evhttp_request* request, size_t max_body_bytes,
                   bool allow_empty);

void send_json(evhttp_request* request, int status, const json& body,
               std::optional<uint64_t> revision = std::nullopt);
void send_text(evhttp_request* request, int status, const std::string& body,
               std::string_view content_type,
               std::optional<uint64_t> revision = std::nullopt);
void send_error(evhttp_request* request, int status, std::string type,
                std::string message,
                std::optional<uint64_t> revision = std::nullopt);
void send_store_error(evhttp_request* request, const Error& error,
                      std::optional<uint64_t> revision = std::nullopt);

}  // namespace mtdd::control::detail

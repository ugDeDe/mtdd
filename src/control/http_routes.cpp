#include "http_internal.hpp"

#include <cstdio>

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <string>
#include <utility>

namespace mtdd::control::detail {

std::string trim_copy(std::string_view value) {
  size_t begin = 0;
  size_t end = value.size();
  while (begin < end &&
         (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' ||
          value[begin] == '\n')) {
    ++begin;
  }
  while (end > begin &&
         (value[end - 1] == ' ' || value[end - 1] == '\t' ||
          value[end - 1] == '\r' || value[end - 1] == '\n')) {
    --end;
  }
  return std::string(value.substr(begin, end - begin));
}

bool ascii_iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

bool constant_time_equal(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

ApiMethod parse_method(evhttp_request* request) {
  switch (evhttp_request_get_command(request)) {
    case EVHTTP_REQ_GET: return ApiMethod::get;
    case EVHTTP_REQ_POST: return ApiMethod::post;
    case EVHTTP_REQ_PATCH: return ApiMethod::patch;
    case EVHTTP_REQ_DELETE: return ApiMethod::delete_;
    default: return ApiMethod::other;
  }
}

RouteInfo classify_route(evhttp_request* request) {
  RouteInfo info;
  const char* uri = evhttp_request_get_uri(request);
  if (uri == nullptr || std::strlen(uri) > 2048) return info;
  evhttp_uri* parsed = evhttp_uri_parse(uri);
  if (parsed == nullptr) return info;
  const char* raw_path = evhttp_uri_get_path(parsed);
  const std::string path = raw_path != nullptr ? raw_path : "";
  evhttp_uri_free(parsed);
  if (path.empty()) return info;

  if (path == "/v1/health") {
    info.route = ApiRoute::health;
    return info;
  }
  if (path == "/v1/ready") {
    info.route = ApiRoute::ready;
    return info;
  }
  if (path == "/v1/status") {
    info.route = ApiRoute::status;
    return info;
  }
  if (path == "/v1/users") {
    info.route = ApiRoute::users;
    return info;
  }
  if (path == "/metrics") {
    info.route = ApiRoute::metrics;
    return info;
  }
  static constexpr std::pair<std::string_view, ApiRoute> kFixed[] = {
      {"/v1/system/info", ApiRoute::system_info},
      {"/v1/config", ApiRoute::config},
      {"/v1/stats/summary", ApiRoute::stats_summary},
      {"/v1/stats/me", ApiRoute::stats_me},
      {"/v1/stats/users", ApiRoute::stats_users},
      {"/v1/events", ApiRoute::events}};
  for (const auto& [fixed, route] : kFixed) {
    if (path == fixed) {
      info.route = route;
      return info;
    }
  }

  // /v1/users/{name}[/action]; names never contain '/'.
  constexpr std::string_view kUsersPrefix = "/v1/users/";
  if (path.rfind(kUsersPrefix, 0) != 0) return info;
  std::string rest = path.substr(kUsersPrefix.size());
  const size_t slash = rest.find('/');
  std::string action;
  if (slash != std::string::npos) {
    action = rest.substr(slash + 1);
    rest.resize(slash);
  }
  if (rest.empty()) return info;
  static constexpr std::pair<std::string_view, ApiRoute> kActions[] = {
      {"", ApiRoute::user},
      {"links", ApiRoute::user_links},
      {"rotate-secret", ApiRoute::rotate_secret},
      {"enable", ApiRoute::user_enable},
      {"disable", ApiRoute::user_disable},
      {"reset-quota", ApiRoute::user_reset_quota}};
  for (const auto& [suffix, route] : kActions) {
    if (action == suffix && (slash == std::string::npos) == suffix.empty()) {
      info.route = route;
      info.name = std::move(rest);
      return info;
    }
  }
  return info;
}

bool method_allowed(ApiRoute route, ApiMethod method) {
  switch (route) {
    case ApiRoute::health:
    case ApiRoute::ready:
    case ApiRoute::status:
    case ApiRoute::metrics:
    case ApiRoute::user_links:
    case ApiRoute::system_info:
    case ApiRoute::config:
    case ApiRoute::stats_summary:
    case ApiRoute::stats_me:
    case ApiRoute::stats_users:
    case ApiRoute::events:
      return method == ApiMethod::get;
    case ApiRoute::users:
      return method == ApiMethod::get || method == ApiMethod::post;
    case ApiRoute::user:
      return method == ApiMethod::get || method == ApiMethod::patch ||
             method == ApiMethod::delete_;
    case ApiRoute::rotate_secret:
    case ApiRoute::user_enable:
    case ApiRoute::user_disable:
    case ApiRoute::user_reset_quota:
      return method == ApiMethod::post;
    case ApiRoute::unknown:
      return false;
  }
  return false;
}

std::optional<HttpError> check_allowed_fields(
    const json& object, std::initializer_list<std::string_view> allowed) {
  for (auto it = object.begin(); it != object.end(); ++it) {
    bool known = false;
    for (auto field : allowed) {
      if (it.key() == field) {
        known = true;
        break;
      }
    }
    if (!known) {
      return HttpError{400, "unknown_field", "unknown field '" + it.key() + "'"};
    }
  }
  return std::nullopt;
}

std::optional<HttpError> parse_max_connections(const json& value,
                                               std::optional<uint32_t>& out) {
  if (value.is_null()) {
    out = std::nullopt;
    return std::nullopt;
  }
  if (!value.is_number_unsigned()) {
    return HttpError{400, "invalid_field",
                     "max_connections must be null or an integer within 1.." +
                         std::to_string(kMaxConnectionsLimit)};
  }
  const uint64_t number = value.get<uint64_t>();
  if (number == 0 || number > kMaxConnectionsLimit) {
    return HttpError{400, "invalid_field",
                     "max_connections must be null or an integer within 1.." +
                         std::to_string(kMaxConnectionsLimit)};
  }
  out = static_cast<uint32_t>(number);
  return std::nullopt;
}

std::optional<HttpError> parse_if_match(evhttp_request* request,
                                        std::optional<uint64_t>& out) {
  const char* raw = evhttp_find_header(evhttp_request_get_input_headers(request),
                                       "If-Match");
  if (raw == nullptr) return std::nullopt;
  std::string value = trim_copy(raw);
  if (value.find(',') != std::string::npos) {
    return HttpError{400, "invalid_field",
                     "If-Match accepts exactly one ETag"};
  }
  if (value == "*") {
    out = std::nullopt;  // matches any existing revision
    return std::nullopt;
  }
  bool quoted = false;
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
    value = value.substr(1, value.size() - 2);
    quoted = true;
  } else if (value.find('"') != std::string::npos) {
    return HttpError{400, "invalid_field",
                     "If-Match must be a strong ETag such as \"7\""};
  }
  if (value.empty() ||
      value.find_first_not_of("0123456789") != std::string::npos) {
    if (quoted) {
      // A quoted tag that is not a numeric revision is a stale/unknown ETag:
      // report the documented concurrency conflict rather than a syntax error.
      return HttpError{412, "revision_conflict",
                       "If-Match ETag does not match the current revision"};
    }
    return HttpError{400, "invalid_field",
                     "If-Match must be a strong ETag such as \"7\""};
  }
  try {
    out = std::stoull(value);
  } catch (...) {
    return HttpError{400, "invalid_field", "If-Match revision is out of range"};
  }
  return std::nullopt;
}

HttpError map_store_error(const Error& error) {
  int status = 500;
  switch (error.code) {
    case ErrorCode::invalid_name:
    case ErrorCode::invalid_secret:
    case ErrorCode::invalid_field:
    case ErrorCode::unknown_field:
    case ErrorCode::invalid_json:
    case ErrorCode::invalid_request:
    case ErrorCode::limit_exceeded:
    case ErrorCode::file_too_large:
      status = 400;
      break;
    case ErrorCode::duplicate_name:
    case ErrorCode::duplicate_secret:
      status = 409;
      break;
    case ErrorCode::not_found:
      status = 404;
      break;
    case ErrorCode::revision_conflict:
      status = 412;
      break;
    case ErrorCode::invalid_file:
    case ErrorCode::unsupported_version:
    case ErrorCode::permission_denied:
    case ErrorCode::symlink_rejected:
    case ErrorCode::io_error:
    case ErrorCode::bind_failed:
    case ErrorCode::invalid_config:
      status = 500;
      break;
  }
  return HttpError{status, to_string(error.code), error.message};
}

namespace {

// Howard Hinnant's days_from_civil: proleptic Gregorian date to Unix days.
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2 ? 1 : 0;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const auto yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

bool digits(std::string_view text, size_t at, size_t count, unsigned& out) {
  if (at + count > text.size()) return false;
  out = 0;
  for (size_t i = at; i < at + count; ++i) {
    if (text[i] < '0' || text[i] > '9') return false;
    out = out * 10 + static_cast<unsigned>(text[i] - '0');
  }
  return true;
}

std::optional<HttpError> parse_nullable_u64(const json& body, const char* key,
                                            uint64_t limit,
                                            Patch<uint64_t>& out) {
  if (!body.contains(key)) return std::nullopt;
  const json& value = body[key];
  if (value.is_null()) {
    out = std::optional<uint64_t>{};
    return std::nullopt;
  }
  if (!value.is_number_unsigned() || value.get<uint64_t>() > limit) {
    return HttpError{400, "invalid_field",
                     std::string(key) + " must be null or an unsigned integer"};
  }
  out = std::optional<uint64_t>(value.get<uint64_t>());
  return std::nullopt;
}

}  // namespace

std::optional<int64_t> parse_rfc3339(std::string_view text) {
  // YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM); fraction is dropped.
  unsigned year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  if (text.size() < 20 || text.size() > 40 || !digits(text, 0, 4, year) ||
      text[4] != '-' || !digits(text, 5, 2, month) || text[7] != '-' ||
      !digits(text, 8, 2, day) || (text[10] != 'T' && text[10] != 't') ||
      !digits(text, 11, 2, hour) || text[13] != ':' ||
      !digits(text, 14, 2, minute) || text[16] != ':' ||
      !digits(text, 17, 2, second)) {
    return std::nullopt;
  }
  size_t at = 19;
  if (text[at] == '.') {
    ++at;
    const size_t start = at;
    while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at;
    if (at == start) return std::nullopt;
  }
  int64_t offset = 0;
  if (at < text.size() && (text[at] == 'Z' || text[at] == 'z')) {
    ++at;
  } else if (at < text.size() && (text[at] == '+' || text[at] == '-')) {
    unsigned oh = 0, om = 0;
    if (!digits(text, at + 1, 2, oh) || at + 3 >= text.size() ||
        text[at + 3] != ':' || !digits(text, at + 4, 2, om) || oh > 23 || om > 59) {
      return std::nullopt;
    }
    offset = (text[at] == '+' ? 1 : -1) * static_cast<int64_t>(oh * 3600 + om * 60);
    at += 6;
  } else {
    return std::nullopt;
  }
  if (at != text.size()) return std::nullopt;
  static constexpr unsigned kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  if (month < 1 || month > 12 || day < 1 ||
      day > kDays[month - 1] + ((month == 2 && leap) ? 1u : 0u) || hour > 23 ||
      minute > 59 || second > 59) {
    return std::nullopt;
  }
  return days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 +
         second - offset;
}

std::string format_rfc3339(int64_t unix_seconds) {
  const int64_t days = unix_seconds >= 0 ? unix_seconds / 86400
                                         : (unix_seconds - 86399) / 86400;
  const int64_t rest = unix_seconds - days * 86400;
  // Inverse of days_from_civil (civil_from_days).
  const int64_t z = days + 719468;
  const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const auto doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  const unsigned d = doy - (153 * mp + 2) / 5 + 1;
  const unsigned m = mp < 10 ? mp + 3 : mp - 9;
  const int64_t y = static_cast<int64_t>(yoe) + era * 400 + (m <= 2 ? 1 : 0);
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ",
                static_cast<long long>(y), m, d, static_cast<long long>(rest / 3600),
                static_cast<long long>(rest / 60 % 60), static_cast<long long>(rest % 60));
  return buffer;
}

std::optional<HttpError> parse_policy_patch(const json& body, UserPolicyPatch& out) {
  if (body.contains("expires_at")) {
    const json& value = body["expires_at"];
    if (value.is_null()) {
      out.expires_at = std::optional<int64_t>{};
    } else {
      const auto parsed =
          value.is_string() ? parse_rfc3339(value.get<std::string>()) : std::nullopt;
      if (!parsed) {
        return HttpError{400, "invalid_field",
                         "expires_at must be null or an RFC 3339 timestamp, "
                         "e.g. 2030-01-01T00:00:00Z"};
      }
      out.expires_at = std::optional<int64_t>(*parsed);
    }
  }
  Patch<uint64_t> unique_ips;
  if (auto error = parse_nullable_u64(body, "max_unique_ips", kMaxUniqueIpsLimit,
                                      unique_ips)) {
    return error;
  }
  if (unique_ips) {
    out.max_unique_ips = *unique_ips ? std::optional<uint32_t>(static_cast<uint32_t>(**unique_ips))
                                     : std::optional<uint32_t>{};
  }
  for (const auto& [key, target] :
       {std::pair{"data_quota_bytes", &out.data_quota_bytes},
        std::pair{"rate_limit_up_bytes_per_sec", &out.rate_limit_up_bytes_per_sec},
        std::pair{"rate_limit_down_bytes_per_sec", &out.rate_limit_down_bytes_per_sec}}) {
    if (auto error = parse_nullable_u64(body, key, UINT64_MAX, *target)) return error;
  }
  if (body.contains("note")) {
    if (!body["note"].is_string()) {
      return HttpError{400, "invalid_field", "note must be a string"};
    }
    out.note = body["note"].get<std::string>();
  }
  return std::nullopt;
}

UserPolicy apply_policy_patch(const UserPolicyPatch& patch) {
  UserPolicy policy;
  if (patch.expires_at) policy.expires_at = *patch.expires_at;
  if (patch.data_quota_bytes) policy.data_quota_bytes = *patch.data_quota_bytes;
  if (patch.max_unique_ips) policy.max_unique_ips = *patch.max_unique_ips;
  if (patch.rate_limit_up_bytes_per_sec) {
    policy.rate_limit_up_bytes_per_sec = *patch.rate_limit_up_bytes_per_sec;
  }
  if (patch.rate_limit_down_bytes_per_sec) {
    policy.rate_limit_down_bytes_per_sec = *patch.rate_limit_down_bytes_per_sec;
  }
  if (patch.note) policy.note = *patch.note;
  return policy;
}

json policy_json(const UserPolicy& policy) {
  const auto nullable = [](const auto& value) {
    return value ? json(*value) : json(nullptr);
  };
  json out;
  out["expires_at"] =
      policy.expires_at ? json(format_rfc3339(*policy.expires_at)) : json(nullptr);
  out["data_quota_bytes"] = nullable(policy.data_quota_bytes);
  out["max_unique_ips"] = nullable(policy.max_unique_ips);
  out["rate_limit_up_bytes_per_sec"] = nullable(policy.rate_limit_up_bytes_per_sec);
  out["rate_limit_down_bytes_per_sec"] = nullable(policy.rate_limit_down_bytes_per_sec);
  out["note"] = policy.note;
  return out;
}

json user_json(const UserRecord& user, const StatisticsSnapshot& stats) {
  json entry;
  entry["name"] = user.name;
  entry["enabled"] = user.enabled;
  if (user.max_connections) {
    entry["max_connections"] = *user.max_connections;
  } else {
    entry["max_connections"] = nullptr;
  }
  entry["generation"] = user.generation;
  entry.update(policy_json(user.policy));
  UserMetricsSnapshot metrics;
  const auto found = stats.users.find(user.name);
  if (found != stats.users.end()) metrics = found->second;
  entry["stats"] = {{"active_connections", metrics.active_connections},
                    {"unique_ips_active", metrics.unique_ips_qualified},
                    {"unique_ips_seen", metrics.unique_ips_active},
                    {"payload_bytes_c2s", metrics.payload_c2s_bytes},
                    {"payload_bytes_s2c", metrics.payload_s2c_bytes},
                    {"quota_used_bytes", metrics.quota_used_bytes}};
  if (metrics.quota_reset_at > 0) {
    entry["stats"]["quota_reset_at"] = format_rfc3339(metrics.quota_reset_at);
  } else {
    entry["stats"]["quota_reset_at"] = nullptr;
  }
  return entry;
}

BodyRead read_body(evhttp_request* request, size_t max_body_bytes,
                   bool allow_empty) {
  BodyRead result;
  const char* content_length =
      evhttp_find_header(evhttp_request_get_input_headers(request),
                         "Content-Length");
  if (content_length != nullptr) {
    try {
      const unsigned long long declared = std::stoull(content_length);
      if (declared > max_body_bytes) {
        result.error = HttpError{413, "body_too_large",
                                 "request body exceeds max_body_bytes"};
        return result;
      }
    } catch (...) {
      result.error =
          HttpError{400, "invalid_field", "invalid Content-Length header"};
      return result;
    }
  }
  evbuffer* input = evhttp_request_get_input_buffer(request);
  const size_t length = evbuffer_get_length(input);
  if (length == 0) {
    if (allow_empty) {
      result.value = json::object();
      return result;
    }
    result.error = HttpError{400, "invalid_request", "request body required"};
    return result;
  }
  if (length > max_body_bytes) {
    result.error = HttpError{413, "body_too_large",
                             "request body exceeds max_body_bytes"};
    return result;
  }
  const unsigned char* data = evbuffer_pullup(input, -1);
  if (data == nullptr) {
    result.error = HttpError{400, "invalid_request", "could not read body"};
    return result;
  }
  const std::string text(reinterpret_cast<const char*>(data), length);
  json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded()) {
    result.error = HttpError{400, "invalid_json", "body is not valid JSON"};
    return result;
  }
  if (!parsed.is_object()) {
    result.error = HttpError{400, "invalid_request", "body must be a JSON object"};
    return result;
  }
  result.value = std::move(parsed);
  return result;
}

namespace {
thread_local uint64_t t_request_id = 0;
std::atomic<uint64_t> g_request_ids{0};
}  // namespace

void set_request_id(uint64_t id) noexcept { t_request_id = id; }
uint64_t current_request_id() noexcept { return t_request_id; }
uint64_t next_request_id() noexcept {
  return g_request_ids.fetch_add(1, std::memory_order_relaxed) + 1;
}

std::optional<HttpError> parse_query(evhttp_request* request,
                                     std::initializer_list<std::string_view> allowed,
                                     Query& out) {
  out.clear();
  const evhttp_uri* uri = evhttp_request_get_evhttp_uri(request);
  const char* raw = uri != nullptr ? evhttp_uri_get_query(uri) : nullptr;
  if (raw == nullptr || *raw == '\0') return std::nullopt;
  evkeyvalq pairs;
  pairs.tqh_first = nullptr;
  pairs.tqh_last = &pairs.tqh_first;
  if (evhttp_parse_query_str(raw, &pairs) != 0) {
    evhttp_clear_headers(&pairs);
    return HttpError{400, "invalid_query", "malformed query string"};
  }
  std::optional<HttpError> error;
  for (evkeyval* pair = pairs.tqh_first; pair != nullptr && !error;
       pair = pair->next.tqe_next) {
    const std::string_view key = pair->key;
    if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
      error = HttpError{400, "invalid_query",
                        "unknown query parameter '" + std::string(key) + "'"};
    } else if (query_value(out, key) != nullptr) {
      error = HttpError{400, "invalid_query",
                        "duplicate query parameter '" + std::string(key) + "'"};
    } else {
      out.emplace_back(pair->key, pair->value);
    }
  }
  evhttp_clear_headers(&pairs);
  return error;
}

const std::string* query_value(const Query& query, std::string_view key) {
  for (const auto& [name, value] : query) {
    if (name == key) return &value;
  }
  return nullptr;
}

std::optional<HttpError> query_uint(const Query& query, std::string_view key,
                                    uint64_t min, uint64_t max, uint64_t& out) {
  const std::string* text = query_value(query, key);
  if (text == nullptr) return std::nullopt;
  uint64_t value = 0;
  bool ok = !text->empty() && text->size() <= 19;
  for (char c : *text) {
    if (c < '0' || c > '9') {
      ok = false;
      break;
    }
    value = value * 10 + static_cast<uint64_t>(c - '0');
  }
  if (!ok || value < min || value > max) {
    return HttpError{400, "invalid_query",
                     std::string(key) + " must be an integer within " +
                         std::to_string(min) + ".." + std::to_string(max)};
  }
  out = value;
  return std::nullopt;
}

void send_json(evhttp_request* request, int status, const json& body,
               std::optional<uint64_t> revision) {
  // Query keys and values are echoed in errors and may be invalid UTF-8.
  std::string text = body.dump(-1, ' ', false, json::error_handler_t::replace);
  // Envelope: {"ok":bool,"request_id":N, ...body}. Spliced into the dumped text
  // so large listings are not copied once more.
  if (body.is_object()) {
    std::string prefix = std::string("{\"ok\":") + (status < 400 ? "true" : "false");
    if (t_request_id != 0) prefix += ",\"request_id\":" + std::to_string(t_request_id);
    text = prefix + (text.size() > 2 ? "," : "") + text.substr(1);
  }
  evbuffer* buffer = evbuffer_new();
  if (buffer == nullptr) {
    evhttp_send_reply(request, 500, nullptr, nullptr);
    return;
  }
  evbuffer_add(buffer, text.data(), text.size());
  evkeyvalq* headers = evhttp_request_get_output_headers(request);
  evhttp_add_header(headers, "Content-Type", "application/json");
  evhttp_add_header(headers, "Cache-Control", "no-store");
  evhttp_add_header(headers, "X-Content-Type-Options", "nosniff");
  if (t_request_id != 0) {
    evhttp_add_header(headers, "X-Request-Id", std::to_string(t_request_id).c_str());
  }
  if (revision) {
    const std::string etag = "\"" + std::to_string(*revision) + "\"";
    evhttp_add_header(headers, "ETag", etag.c_str());
  }
  evhttp_send_reply(request, status, nullptr, buffer);
  evbuffer_free(buffer);
}

void send_text(evhttp_request* request, int status, const std::string& body,
               std::string_view content_type,
               std::optional<uint64_t> revision) {
  evbuffer* buffer = evbuffer_new();
  if (buffer == nullptr) {
    evhttp_send_reply(request, 500, nullptr, nullptr);
    return;
  }
  evbuffer_add(buffer, body.data(), body.size());
  evkeyvalq* headers = evhttp_request_get_output_headers(request);
  const std::string type(content_type);
  evhttp_add_header(headers, "Content-Type", type.c_str());
  evhttp_add_header(headers, "Cache-Control", "no-store");
  if (t_request_id != 0) {
    evhttp_add_header(headers, "X-Request-Id", std::to_string(t_request_id).c_str());
  }
  if (revision) {
    const std::string etag = "\"" + std::to_string(*revision) + "\"";
    evhttp_add_header(headers, "ETag", etag.c_str());
  }
  evhttp_send_reply(request, status, nullptr, buffer);
  evbuffer_free(buffer);
}

void send_error(evhttp_request* request, int status, std::string type,
                std::string message, std::optional<uint64_t> revision) {
  json body;
  body["error"] = {{"code", status},
                   {"type", std::move(type)},
                   {"message", std::move(message)}};
  send_json(request, status, body, revision);
}

void send_store_error(evhttp_request* request, const Error& error,
                      std::optional<uint64_t> revision) {
  const HttpError mapped = map_store_error(error);
  const std::string message =
      error.uncertain
          ? "durability outcome uncertain after rename; in-memory state was not "
            "published: " + mapped.message
          : mapped.message;
  send_error(request, mapped.status, mapped.type, message, revision);
}

}  // namespace mtdd::control::detail

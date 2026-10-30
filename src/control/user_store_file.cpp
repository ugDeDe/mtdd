#include "store_internal.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <string>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace mtdd::control::detail {

using json = nlohmann::json;

namespace {
// Test-only, detail-namespace seam. Tests install it single-threaded before
// creating worker threads and clear it after joining them; production code
// never sets it, so this is a null check on the normal path.
PersistGateHook g_persist_gate_hook = nullptr;
void* g_persist_gate_context = nullptr;
}  // namespace

void set_persist_gate_hook(PersistGateHook hook, void* context) noexcept {
  g_persist_gate_hook = hook;
  g_persist_gate_context = context;
}

std::string lower_ascii(std::string value) {
  for (char& c : value) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return value;
}

bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

std::string hex_encode(const unsigned char* data, size_t size) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out[2 * i] = kHex[data[i] >> 4];
    out[2 * i + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

Error errno_error(int err, std::string_view what) {
  Error e;
  if (err == EACCES || err == EPERM) {
    e.code = ErrorCode::permission_denied;
  } else if (err == ELOOP) {
    e.code = ErrorCode::symlink_rejected;
  } else {
    e.code = ErrorCode::io_error;
  }
  e.message = std::string(what) + ": " + std::strerror(err);
  return e;
}

std::string parent_dir(const std::string& path) {
  const auto pos = path.find_last_of('/');
  if (pos == std::string::npos) return ".";
  if (pos == 0) return "/";
  return path.substr(0, pos);
}

std::string base_name(const std::string& path) {
  const auto pos = path.find_last_of('/');
  return pos == std::string::npos ? path : path.substr(pos + 1);
}

// Creates missing path components with the configured owner-only mode.
// Rejects symlinked or non-directory components.
std::optional<Error> ensure_directory(const std::string& dir, uint32_t mode,
                                      bool create) {
  if (dir.empty()) return std::nullopt;
  std::string current;
  size_t i = 0;
  if (dir.front() == '/') {
    current = "/";
    i = 1;
  }
  while (i <= dir.size()) {
    const size_t next = dir.find('/', i);
    const std::string component =
        dir.substr(i, next == std::string::npos ? std::string::npos : next - i);
    if (!component.empty()) {
      if (!current.empty() && current.back() != '/') current += '/';
      current += component;
      struct stat st {};
      if (::lstat(current.c_str(), &st) != 0) {
        if (errno != ENOENT) return errno_error(errno, "stat directory");
        if (!create) {
          return Error{ErrorCode::io_error,
                       "directory does not exist: " + current};
        }
        if (::mkdir(current.c_str(), static_cast<mode_t>(mode)) != 0) {
          return errno_error(errno, "mkdir " + current);
        }
        // mkdir applies umask; enforce the documented mode explicitly.
        if (::chmod(current.c_str(), static_cast<mode_t>(mode)) != 0) {
          return errno_error(errno, "chmod " + current);
        }
      } else {
        if (S_ISLNK(st.st_mode)) {
          return Error{ErrorCode::symlink_rejected,
                       "directory component is a symlink: " + current};
        }
        if (!S_ISDIR(st.st_mode)) {
          return Error{ErrorCode::invalid_file,
                       "path component is not a directory: " + current};
        }
      }
    }
    if (next == std::string::npos) break;
    i = next + 1;
  }
  return std::nullopt;
}

std::optional<Error> check_allowed_store_fields(
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
      return Error{ErrorCode::unknown_field, "unknown field '" + it.key() + "'"};
    }
  }
  return std::nullopt;
}

std::optional<uint64_t> as_u64(const json& value) {
  if (!value.is_number_unsigned()) return std::nullopt;
  return value.get<uint64_t>();
}

std::optional<uint32_t> as_max_connections(const json& value) {
  if (value.is_null()) return std::nullopt;
  auto number = as_u64(value);
  if (!number || *number == 0 || *number > kMaxConnectionsLimit) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(*number);
}

// Reads an optional unsigned (or, for expires_at, non-negative) integer.
template <typename T>
std::optional<Error> optional_number(const json& j, const char* key,
                                     std::optional<T>& out) {
  if (!j.contains(key) || j[key].is_null()) return std::nullopt;
  const auto value = as_u64(j[key]);
  if (!value || *value > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
    return Error{ErrorCode::invalid_field,
                 std::string("user.") + key + " must be null or an unsigned integer"};
  }
  out = static_cast<T>(*value);
  return std::nullopt;
}

std::optional<Error> validate_policy_json(const json& j, UserPolicy& out) {
  if (auto error = optional_number(j, "expires_at", out.expires_at)) return error;
  if (auto error = optional_number(j, "data_quota_bytes", out.data_quota_bytes)) {
    return error;
  }
  if (auto error = optional_number(j, "max_unique_ips", out.max_unique_ips)) {
    return error;
  }
  if (auto error = optional_number(j, "rate_limit_up_bytes_per_sec",
                                   out.rate_limit_up_bytes_per_sec)) {
    return error;
  }
  if (auto error = optional_number(j, "rate_limit_down_bytes_per_sec",
                                   out.rate_limit_down_bytes_per_sec)) {
    return error;
  }
  if (j.contains("note")) {
    if (!j["note"].is_string()) {
      return Error{ErrorCode::invalid_field, "user.note must be a string"};
    }
    out.note = j["note"].get<std::string>();
  }
  if (auto reason = UserStore::validate_policy(out)) {
    return Error{ErrorCode::invalid_field, "user: " + *reason};
  }
  return std::nullopt;
}

std::optional<Error> validate_user_json(const json& j, uint64_t version,
                                        UserRecord& out) {
  if (!j.is_object()) {
    return Error{ErrorCode::invalid_file, "user entry is not an object"};
  }
  if (version == 1) {
    if (auto error = check_allowed_store_fields(
            j, {"name", "secret", "enabled", "max_connections", "generation"})) {
      return error;
    }
  } else if (auto error = check_allowed_store_fields(
                 j, {"name", "secret", "enabled", "max_connections", "generation",
                     "expires_at", "data_quota_bytes", "max_unique_ips",
                     "rate_limit_up_bytes_per_sec",
                     "rate_limit_down_bytes_per_sec", "note"})) {
    return error;
  }
  if (!j.contains("name") || !j["name"].is_string()) {
    return Error{ErrorCode::invalid_field, "user.name must be a string"};
  }
  out.name = j["name"].get<std::string>();
  if (!UserStore::is_valid_name(out.name)) {
    return Error{ErrorCode::invalid_name, "invalid user name '" + out.name + "'"};
  }
  if (!j.contains("secret") || !j["secret"].is_string()) {
    return Error{ErrorCode::invalid_field, "user.secret must be a string"};
  }
  const std::string secret = j["secret"].get<std::string>();
  if (!UserStore::is_valid_secret_hex(secret)) {
    return Error{ErrorCode::invalid_secret,
                 "user.secret must be exactly 32 hexadecimal characters"};
  }
  out.secret_hex = lower_ascii(secret);
  if (!j.contains("enabled") || !j["enabled"].is_boolean()) {
    return Error{ErrorCode::invalid_field, "user.enabled must be a boolean"};
  }
  out.enabled = j["enabled"].get<bool>();
  if (j.contains("max_connections")) {
    const auto& raw = j["max_connections"];
    if (!raw.is_null()) {
      const auto parsed = as_max_connections(raw);
      if (!parsed) {
        return Error{ErrorCode::invalid_field,
                     "user.max_connections must be null or 1.." +
                         std::to_string(kMaxConnectionsLimit)};
      }
      out.max_connections = parsed;
    }
  }
  if (!j.contains("generation")) {
    return Error{ErrorCode::invalid_field, "user.generation is required"};
  }
  const auto generation = as_u64(j["generation"]);
  if (!generation || *generation == 0) {
    return Error{ErrorCode::invalid_field, "user.generation must be >= 1"};
  }
  out.generation = *generation;
  if (version >= 2) return validate_policy_json(j, out.policy);
  return std::nullopt;
}

std::optional<Error> parse_store_file(const std::string& text, size_t max_users,
                                      uint64_t& revision,
                                      std::vector<UserRecord>& users) {
  const json root = json::parse(text, nullptr, false);
  if (root.is_discarded() || !root.is_object()) {
    return Error{ErrorCode::invalid_json, "users file is not a JSON object"};
  }
  if (auto error = check_allowed_store_fields(root, {"version", "revision", "users"})) {
    return error;
  }
  if (!root.contains("version")) {
    return Error{ErrorCode::invalid_field, "version is required"};
  }
  const auto version = as_u64(root["version"]);
  if (!version) return Error{ErrorCode::invalid_field, "version must be an integer"};
  if (*version != 1 && *version != 2) {
    return Error{ErrorCode::unsupported_version,
                 "unsupported users file version " + std::to_string(*version)};
  }
  if (!root.contains("revision")) {
    return Error{ErrorCode::invalid_field, "revision is required"};
  }
  const auto parsed_revision = as_u64(root["revision"]);
  if (!parsed_revision) {
    return Error{ErrorCode::invalid_field, "revision must be an unsigned integer"};
  }
  revision = *parsed_revision;

  if (!root.contains("users") || !root["users"].is_array()) {
    return Error{ErrorCode::invalid_field, "users must be an array"};
  }
  const auto& array = root["users"];
  if (array.size() > max_users) {
    return Error{ErrorCode::limit_exceeded,
                 "users file exceeds max_users (" + std::to_string(max_users) + ")"};
  }

  std::unordered_set<std::string> names;
  std::unordered_set<std::string> secrets;
  users.clear();
  users.reserve(array.size());
  for (const auto& entry : array) {
    UserRecord record;
    if (auto error = validate_user_json(entry, *version, record)) {
      return error;
    }
    if (!names.insert(record.name).second) {
      return Error{ErrorCode::duplicate_name,
                   "duplicate user name '" + record.name + "'"};
    }
    if (!secrets.insert(record.secret_hex).second) {
      return Error{ErrorCode::duplicate_secret,
                   "duplicate user secret for '" + record.name + "'"};
    }
    users.push_back(std::move(record));
  }
  for (const auto& user : users) {
    // Generations are allocated from revisions; a hand-edited file must not be
    // able to create a generation that a future mutation could mint again.
    if (user.generation > revision) {
      return Error{ErrorCode::invalid_file,
                   "user '" + user.name + "' generation exceeds revision"};
    }
  }
  std::sort(users.begin(), users.end(),
            [](const UserRecord& a, const UserRecord& b) { return a.name < b.name; });
  return std::nullopt;
}

std::optional<Error> write_all(int fd, std::string_view data) {
  size_t offset = 0;
  while (offset < data.size()) {
    ssize_t written =
        ::write(fd, data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR) continue;
      return errno_error(errno, "write users file");
    }
    if (written == 0) {
      return Error{ErrorCode::io_error,
                   "write users file: zero-length write (EIO)"};
    }
    offset += static_cast<size_t>(written);
  }
  return std::nullopt;
}

std::string serialize_snapshot(uint64_t revision,
                               const std::vector<UserRecord>& users) {
  json root;
  const bool extended = std::any_of(users.begin(), users.end(), [](const UserRecord& user) {
    return !user.policy.empty();
  });
  root["version"] = extended ? 2 : 1;
  root["revision"] = revision;
  json array = json::array();
  for (const auto& user : users) {
    json entry;
    entry["name"] = user.name;
    entry["secret"] = user.secret_hex;
    entry["enabled"] = user.enabled;
    if (user.max_connections) {
      entry["max_connections"] = *user.max_connections;
    } else {
      entry["max_connections"] = nullptr;
    }
    entry["generation"] = user.generation;
    if (extended) {
      const auto nullable = [](const auto& value) {
        return value ? json(*value) : json(nullptr);
      };
      const UserPolicy& policy = user.policy;
      entry["expires_at"] = nullable(policy.expires_at);
      entry["data_quota_bytes"] = nullable(policy.data_quota_bytes);
      entry["max_unique_ips"] = nullable(policy.max_unique_ips);
      entry["rate_limit_up_bytes_per_sec"] = nullable(policy.rate_limit_up_bytes_per_sec);
      entry["rate_limit_down_bytes_per_sec"] =
          nullable(policy.rate_limit_down_bytes_per_sec);
      entry["note"] = policy.note;
    }
    array.push_back(std::move(entry));
  }
  root["users"] = std::move(array);
  std::string text = root.dump();
  text.push_back('\n');
  return text;
}

// Atomically replaces the store file: temp in the same directory, fsync file,
// rename, fsync directory. Never publishes on error; after a successful rename
// a directory fsync failure is reported as uncertain.
std::optional<Error> persist_atomic(const std::string& path,
                                    const std::string& text,
                                    const StoreOptions& options) {
  if (g_persist_gate_hook != nullptr) {
    g_persist_gate_hook(g_persist_gate_context);
  }
  const std::string dir = parent_dir(path);
  const std::string base = base_name(path);
  if (base.empty()) {
    return Error{ErrorCode::invalid_config, "users path has no file name"};
  }
  if (auto error = ensure_directory(dir, options.dir_mode,
                                    options.create_directories)) {
    return error;
  }

  struct stat target {};
  if (::lstat(path.c_str(), &target) == 0) {
    if (S_ISLNK(target.st_mode)) {
      return Error{ErrorCode::symlink_rejected,
                   "users file path is a symlink: " + path};
    }
    if (!S_ISREG(target.st_mode)) {
      return Error{ErrorCode::invalid_file,
                   "users file path is not a regular file: " + path};
    }
  } else if (errno != ENOENT) {
    return errno_error(errno, "stat users file");
  }

  static std::atomic<uint64_t> sequence{0};
  std::string temp_path;
  int fd = -1;
  for (int attempt = 0; attempt < 8; ++attempt) {
    temp_path = dir + "/." + base + ".tmp." + std::to_string(::getpid()) + "." +
                std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
    fd = ::open(temp_path.c_str(),
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                static_cast<mode_t>(options.file_mode));
    if (fd >= 0) break;
    if (errno != EEXIST) return errno_error(errno, "create temporary users file");
  }
  if (fd < 0) {
    return Error{ErrorCode::io_error,
                 "could not create a unique temporary users file"};
  }

  auto cleanup = [&]() {
    ::close(fd);
    ::unlink(temp_path.c_str());
  };

  if (::fchmod(fd, static_cast<mode_t>(options.file_mode)) != 0) {
    auto error = errno_error(errno, "chmod temporary users file");
    cleanup();
    return error;
  }
  if (auto error = write_all(fd, text)) {
    cleanup();
    return error;
  }
  if (::fsync(fd) != 0) {
    auto error = errno_error(errno, "fsync temporary users file");
    cleanup();
    return error;
  }
  ::close(fd);
  fd = -1;

  if (::rename(temp_path.c_str(), path.c_str()) != 0) {
    auto error = errno_error(errno, "rename users file");
    ::unlink(temp_path.c_str());
    return error;
  }

  // From here on the new content is visible. A directory fsync failure means
  // durability across a crash is uncertain, so report it honestly.
  const int dir_fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir_fd < 0) {
    Error error = errno_error(errno, "open users directory for fsync");
    error.uncertain = true;
    return error;
  }
  if (::fsync(dir_fd) != 0) {
    Error error = errno_error(errno, "fsync users directory");
    error.uncertain = true;
    ::close(dir_fd);
    return error;
  }
  ::close(dir_fd);
  return std::nullopt;
}


}  // namespace mtdd::control::detail

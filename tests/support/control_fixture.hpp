#pragma once

// Unit and localhost HTTP integration tests for mtdd control/statistics.
// Written before the implementation (RED phase).
#include <mtdd/control.hpp>

#include "../../src/control/store_internal.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {

using namespace std::chrono_literals;
using mtdd::control::ApiMethod;
using mtdd::control::ApiRoute;
using mtdd::control::BufferState;
using mtdd::control::ControlServer;
using mtdd::control::CreateUserRequest;
using mtdd::control::DeleteUserRequest;
using mtdd::control::Direction;
using mtdd::control::ErrorCode;
using mtdd::control::HandshakeResult;
using mtdd::control::HttpOptions;
using mtdd::control::MeResult;
using mtdd::control::MeAnswerResult;
using mtdd::control::MeWorkerSnapshot;
using mtdd::control::MutationOutcome;
using mtdd::control::RejectReason;
using mtdd::control::RotateSecretRequest;
using mtdd::control::Statistics;
using mtdd::control::StoreOptions;
using mtdd::control::UpdateUserRequest;
using mtdd::control::UserStore;

constexpr const char* kToken = "unit-test-bearer-token-not-a-secret";
constexpr const char* kHexA =
    "00112233445566778899aabbccddeeff";
constexpr const char* kHexB =
    "ffeeddccbbaa99887766554433221100";
constexpr const char* kHexC =
    "0123456789abcdef0123456789abcdef";

constexpr int64_t kHistoryTue1030 = 1894098600;  // 2030-01-08 10:30 UTC
constexpr int64_t kHistoryTue1100 = 1894100400;  // 2030-01-08 11:00 UTC
constexpr int64_t kHistoryNextMon = 1894579200;  // 2030-01-14 00:00 UTC

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

class TempDir {
 public:
  TempDir() {
    std::error_code ec;
    const char* configured = std::getenv("MTDD_TEST_TMPDIR");
    const std::filesystem::path base = configured ? std::filesystem::path(configured)
                                                   : std::filesystem::temp_directory_path();
    std::filesystem::create_directories(base, ec);
    if (ec) throw std::runtime_error("cannot create test temporary directory");
    std::string tmpl = (base / "mtdd-control-XXXXXX").string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char* made = ::mkdtemp(buf.data());
    if (made == nullptr) throw std::runtime_error("mkdtemp failed");
    path_ = made;
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  const std::string& path() const { return path_; }
  std::string file(std::string_view name) const {
    return path_ + "/" + std::string(name);
  }

 private:
  std::string path_;
};

[[maybe_unused]] mode_t mode_of(const std::string& path) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) return 0;
  return st.st_mode & 07777;
}

[[maybe_unused]] std::size_t count_server_sockets(uint16_t port) {
  DIR* directory = ::opendir("/proc/self/fd");
  if (directory == nullptr) return 0;
  std::size_t count = 0;
  while (dirent* entry = ::readdir(directory)) {
    if (entry->d_name[0] == '.') continue;
    char* end = nullptr;
    const long fd = std::strtol(entry->d_name, &end, 10);
    if (end == nullptr || *end != '\0' || fd < 0) continue;
    sockaddr_storage storage {};
    socklen_t length = sizeof(storage);
    if (::getsockname(static_cast<int>(fd),
                      reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
      continue;
    }
    uint16_t local_port = 0;
    if (storage.ss_family == AF_INET) {
      local_port = ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port);
    } else if (storage.ss_family == AF_INET6) {
      local_port = ntohs(reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port);
    }
    if (local_port == port) ++count;
  }
  ::closedir(directory);
  return count;
}

[[maybe_unused]] std::string read_text_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(in),
                     std::istreambuf_iterator<char>());
}

[[maybe_unused]] void write_text_file(const std::string& path, std::string_view data,
                     mode_t mode = 0600) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(data.data(), static_cast<std::streamsize>(data.size()));
  out.close();
  if (::chmod(path.c_str(), mode) != 0) {
    throw std::runtime_error("chmod test fixture failed");
  }
}

[[maybe_unused]] UserStore open_store_or_throw(const std::string& path, StoreOptions opts = {}) {
  auto r = UserStore::open(path, std::move(opts));
  if (!r.ok()) {
    throw std::runtime_error("UserStore::open failed: " +
                             std::string(mtdd::control::to_string(r.error().code)) +
                             " " + r.error().message);
  }
  return std::move(r).value();
}

// ---------------------------------------------------------------------------
// Minimal bounded localhost HTTP/1.1 client (test-only, not production).
// ---------------------------------------------------------------------------

struct HttpResult {
  int status{0};  // 0 == transport failure / connection closed before status
  std::string body;
  std::map<std::string, std::string> headers;
  std::string error;
};

std::string ascii_lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

std::string trim(std::string s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return {};
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

int connect_localhost(uint16_t port, int timeout_ms) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }
  int flags = ::fcntl(fd, F_GETFL, 0);
  ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (rc != 0) {
    if (errno != EINPROGRESS) {
      ::close(fd);
      return -1;
    }
    pollfd p {fd, POLLOUT, 0};
    int pr = ::poll(&p, 1, timeout_ms);
    if (pr <= 0) {
      ::close(fd);
      return -1;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
      ::close(fd);
      return -1;
    }
  }
  // Keep the socket non-blocking: every wait below is poll-deadline bounded.
  return fd;
}

bool send_all(int fd, const std::string& data, int timeout_ms) {
  size_t off = 0;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n > 0) {
      off += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now())
                        .count();
      if (remain <= 0) return false;
      pollfd p {fd, POLLOUT, 0};
      if (::poll(&p, 1, static_cast<int>(remain)) <= 0) return false;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

std::string decode_chunked(const std::string& raw) {
  std::string out;
  size_t pos = 0;
  while (pos < raw.size()) {
    size_t line_end = raw.find("\r\n", pos);
    if (line_end == std::string::npos) break;
    std::string size_line = raw.substr(pos, line_end - pos);
    size_t semi = size_line.find(';');
    if (semi != std::string::npos) size_line = size_line.substr(0, semi);
    unsigned long long size = 0;
    try {
      size = std::stoull(trim(size_line), nullptr, 16);
    } catch (...) {
      break;
    }
    pos = line_end + 2;
    if (size == 0) break;
    if (pos + size > raw.size()) break;
    out.append(raw, pos, static_cast<size_t>(size));
    pos += static_cast<size_t>(size);
    if (raw.compare(pos, 2, "\r\n") == 0) pos += 2;
  }
  return out;
}

HttpResult http_call(uint16_t port, const std::string& method,
                     const std::string& path, const std::string& token,
                     const std::string& body = {},
                     const std::vector<std::pair<std::string, std::string>>& extra = {},
                     std::chrono::milliseconds timeout = 5000ms) {
  HttpResult result;
  int timeout_ms = static_cast<int>(timeout.count());
  int fd = connect_localhost(port, timeout_ms);
  if (fd < 0) {
    result.error = "connect failed";
    return result;
  }

  std::string request = method + " " + path + " HTTP/1.1\r\n";
  request += "Host: 127.0.0.1\r\n";
  request += "Connection: close\r\n";
  if (!token.empty()) request += "Authorization: Bearer " + token + "\r\n";
  for (const auto& [key, value] : extra) request += key + ": " + value + "\r\n";
  if (!body.empty() || method == "POST" || method == "PATCH") {
    request += "Content-Type: application/json\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  }
  request += "\r\n";
  request += body;

  if (!send_all(fd, request, timeout_ms)) {
    result.error = "send failed";
    ::close(fd);
    return result;
  }
  // No shutdown(SHUT_WR): evhttp treats the half-close as EOF and drops
  // the connection mid-reply, truncating bodies larger than one write.

  std::string raw;
  auto deadline = std::chrono::steady_clock::now() + timeout;
  bool closed = false;
  while (true) {
    char buf[8192];
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n > 0) {
      raw.append(buf, static_cast<size_t>(n));
      auto hdr_end = raw.find("\r\n\r\n");
      if (hdr_end != std::string::npos) {
        std::string head = raw.substr(0, hdr_end);
        std::string head_lower = ascii_lower(head);
        if (head_lower.find("\r\ntransfer-encoding: chunked") == std::string::npos) {
          auto cl = head_lower.find("\r\ncontent-length:");
          if (cl != std::string::npos) {
            size_t line_end = head_lower.find("\r\n", cl + 2);
            size_t value_start = cl + std::strlen("\r\ncontent-length:");
            std::string value = trim(head_lower.substr(
                value_start, line_end == std::string::npos ? std::string::npos
                                                           : line_end - value_start));
            try {
              size_t want = std::stoull(value);
              if (raw.size() >= hdr_end + 4 + want) break;
            } catch (...) {
            }
          }
        }
      }
      continue;
    }
    if (n == 0) {
      closed = true;
      break;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now())
                        .count();
      if (remain <= 0) {
        result.error = "read timeout";
        break;
      }
      pollfd p {fd, POLLIN, 0};
      if (::poll(&p, 1, static_cast<int>(remain)) <= 0) {
        result.error = "read timeout";
        break;
      }
      continue;
    }
    result.error = "read failed";
    break;
  }
  ::close(fd);
  (void)closed;

  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) {
    result.error = result.error.empty() ? "no response headers" : result.error;
    return result;
  }
  std::string head = raw.substr(0, hdr_end);
  std::string payload = raw.substr(hdr_end + 4);

  size_t line_end = head.find("\r\n");
  std::string status_line = head.substr(0, line_end);
  size_t sp1 = status_line.find(' ');
  if (sp1 == std::string::npos) {
    result.error = "bad status line";
    return result;
  }
  try {
    result.status = std::stoi(status_line.substr(sp1 + 1));
  } catch (...) {
    result.error = "bad status code";
    return result;
  }

  size_t pos = (line_end == std::string::npos) ? head.size() : line_end + 2;
  while (pos < head.size()) {
    size_t eol = head.find("\r\n", pos);
    std::string line = head.substr(pos, eol == std::string::npos ? std::string::npos
                                                                 : eol - pos);
    size_t colon = line.find(':');
    if (colon != std::string::npos) {
      result.headers[ascii_lower(trim(line.substr(0, colon)))] =
          trim(line.substr(colon + 1));
    }
    if (eol == std::string::npos) break;
    pos = eol + 2;
  }

  auto te = result.headers.find("transfer-encoding");
  if (te != result.headers.end() && ascii_lower(te->second).find("chunked") != std::string::npos) {
    result.body = decode_chunked(payload);
  } else {
    auto cl = result.headers.find("content-length");
    if (cl != result.headers.end()) {
      try {
        size_t want = std::stoull(cl->second);
        if (payload.size() < want && result.error.empty()) result.error = "truncated body";
        result.body = payload.substr(0, std::min(want, payload.size()));
      } catch (...) {
        result.body = payload;
      }
    } else {
      result.body = payload;
    }
  }
  return result;
}

[[maybe_unused]] nlohmann::json parse_json(const HttpResult& r) {
  return nlohmann::json::parse(r.body);
}

[[maybe_unused]] std::string header_value(const HttpResult& r, const std::string& name) {
  auto it = r.headers.find(ascii_lower(name));
  return it == r.headers.end() ? std::string() : it->second;
}

// ---------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------

class Harness {
 public:
  explicit Harness(StoreOptions store_options = {}, HttpOptions http_options = {},
                   bool enable_ip_history = false) {
    if (http_options.bearer_token.empty()) http_options.bearer_token = kToken;
    http_options_ = std::move(http_options);
    auto r = UserStore::open(dir_.file("users.json"), std::move(store_options));
    if (!r.ok()) {
      throw std::runtime_error("store open: " + r.error().message);
    }
    store_ = std::make_unique<UserStore>(std::move(r).value());
    if (enable_ip_history) stats_.enable_ip_history();
    server_ = std::make_unique<ControlServer>(*store_, stats_, http_options_);
    auto started = server_->start();
    if (!started.ok()) {
      throw std::runtime_error("server start: " + started.error().message);
    }
    port_ = started.value();
  }
  ~Harness() {
    if (server_) server_->stop();
  }
  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  HttpResult req(const std::string& method, const std::string& path,
                 const std::string& body = {},
                 const std::string& token = kToken,
                 const std::vector<std::pair<std::string, std::string>>& extra = {},
                 std::chrono::milliseconds timeout = 5000ms) {
    return http_call(port_, method, path, token, body, extra, timeout);
  }

  UserStore& store() { return *store_; }
  Statistics& stats() { return stats_; }
  uint16_t port() const { return port_; }
  TempDir& dir() { return dir_; }
  const HttpOptions& http_options() const { return http_options_; }

 private:
  TempDir dir_;
  Statistics stats_;
  std::unique_ptr<UserStore> store_;
  HttpOptions http_options_;
  std::unique_ptr<ControlServer> server_;
  uint16_t port_{0};
};

[[maybe_unused]] std::string make_user_body(const std::string& name,
                           const std::optional<std::string>& secret = std::nullopt,
                           std::optional<nlohmann::json> max_connections = std::nullopt,
                           std::optional<bool> enabled = std::nullopt) {
  nlohmann::json j = {{"name", name}};
  if (secret) j["secret"] = *secret;
  if (max_connections) j["max_connections"] = *max_connections;
  if (enabled) j["enabled"] = *enabled;
  return j.dump();
}

// ---------------------------------------------------------------------------
// UserStore: validation and CRUD
// ---------------------------------------------------------------------------

}  // namespace

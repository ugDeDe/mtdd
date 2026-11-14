// Internal users-file persistence declarations shared by store translation
// units. Not part of the public API.
#pragma once

#include <mtdd/control.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mtdd::control::detail {

std::string lower_ascii(std::string value);
// Lowercase DNS hostname (labels 1..63 of [a-z0-9-], not starting or ending
// with "-", total <= kMaxTlsDomainBytes). Personal tls_domain values must pass.
bool valid_tls_domain(std::string_view domain);
// 32 lowercase hexadecimal characters, not all zero.
bool valid_ad_tag(std::string_view tag);
bool is_hex_digit(char c);
std::string hex_encode(const unsigned char* data, size_t size);

Error errno_error(int err, std::string_view what);
std::string parent_dir(const std::string& path);
std::string base_name(const std::string& path);

std::optional<Error> ensure_directory(const std::string& dir, uint32_t mode,
                                      bool create);
std::optional<Error> parse_store_file(const std::string& text, size_t max_users,
                                      uint64_t& revision,
                                      std::vector<UserRecord>& users);
std::string serialize_snapshot(uint64_t revision,
                               const std::vector<UserRecord>& users);
std::optional<Error> persist_atomic(const std::string& path,
                                    const std::string& text,
                                    const StoreOptions& options);

// Test-only deterministic gate: runs at the very start of persist_atomic(),
// while the caller still holds the store mutation mutex and before any
// filesystem work. Production code never installs it; it exists so tests can
// prove that readers do not wait for an in-flight durable write. Install
// before starting worker threads and clear it before destroying the store.
// Not part of the public API, configuration, or CLI.
using PersistGateHook = void (*)(void* context);
void set_persist_gate_hook(PersistGateHook hook, void* context) noexcept;

}  // namespace mtdd::control::detail

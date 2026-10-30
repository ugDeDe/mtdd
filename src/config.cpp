#include "mtdd/config.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>

namespace mtdd {
namespace {
constexpr std::size_t max_config_bytes{64 * 1024};

std::uint64_t number(const nlohmann::json& value, const char* key, std::uint64_t fallback,
                     std::uint64_t minimum, std::uint64_t maximum) {
    if (!value.contains(key)) {
        if (fallback < minimum || fallback > maximum)
            throw std::invalid_argument(std::string(key) + " default is outside its supported range");
        return fallback;
    }
    const auto& field = value.at(key);
    if (!field.is_number_integer() || (!field.is_number_unsigned() && field.get<std::int64_t>() < 0))
        throw std::invalid_argument(std::string(key) + " must be a non-negative integer");
    const auto result = field.get<std::uint64_t>();
    if (result < minimum || result > maximum)
        throw std::invalid_argument(std::string(key) + " is outside its supported range");
    return result;
}

std::string text(const nlohmann::json& value, const char* key, const std::string& fallback) {
    if (!value.contains(key)) return fallback;
    if (!value.at(key).is_string()) throw std::invalid_argument(std::string(key) + " must be a string");
    auto result = value.at(key).get<std::string>();
    if (result.empty() || result.size() > 4096 || result.find('\0') != std::string::npos)
        throw std::invalid_argument(std::string(key) + " is empty or too long");
    return result;
}

bool boolean(const nlohmann::json& value, const char* key, bool fallback) {
    if (!value.contains(key)) return fallback;
    if (!value.at(key).is_boolean()) throw std::invalid_argument(std::string(key) + " must be boolean");
    return value.at(key).get<bool>();
}

bool valid_domain(const std::string& domain) {
    if (domain.empty() || domain.size() > 253) return false;
    std::size_t start{};
    while (start < domain.size()) {
        const auto end = domain.find('.', start);
        const auto length = (end == std::string::npos ? domain.size() : end) - start;
        if (length == 0 || length > 63 || domain[start] == '-' || domain[start + length - 1] == '-') return false;
        for (std::size_t i = start; i < start + length; ++i) {
            const auto c = static_cast<unsigned char>(domain[i]);
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-') return false;
        }
        if (end == std::string::npos) return true;
        start = end + 1;
    }
    return false;
}

bool numeric_ip(const std::string& host) {
    std::array<unsigned char, 16> address{};
    return inet_pton(AF_INET, host.c_str(), address.data()) == 1 ||
           inet_pton(AF_INET6, host.c_str(), address.data()) == 1;
}

bool loopback(const std::string& host) {
    in_addr v4{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) return (ntohl(v4.s_addr) >> 24) == 127;
    return host == "::1";
}

unsigned hex_digit(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
    throw std::invalid_argument("ad_tag must contain exactly 32 hexadecimal characters");
}

std::filesystem::path resolve(const std::filesystem::path& base, const std::string& path) {
    const std::filesystem::path result{path};
    return (result.is_absolute() ? result : base / result).lexically_normal();
}
} // namespace

Config Config::parse(const nlohmann::json& value, const std::filesystem::path& base) {
    if (!value.is_object()) throw std::invalid_argument("configuration must be a JSON object");
    const std::set<std::string> allowed{
        "proxy_host", "proxy_port", "public_host", "public_port", "control_host", "control_port", "allow_remote_control",
        "api_token_env", "tls_domain", "ad_tag", "users_path", "me_config_path", "me_secret_path",
        "workers", "max_connections", "max_handshakes", "max_frame_bytes", "connection_queue_bytes",
        "global_buffer_bytes", "handshake_timeout_seconds", "idle_timeout_seconds", "shutdown_timeout_seconds",
        "metadata_refresh_seconds", "fallback_host", "fallback_port", "masking", "unique_ip_stats_path",
        "direct_fallback_enabled", "direct_fallback_dcs", "me_connections_per_dc",
        "me_clients_per_writer", "client_keepalive_seconds", "client_ack_timeout_seconds",
        "media_user_rate_kbps", "media_total_rate_kbps"};
    for (const auto& [key, ignored] : value.items()) {
        (void)ignored;
        if (!allowed.contains(key)) throw std::invalid_argument("unknown configuration option: " + key);
    }
    Config config;
    config.proxy_host = text(value, "proxy_host", config.proxy_host);
    config.control_host = text(value, "control_host", config.control_host);
    if (!numeric_ip(config.proxy_host) || !numeric_ip(config.control_host))
        throw std::invalid_argument("listener hosts must be numeric IP addresses");
    config.allow_remote_control = boolean(value, "allow_remote_control", false);
    if (!config.allow_remote_control && !loopback(config.control_host))
        throw std::invalid_argument("non-loopback API requires allow_remote_control=true and a secure network/tunnel");
    config.proxy_port = static_cast<std::uint16_t>(number(value, "proxy_port", config.proxy_port, 1, 65535));
    config.public_host = text(value, "public_host", "");
    if (!config.public_host.empty() && (!numeric_ip(config.public_host) && !valid_domain(config.public_host)))
        throw std::invalid_argument("public_host must be an IP address or DNS hostname");
    if (config.public_host == "0.0.0.0" || config.public_host == "::")
        throw std::invalid_argument("public_host must not be an unspecified address");
    config.public_port = static_cast<std::uint16_t>(number(value, "public_port", config.proxy_port, 1, 65535));
    config.control_port = static_cast<std::uint16_t>(number(value, "control_port", config.control_port, 1, 65535));
    if (config.proxy_port == config.control_port &&
        (config.proxy_host == config.control_host || config.proxy_host == "0.0.0.0" ||
         config.control_host == "0.0.0.0" || config.proxy_host == "::" || config.control_host == "::"))
        throw std::invalid_argument("proxy and control listener endpoints overlap");
    config.fallback_host = text(value, "fallback_host", config.fallback_host);
    if (numeric_ip(config.fallback_host)) {
        if (config.fallback_host == "0.0.0.0" || config.fallback_host == "::")
            throw std::invalid_argument("fallback_host must not be a wildcard address");
    } else if (!valid_domain(config.fallback_host)) {
        throw std::invalid_argument("fallback_host must be an IP address or a DNS hostname");
    }
    config.fallback_port = static_cast<std::uint16_t>(number(value, "fallback_port", 0, 0, 65535));
    config.masking = boolean(value, "masking", config.masking);
    if (config.fallback_port != 0 &&
        (config.fallback_port == config.proxy_port || config.fallback_port == config.control_port))
        throw std::invalid_argument("fallback port must differ from proxy and control ports");
    config.api_token_env = text(value, "api_token_env", config.api_token_env);
    for (const auto c : config.api_token_env)
        if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_')
            throw std::invalid_argument("api_token_env must be an environment variable name");
    config.tls_domain = text(value, "tls_domain", "");
    if (!valid_domain(config.tls_domain)) throw std::invalid_argument("tls_domain must be a DNS hostname");
    const auto tag = text(value, "ad_tag", "");
    if (tag.size() != 32) throw std::invalid_argument("ad_tag is required and must have 32 hexadecimal characters");
    for (std::size_t i{}; i < config.ad_tag.size(); ++i)
        config.ad_tag[i] = static_cast<std::uint8_t>((hex_digit(tag[i * 2]) << 4) | hex_digit(tag[i * 2 + 1]));
    if (std::all_of(config.ad_tag.begin(), config.ad_tag.end(), [](auto byte) { return byte == 0; }))
        throw std::invalid_argument("ad_tag must not be all zero");
    config.users_path = resolve(base, text(value, "users_path", "users.json"));
    if (value.contains("me_config_path")) config.me_config_path = resolve(base, text(value, "me_config_path", ""));
    if (value.contains("me_secret_path")) config.me_secret_path = resolve(base, text(value, "me_secret_path", ""));
    if (config.me_config_path.empty() != config.me_secret_path.empty())
        throw std::invalid_argument("me_config_path and me_secret_path must be provided together");
    if (value.contains("unique_ip_stats_path")) {
        config.unique_ip_stats_path = resolve(base, text(value, "unique_ip_stats_path", ""));
        if (config.unique_ip_stats_path == config.users_path ||
            config.unique_ip_stats_path == config.me_config_path ||
            config.unique_ip_stats_path == config.me_secret_path)
            throw std::invalid_argument("unique IP statistics must use a separate file");
    }
    config.workers = static_cast<std::uint32_t>(number(value, "workers", 0, 0, 256));
    config.me_connections_per_dc = static_cast<std::uint32_t>(
        number(value, "me_connections_per_dc", config.me_connections_per_dc, 1, 24));
    config.me_clients_per_writer = static_cast<std::uint32_t>(
        number(value, "me_clients_per_writer", config.me_clients_per_writer, 1, 1000000));
    if (value.contains("max_connections")) {
        config.max_connections = static_cast<std::uint32_t>(
            number(value, "max_connections", 0, 1, 1000000));
    }
    if (value.contains("max_handshakes")) {
        config.max_handshakes = static_cast<std::uint32_t>(
            number(value, "max_handshakes", 0, 1, 1000000));
    }
    config.max_frame_bytes = static_cast<std::size_t>(number(value, "max_frame_bytes", config.max_frame_bytes, 4096, 16 * 1024 * 1024));
    config.connection_queue_bytes = static_cast<std::size_t>(number(value, "connection_queue_bytes", config.connection_queue_bytes, 4096, 16 * 1024 * 1024));
    config.global_buffer_bytes = static_cast<std::size_t>(number(value, "global_buffer_bytes", config.global_buffer_bytes, config.connection_queue_bytes, 1024ULL * 1024 * 1024));
    const auto minimum_buffer_budget = 2 * config.max_frame_bytes + 2 * config.connection_queue_bytes + 65536;
    if (config.global_buffer_bytes < minimum_buffer_budget)
        throw std::invalid_argument("global_buffer_bytes must cover two maximum frames, two queues and 64 KiB overhead");
    if (config.workers != 0 &&
        config.global_buffer_bytes / config.workers < minimum_buffer_budget)
        throw std::invalid_argument(
            "global_buffer_bytes is too small for the configured workers: each reactor "
            "needs at least 2*max_frame_bytes + 2*connection_queue_bytes + 64 KiB; "
            "reduce workers or raise global_buffer_bytes");
    config.handshake_timeout = std::chrono::seconds(number(value, "handshake_timeout_seconds", 15, 1, 120));
    config.idle_timeout = std::chrono::seconds(number(value, "idle_timeout_seconds", 1800, 30, 86400));
    config.shutdown_timeout = std::chrono::seconds(number(value, "shutdown_timeout_seconds", 10, 1, 120));
    config.metadata_refresh = std::chrono::seconds(number(value, "metadata_refresh_seconds", 3600, 60, 86400));
    config.client_keepalive = std::chrono::seconds(number(value, "client_keepalive_seconds", 60, 0, 7200));
    config.client_ack_timeout = std::chrono::seconds(number(value, "client_ack_timeout_seconds", 90, 0, 3600));
    config.media_user_rate_kbps = static_cast<std::uint64_t>(number(value, "media_user_rate_kbps", 0, 0, 100000000));
    config.media_total_rate_kbps = static_cast<std::uint64_t>(number(value, "media_total_rate_kbps", 0, 0, 100000000));
    if (config.client_ack_timeout.count() != 0 && config.client_ack_timeout.count() < 10)
        throw std::invalid_argument("client_ack_timeout_seconds must be 0 or at least 10");
    config.direct_fallback_enabled =
        boolean(value, "direct_fallback_enabled", config.direct_fallback_enabled);
    if (value.contains("direct_fallback_dcs")) {
        const auto& dcs = value.at("direct_fallback_dcs");
        if (!dcs.is_array()) throw std::invalid_argument("direct_fallback_dcs must be an array");
        std::set<std::int16_t> seen;
        for (const auto& field : dcs) {
            if (!field.is_number_integer()) {
                throw std::invalid_argument("direct_fallback_dcs entries must be integers");
            }
            const auto raw = field.get<std::int64_t>();
            if (raw == 0 || raw < -5 || raw > 5) {
                throw std::invalid_argument(
                    "direct_fallback_dcs supports only signed DCs +/-1..5 (no 203/CDN)");
            }
            const auto dc = static_cast<std::int16_t>(raw);
            if (!seen.insert(dc).second) {
                throw std::invalid_argument("direct_fallback_dcs contains a duplicate DC");
            }
            config.direct_fallback_dcs.push_back(dc);
        }
    }
    return config;
}

Config Config::load(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open configuration file");
    std::string bytes;
    std::array<char, 4096> chunk{};
    while (file.read(chunk.data(), static_cast<std::streamsize>(chunk.size())) || file.gcount() != 0) {
        bytes.append(chunk.data(), static_cast<std::size_t>(file.gcount()));
        if (bytes.size() > max_config_bytes) throw std::invalid_argument("configuration file is too large");
    }
    if (file.bad()) throw std::runtime_error("cannot read configuration file");
    try {
        return parse(nlohmann::json::parse(bytes), std::filesystem::absolute(path).parent_path());
    } catch (const nlohmann::json::exception&) {
        throw std::invalid_argument("invalid JSON configuration");
    }
}
} // namespace mtdd

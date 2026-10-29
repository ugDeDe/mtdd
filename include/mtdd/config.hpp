#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json_fwd.hpp>
#include <string>
#include <vector>

namespace mtdd {
struct Config {
    std::string proxy_host{"127.0.0.1"};
    std::uint16_t proxy_port{14443};
    std::string public_host;
    std::uint16_t public_port{0};
    std::string control_host{"127.0.0.1"};
    std::uint16_t control_port{9090};
    bool allow_remote_control{false};
    std::string fallback_host{"127.0.0.1"};
    std::uint16_t fallback_port{0}; // Nonzero pins the masking relay to this target.
    // Probe masking on by default: unrecognised ClientHellos are relayed to the
    // real server of the probed SNI name when it belongs to tls_domain.
    bool masking{true};
    std::string api_token_env{"MTDD_API_TOKEN"};
    std::string tls_domain;
    std::array<std::uint8_t, 16> ad_tag{};
    std::filesystem::path users_path;
    std::filesystem::path unique_ip_stats_path; // optional private HLL checkpoints
    std::filesystem::path me_config_path;
    std::filesystem::path me_secret_path;
    std::uint32_t workers{0};
    // Zero means unlimited; set a positive value to enforce a global cap.
    std::uint32_t max_connections{0};
    // Maximum active ME connections per signed DC and reactor, range 1..24.
    std::uint32_t me_connections_per_dc{16};
    std::uint32_t me_clients_per_writer{400};
    // Zero means unlimited; set a positive value to cap pending handshakes.
    std::uint32_t max_handshakes{0};
    std::size_t max_frame_bytes{2 * 1024 * 1024};
    std::size_t connection_queue_bytes{256 * 1024};
    std::size_t global_buffer_bytes{256 * 1024 * 1024};
    std::chrono::seconds handshake_timeout{15};
    std::chrono::seconds idle_timeout{1800};
    std::chrono::seconds shutdown_timeout{10};
    // Client socket liveness. Keepalive probes start after this much silence
    // (0 disables), and TCP_USER_TIMEOUT resets a peer that leaves data or
    // probes unacknowledged this long (0 keeps the kernel default). Without
    // them a vanished mobile client holds its slot until idle_timeout.
    std::chrono::seconds client_keepalive{60};
    std::chrono::seconds client_ack_timeout{90};
    std::chrono::seconds metadata_refresh{3600};
    // Opt-in Direct Telegram DC fallback. Disabled by default; only the listed
    // signed DCs use the trusted official direct address table.
    bool direct_fallback_enabled{false};
    std::vector<std::int16_t> direct_fallback_dcs;

    static Config parse(const nlohmann::json& value, const std::filesystem::path& base);
    static Config load(const std::filesystem::path& path);
};
} // namespace mtdd

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
    // Optional GET-only API token; empty means no read token is accepted.
    std::string api_read_token_env;
    // Peer allowlist for the API listener; empty admits any peer with a token.
    std::vector<std::string> control_allow;
    // Separate Prometheus listener. Port 0 disables it. 9091 rather than 9100
    // so it does not collide with node_exporter on the same host.
    std::string metrics_host{"127.0.0.1"};
    std::uint16_t metrics_port{9091};
    // Optional scrape token; without it only metrics_allow guards /metrics.
    std::string metrics_token_env;
    std::vector<std::string> metrics_allow{"127.0.0.0/8", "::1"};
    std::string tls_domain;
    std::array<std::uint8_t, 16> ad_tag{};
    std::filesystem::path users_path;
    std::filesystem::path unique_ip_stats_path; // optional private HLL checkpoints
    std::filesystem::path usage_state_path;     // optional private per-user quota counters
    // Payload bytes (c2s + s2c) one connection must transfer before its IP
    // counts as "active" unique. 0 qualifies at handshake (active == seen).
    std::uint64_t unique_ip_min_bytes{1024 * 1024};
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
    // Media shaping for signed DC < 0 (file/photo/video downloads), kbit/s.
    // Per proxy user across all of its media connections, and a process-wide
    // cap. 0 disables. Reloadable with SIGHUP.
    std::uint64_t media_user_rate_kbps{0};
    std::uint64_t media_total_rate_kbps{0};
    // How long a device's auth key stays listed in the devices gauge after its
    // last connection closed. An idle key never blocks a new device.
    std::chrono::seconds device_window{900};
    // Investigation aid: connections from these addresses/CIDRs get a
    // per-stage log in the journal ("mtdd watch: ..."): SYN fingerprint,
    // first bytes, ClientHello, auth result, masking, DC, auth_key_id,
    // MTProto frames, close reason and kernel byte counts. Empty = off.
    std::vector<std::string> watch_ips;
    // Suspicious-behaviour detection (GET /v1/suspects, mtdd-ctl suspects).
    // Addresses at or above suspect_watch_score get the watch_ips log
    // automatically (0 = never). At or above suspect_ban_score their
    // connections go to masking even with a valid secret (0 = off). Idle
    // entries are dropped after suspect_ttl.
    bool suspects{true};
    std::uint32_t suspect_watch_score{60};
    std::uint32_t suspect_ban_score{0};
    std::chrono::hours suspect_ttl{168};
    std::chrono::seconds metadata_refresh{3600};
    // Opt-in Direct Telegram DC fallback. Disabled by default; only the listed
    // signed DCs use the trusted official direct address table.
    bool direct_fallback_enabled{false};
    std::vector<std::int16_t> direct_fallback_dcs;

    static Config parse(const nlohmann::json& value, const std::filesystem::path& base);
    static Config load(const std::filesystem::path& path);
    // Effective settings for GET /v1/config. Tokens never live in Config (only
    // their variable names do); the ad_tag is reduced to "is it set".
    nlohmann::json public_view() const;
    // Exposure summary for GET /v1/system/info: what listens where, with which
    // guard. Booleans and counts only.
    nlohmann::json security_posture() const;
};
} // namespace mtdd

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json_fwd.hpp>
#include <string>
#include <vector>

namespace mtdd {
// One way out of the host for outbound connections (Telegram ME and Direct
// DCs, masking, metadata downloads), as telemt's [[upstreams]]:
//   direct  connect from here, optionally through `interface`
//           (SO_BINDTODEVICE) or from `bind_address`;
//   socks5  connect through a SOCKS5 proxy at host:port (numeric), with
//           optional username/password; interface/bind_address then apply
//           to the connection to the proxy.
// A connection picks among the upstreams of its scope by weight: Telegram
// connections and metadata use the upstreams without scopes, masking uses
// Config::masking_scope.
struct UpstreamConfig {
    enum class Type { direct, socks5 };
    std::string name;
    Type type{Type::direct};
    std::string interface;
    std::string bind_address;
    std::string host;  // socks5 server address
    std::uint16_t port{0};
    std::string username;
    std::string password;
    std::uint32_t weight{1};
    std::vector<std::string> scopes;  // empty: the default scope
};

struct Config {
    std::string proxy_host{"127.0.0.1"};
    std::uint16_t proxy_port{14443};
    std::string public_host;
    std::uint16_t public_port{0};
    std::string control_host{"127.0.0.1"};
    std::uint16_t control_port{9090};
    bool allow_remote_control{false};
    // PROXY protocol (HAProxy v1/v2) on the proxy listener, for a trusted
    // front (SNI router, load balancer) that forwards client connections.
    // When on, every connection must start with a PROXY header, sent by a peer
    // in proxy_protocol_allow; others are closed. The header's source address
    // then stands for the client everywhere (limits, statistics, suspects,
    // watch_ips, the address reported to Telegram).
    bool proxy_protocol{false};
    std::vector<std::string> proxy_protocol_allow{"127.0.0.0/8", "::1"};
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
    // Outbound upstreams; empty means one plain direct upstream.
    std::vector<UpstreamConfig> upstreams;
    // Scope of the masking connections (telemt's tls_fetch_scope); empty is
    // the default scope. E.g. "local" with a direct upstream scoped "local"
    // keeps a local mask site off a tunnel the Telegram traffic takes.
    std::string masking_scope;
    // The address Telegram's middle-end sees this host connect from, when it
    // is not the socket's own: behind NAT or through a tunnel/upstream whose
    // exit address is fixed (telemt's middle_proxy_nat_ip). It replaces the
    // local IP in the ME key derivation and in RPC_PROXY_REQ; the port is
    // kept, so the NAT must preserve source ports. Empty: the socket address
    // (or, through SOCKS5, the address the proxy reports).
    std::string me_nat_ip;
    std::filesystem::path users_path;
    std::filesystem::path unique_ip_stats_path; // optional private HLL checkpoints
    std::filesystem::path usage_state_path;     // optional private per-user quota counters
    // Payload bytes (c2s + s2c) one connection must transfer before its IP
    // counts as "active" unique. 0 qualifies at handshake (active == seen).
    std::uint64_t unique_ip_min_bytes{1024 * 1024};
    std::filesystem::path me_config_path;
    std::filesystem::path me_secret_path;
    // IPv6 Middle-End endpoints (getProxyConfigV6):
    //   off   only the IPv4 list (getProxyConfig), as before;
    //   auto  also load the IPv6 list; a DC dials IPv6 only when it has no
    //         IPv4 endpoint or its IPv4 dials keep failing (see me.cpp);
    //   on    IPv6 first, IPv4 as the fallback by the same rule.
    // A failed IPv6 list never fails a metadata refresh: the previous IPv6
    // list (or none) is kept.
    enum class MeIpv6 : std::uint8_t { off, automatic, on };
    MeIpv6 me_ipv6{MeIpv6::automatic};
    // Local IPv6 list instead of the download (like me_config_path). With
    // me_config_path set and this empty, no IPv6 list is used.
    std::filesystem::path me_config_v6_path;
    std::uint32_t workers{0};
    // Zero means unlimited; set a positive value to enforce a global cap.
    std::uint32_t max_connections{0};
    // Maximum active ME connections per signed DC and reactor, range 1..24.
    // Pin reactor i to the i-th CPU of the process affinity mask when there
    // are no more reactors than CPUs. With RFS the kernel then processes each
    // connection's packets on the CPU of the reactor that owns it, and
    // reactors keep their caches instead of migrating.
    bool cpu_affinity{true};
    std::uint32_t me_connections_per_dc{16};
    // Process-wide ME writers per signed DC across all reactors, 1..1024;
    // 0 = no process-wide cap. Each reactor's first writer of a DC (and of a
    // metadata successor generation) is exempt, so no reactor is starved.
    // Reloadable with SIGHUP.
    std::uint32_t me_connections_per_dc_total{0};
    std::uint32_t me_clients_per_writer{400};
    // Zero means unlimited; set a positive value to cap pending handshakes.
    std::uint32_t max_handshakes{0};
    std::size_t max_frame_bytes{2 * 1024 * 1024};
    std::size_t connection_queue_bytes{256 * 1024};
    // Relay-buffer budget shared by all reactors. When the config omits it,
    // Config::parse sizes it from memory (default_global_buffer_bytes) and
    // sets global_buffer_auto.
    std::size_t global_buffer_bytes{256 * 1024 * 1024};
    bool global_buffer_auto{false};
    std::chrono::seconds handshake_timeout{15};
    // Accepted |server clock - ClientHello timestamp|, seconds. 0 ignores the
    // client timestamp entirely (replay protection then rests on the replay
    // cache alone, with a fixed one-hour retention).
    std::uint32_t client_clock_skew_seconds{120};
    // FakeTLS ServerHello held back by a uniform draw from this inclusive
    // range, as a real server answers only after its own key exchange and
    // signature. 0/0 (the default) answers at once: every Telegram connection
    // pays the delay. At most kMaxServerHelloDelay, min <= max; the maximum
    // defaults to the minimum.
    std::chrono::milliseconds server_hello_delay_min{0};
    std::chrono::milliseconds server_hello_delay_max{0};
    static constexpr std::chrono::milliseconds kMaxServerHelloDelay{1000};
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
    // Client fingerprint: each accepted SYN is kept (TCP_SAVE_SYN) and read
    // back, and the ClientHello is classified, to name the platform of a
    // device or suspect (Android/Apple/Windows/Linux). Off by default: it costs
    // a getsockopt and a parse per connection; without it platforms are
    // "Undefined".
    bool fingerprint{false};
    // Suspicious-behaviour detection (GET /v1/suspects, mtdd-ctl suspects).
    // Off by default. Addresses at or above suspect_watch_score get the
    // watch_ips log automatically (0 = never). At or above suspect_ban_score
    // their connections go to masking even with a valid secret (0 = off).
    // Idle entries are dropped after suspect_ttl.
    bool suspects{false};
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

// Upper bound of global_buffer_bytes, explicit or derived.
inline constexpr std::uint64_t kMaxGlobalBufferBytes = 64ULL << 30;

// Memory available to this process: the smaller of MemTotal and every cgroup
// memory limit on the process's cgroup path (v2 memory.max, v1
// memory.limit_in_bytes). `root` prefixes /proc and /sys for tests. 0 when
// MemTotal cannot be read.
std::uint64_t detect_memory_limit_bytes(const std::filesystem::path& root = "/");

// Budget used when global_buffer_bytes is not configured: a quarter of
// `memory_bytes`, clamped to 64 MiB..kMaxGlobalBufferBytes; 256 MiB when the
// memory size is unknown (0).
std::uint64_t default_global_buffer_bytes(std::uint64_t memory_bytes);
} // namespace mtdd

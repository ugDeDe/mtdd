#include "mtdd/config.hpp"
#include "mtdd/metadata.hpp"

#include <gtest/gtest.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <unistd.h>

namespace {

nlohmann::json minimal_config() {
    return {{"tls_domain", "example.org"},
            {"ad_tag", "00112233445566778899aabbccddeeff"}};
}

TEST(Config, MinimalConfigHasUnlimitedConnectionDefaults) {
    const auto config = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_EQ(config.control_host, "127.0.0.1");
    EXPECT_EQ(config.control_port, 9090);
    EXPECT_EQ(config.workers, 0U);
    EXPECT_EQ(config.max_connections, 0U);
    EXPECT_EQ(config.max_handshakes, 0U);
    EXPECT_EQ(config.users_path, "/work/users.json");
    EXPECT_LT(config.connection_queue_bytes, config.global_buffer_bytes);
    EXPECT_EQ(config.ad_tag.front(), 0x00);
    EXPECT_EQ(config.ad_tag.back(), 0xff);
}

TEST(Config, ProxyProtocolIsOffByDefaultWithALoopbackAllowlist) {
    const auto config = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_FALSE(config.proxy_protocol);
    EXPECT_EQ(config.proxy_protocol_allow, (std::vector<std::string>{"127.0.0.0/8", "::1"}));
    EXPECT_FALSE(config.public_view()["proxy_protocol"].get<bool>());

    auto value = minimal_config();
    value["proxy_protocol"] = true;
    value["proxy_protocol_allow"] = {"10.0.0.0/8", "fd00::/8"};
    const auto enabled = mtdd::Config::parse(value, "/work");
    EXPECT_TRUE(enabled.proxy_protocol);
    EXPECT_EQ(enabled.proxy_protocol_allow.size(), 2U);
    EXPECT_EQ(enabled.security_posture()["proxy_protocol"]["allowlist_entries"], 2);

    value["proxy_protocol_allow"] = nlohmann::json::array();
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["proxy_protocol_allow"] = {"not-an-address"};
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value.erase("proxy_protocol_allow");
    value["proxy_protocol"] = "yes";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, UpstreamsParseLikeTelemtAndHideCredentials) {
    auto value = minimal_config();
    value["upstreams"] = nlohmann::json::parse(R"([
        {"name": "donor", "type": "socks5", "address": "10.200.0.1:1080",
         "username": "u", "password": "p", "weight": 10},
        {"type": "socks5", "address": "[2001:db8::1]:41080", "interface": "mtpawg"},
        {"type": "direct", "scopes": "local,fetch", "weight": 1},
        {"type": "direct", "bind_address": "10.8.0.2", "enabled": false}
    ])");
    value["masking_scope"] = "local";
    value["me_nat_ip"] = "203.0.113.9";
    const auto config = mtdd::Config::parse(value, "/work");
    ASSERT_EQ(config.upstreams.size(), 3U);  // the disabled one is dropped
    const auto& donor = config.upstreams[0];
    EXPECT_EQ(donor.type, mtdd::UpstreamConfig::Type::socks5);
    EXPECT_EQ(donor.host, "10.200.0.1");
    EXPECT_EQ(donor.port, 1080);
    EXPECT_EQ(donor.username, "u");
    EXPECT_EQ(donor.weight, 10U);
    EXPECT_EQ(config.upstreams[1].host, "2001:db8::1");
    EXPECT_EQ(config.upstreams[1].interface, "mtpawg");
    EXPECT_EQ(config.upstreams[2].scopes, (std::vector<std::string>{"local", "fetch"}));
    EXPECT_EQ(config.masking_scope, "local");
    EXPECT_EQ(config.me_nat_ip, "203.0.113.9");

    const auto view = config.public_view();
    EXPECT_EQ(view["upstreams"][0]["address"], "10.200.0.1:1080");
    EXPECT_EQ(view["upstreams"][0]["auth"], true);
    EXPECT_EQ(view["upstreams"][1]["address"], "[2001:db8::1]:41080");
    EXPECT_EQ(view.dump().find("\"p\""), std::string::npos);  // the password never shows

    EXPECT_TRUE(mtdd::Config::parse(minimal_config(), "/work").upstreams.empty());
}

TEST(Config, InvalidUpstreamsAreRefused) {
    const std::vector<std::string> bad = {
        R"({"upstreams": {}})",
        R"({"upstreams": [{"type": "http"}]})",
        R"({"upstreams": [{"type": "socks5"}]})",
        R"({"upstreams": [{"type": "socks5", "address": "proxy.example:1080"}]})",
        R"({"upstreams": [{"type": "socks5", "address": "2001:db8::1:1080"}]})",
        R"({"upstreams": [{"type": "socks5", "address": "127.0.0.1:0"}]})",
        R"({"upstreams": [{"type": "socks5", "address": "127.0.0.1:1080", "username": "u"}]})",
        R"({"upstreams": [{"type": "socks5", "address": "127.0.0.1:1080", "username": 5, "password": "p"}]})",
        R"({"upstreams": [{"type": "direct", "address": "127.0.0.1:1080"}]})",
        R"({"upstreams": [{"type": "direct", "interface": "bad iface"}]})",
        R"({"upstreams": [{"type": "direct", "bind_address": "host.example"}]})",
        R"({"upstreams": [{"type": "direct", "weight": 0}]})",
        R"({"upstreams": [{"type": "direct", "scopes": ["bad scope"]}]})",
        R"({"upstreams": [{"type": "direct", "scopes": ["local"]}]})",  // no default scope
        R"({"upstreams": [{"type": "direct", "colour": "red"}]})",
        R"({"masking_scope": "local"})",                                // no such scope
        R"({"me_nat_ip": "0.0.0.0"})",
        R"({"me_nat_ip": "nat.example"})",
    };
    for (const auto& patch : bad) {
        SCOPED_TRACE(patch);
        auto value = minimal_config();
        value.update(nlohmann::json::parse(patch));
        EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    }
}

TEST(Config, SuspectsAndFingerprintAreOffByDefault) {
    const auto config = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_FALSE(config.suspects);
    EXPECT_FALSE(config.fingerprint);
    auto on = minimal_config();
    on["suspects"] = true;
    on["fingerprint"] = true;
    const auto enabled = mtdd::Config::parse(on, "/work");
    EXPECT_TRUE(enabled.suspects);
    EXPECT_TRUE(enabled.fingerprint);
}

TEST(Config, CpuAffinityIsOnByDefaultAndCanBeDisabled) {
    EXPECT_TRUE(mtdd::Config::parse(minimal_config(), "/work").cpu_affinity);
    auto off = minimal_config();
    off["cpu_affinity"] = false;
    EXPECT_FALSE(mtdd::Config::parse(off, "/work").cpu_affinity);
}

TEST(Config, MetricsListenerDefaultsToLoopbackWithoutToken) {
    const auto config = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_EQ(config.metrics_host, "127.0.0.1");
    EXPECT_EQ(config.metrics_port, 9091);
    EXPECT_TRUE(config.metrics_token_env.empty());
    EXPECT_TRUE(config.api_read_token_env.empty());
    EXPECT_EQ(config.metrics_allow, (std::vector<std::string>{"127.0.0.0/8", "::1"}));
    EXPECT_TRUE(config.control_allow.empty());
}

TEST(Config, MetricsAndTokenOptionsAreValidated) {
    auto value = minimal_config();
    value["api_read_token_env"] = "MTDD_API_READ_TOKEN";
    value["metrics_token_env"] = "MTDD_METRICS_TOKEN";
    value["metrics_host"] = "0.0.0.0";
    value["metrics_allow"] = {"10.0.0.0/8", "2001:db8::/32", "192.0.2.1"};
    value["control_allow"] = {"127.0.0.1/32"};
    const auto config = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(config.api_read_token_env, "MTDD_API_READ_TOKEN");
    EXPECT_EQ(config.metrics_allow.size(), 3U);
    EXPECT_EQ(config.control_allow.front(), "127.0.0.1/32");

    value = minimal_config();
    value["metrics_port"] = 0;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").metrics_port, 0);

    const auto rejects = [](nlohmann::json bad) {
        EXPECT_THROW(mtdd::Config::parse(bad, "/work"), std::invalid_argument) << bad.dump();
    };
    auto bad = minimal_config();
    bad["metrics_allow"] = {"10.0.0.0/33"};
    rejects(bad);
    bad["metrics_allow"] = "127.0.0.1";
    rejects(bad);
    bad = minimal_config();
    bad["metrics_allow"] = nlohmann::json::array();
    rejects(bad);  // neither token nor allowlist
    bad = minimal_config();
    bad["metrics_host"] = "0.0.0.0";
    rejects(bad);  // public exporter must opt in explicitly
    bad = minimal_config();
    bad["metrics_port"] = 9090;
    rejects(bad);  // collides with control_port
    bad = minimal_config();
    bad["metrics_token_env"] = "MTDD_API_TOKEN";
    rejects(bad);
    bad = minimal_config();
    bad["api_read_token_env"] = "X";
    bad["metrics_token_env"] = "X";
    rejects(bad);
    bad = minimal_config();
    bad["api_read_token_env"] = "BAD-NAME";
    rejects(bad);
}

TEST(Config, PublicLinkAddressIsValidatedAndPortDefaultsToListener) {
    auto value = minimal_config();
    value["proxy_port"] = 1234;
    value["public_host"] = "2001:db8::1";
    auto config = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(config.public_port, 1234);
    value["public_port"] = 443;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").public_port, 443);
    for (const auto* invalid : {"0.0.0.0", "::", "host/?x=1", "bad host"}) {
        value["public_host"] = invalid;
        EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    }
    value["public_host"] = "proxy.example.org";
    value["public_port"] = 0;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, RejectsUnknownOptionsInsteadOfSilentlyIgnoringThem) {
    auto value = minimal_config();
    value["use_direct"] = true;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, AdTagIsOptionalButValidatedWhenSet) {
    // Absent ad_tag is allowed and means "no sponsored channel" (all-zero).
    auto value = minimal_config();
    value.erase("ad_tag");
    const auto no_tag = mtdd::Config::parse(value, "/work");
    EXPECT_TRUE(std::all_of(no_tag.ad_tag.begin(), no_tag.ad_tag.end(),
                            [](auto b) { return b == 0; }));
    EXPECT_FALSE(no_tag.public_view()["ad_tag_set"].get<bool>());
    // When present it must be 32 hex characters and not all zero.
    value = minimal_config();
    value["ad_tag"] = "bad";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["ad_tag"] = std::string(32, '0');
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["ad_tag"] = "00112233445566778899aabbccddeefZ";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value = minimal_config();
    value["tls_domain"] = "example.org\r\nInjected: yes";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, RejectsUnboundedAndMistypedLimits) {
    for (const auto& invalid : {nlohmann::json(-1), nlohmann::json(0),
                                nlohmann::json(true), nlohmann::json(1.5)}) {
        auto value = minimal_config();
        value["max_connections"] = invalid;
        EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    }
    auto value = minimal_config();
    value["workers"] = 257;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, WorkerCountAutoByDefaultAndExplicitlyBounded) {
    EXPECT_EQ(mtdd::Config::parse(minimal_config(), "/work").workers, 0U);
    for (const auto workers : {1U, 2U, 4U}) {
        auto value = minimal_config();
        value["workers"] = workers;
        EXPECT_EQ(mtdd::Config::parse(value, "/work").workers, workers);
    }
    auto maximum = minimal_config();
    maximum["workers"] = 256;
    maximum["max_frame_bytes"] = 4096;
    maximum["connection_queue_bytes"] = 4096;
    maximum["global_buffer_bytes"] = 256 * (2 * 4096 + 2 * 4096 + 65536);
    EXPECT_EQ(mtdd::Config::parse(maximum, "/work").workers, 256U);
    auto value = minimal_config();
    value["workers"] = -1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, MeConnectionsPerDcIsBounded) {
    EXPECT_EQ(mtdd::Config::parse(minimal_config(), "/work").me_connections_per_dc, 16U);
    for (const auto connections : {1U, 4U, 8U, 12U, 13U, 24U}) {
        auto value = minimal_config();
        value["me_connections_per_dc"] = connections;
        EXPECT_EQ(mtdd::Config::parse(value, "/work").me_connections_per_dc,
                  connections);
    }
    for (const auto invalid : {0, 25, -1}) {
        auto value = minimal_config();
        value["me_connections_per_dc"] = invalid;
        EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    }
}

TEST(Config, MeClientsPerWriterIsConfigurableAndBounded) {
    EXPECT_EQ(mtdd::Config::parse(minimal_config(), "/work").me_clients_per_writer, 400U);
    auto value = minimal_config();
    value["me_clients_per_writer"] = 42;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").me_clients_per_writer, 42U);
    value["me_clients_per_writer"] = 0;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, ClientLivenessTimeoutsHaveDefaultsAndBounds) {
    const auto defaults = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_EQ(defaults.client_keepalive.count(), 60);
    EXPECT_EQ(defaults.client_ack_timeout.count(), 90);
    auto value = minimal_config();
    value["client_keepalive_seconds"] = 0;
    value["client_ack_timeout_seconds"] = 0;
    const auto disabled = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(disabled.client_keepalive.count(), 0);
    EXPECT_EQ(disabled.client_ack_timeout.count(), 0);
    value["client_ack_timeout_seconds"] = 5;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["client_ack_timeout_seconds"] = 3601;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["client_ack_timeout_seconds"] = 30;
    value["client_keepalive_seconds"] = -1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, ExplicitWorkersRequirePerReactorBufferBudget) {
    auto value = minimal_config();
    value["workers"] = 4;
    value["max_frame_bytes"] = 4096;
    value["connection_queue_bytes"] = 4096;
    value["global_buffer_bytes"] = 4 * (2 * 4096 + 2 * 4096 + 65536) - 1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["global_buffer_bytes"] = 4 * (2 * 4096 + 2 * 4096 + 65536);
    EXPECT_NO_THROW(mtdd::Config::parse(value, "/work"));
}

TEST(Config, RemoteControlRequiresExplicitOptIn) {
    auto value = minimal_config();
    value["control_host"] = "0.0.0.0";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["allow_remote_control"] = true;
    EXPECT_NO_THROW(mtdd::Config::parse(value, "/work"));
}

TEST(Config, RejectsListenerCollisionsIncludingWildcardBindings) {
    auto value = minimal_config();
    value["proxy_port"] = 9090;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["proxy_host"] = "0.0.0.0";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["proxy_host"] = "::";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, ExplicitConnectionAndHandshakeCapsAreIndependent) {
    auto value = minimal_config();
    value["max_connections"] = 1;
    auto parsed = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(parsed.max_connections, 1U);
    EXPECT_EQ(parsed.max_handshakes, 0U);
    value["max_handshakes"] = 3;
    parsed = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(parsed.max_connections, 1U);
    EXPECT_EQ(parsed.max_handshakes, 3U);
}

TEST(Config, ServerHelloDelayIsOffByDefaultAndBounded) {
    const auto defaults = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_EQ(defaults.server_hello_delay_min.count(), 0);
    EXPECT_EQ(defaults.server_hello_delay_max.count(), 0);
    EXPECT_EQ(defaults.public_view()["server_hello_delay_max_ms"].get<std::int64_t>(), 0);

    auto value = minimal_config();
    value["server_hello_delay_min_ms"] = 8;
    value["server_hello_delay_max_ms"] = 24;
    const auto parsed = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(parsed.server_hello_delay_min, std::chrono::milliseconds(8));
    EXPECT_EQ(parsed.server_hello_delay_max, std::chrono::milliseconds(24));
    EXPECT_EQ(parsed.public_view()["server_hello_delay_min_ms"].get<std::int64_t>(), 8);
    EXPECT_EQ(parsed.public_view()["server_hello_delay_max_ms"].get<std::int64_t>(), 24);

    value["server_hello_delay_max_ms"] = 1000;
    EXPECT_NO_THROW(mtdd::Config::parse(value, "/work"));
    value["server_hello_delay_max_ms"] = 1001;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["server_hello_delay_max_ms"] = 5;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument) << "min > max";
    value["server_hello_delay_max_ms"] = -1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value.erase("server_hello_delay_max_ms");
    EXPECT_EQ(mtdd::Config::parse(value, "/work").server_hello_delay_max,
              std::chrono::milliseconds(8))
        << "a minimum alone is a fixed delay";
    value["server_hello_delay_min_ms"] = 1001;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, RequiresEnoughGlobalMemoryForOneMaximumFrameAndQueues) {
    auto value = minimal_config();
    value["global_buffer_bytes"] = 262144;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, FallbackDefaultsDisabledAndAcceptsFixedLoopback) {
    const auto defaults = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_EQ(defaults.fallback_host, "127.0.0.1");
    EXPECT_EQ(defaults.fallback_port, 0);
    EXPECT_TRUE(defaults.masking);
    auto value = minimal_config();
    value["fallback_port"] = 18443;
    auto parsed = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(parsed.fallback_host, "127.0.0.1");
    EXPECT_EQ(parsed.fallback_port, 18443);
    value["fallback_host"] = "::1";
    EXPECT_EQ(mtdd::Config::parse(value, "/work").fallback_host, "::1");
}

TEST(Config, FallbackAcceptsRemoteMaskingTargets) {
    for (const auto* host : {"1.1.1.1", "::1", "127.0.0.1", "github.com", "localhost",
                             "127.0.0.1.example.org"}) {
        auto value = minimal_config();
        value["fallback_host"] = host;
        value["fallback_port"] = 18443;
        EXPECT_EQ(mtdd::Config::parse(value, "/work").fallback_host, host);
    }
}

TEST(Config, FallbackRejectsWildcardAndListenerPorts) {
    for (const auto* host : {"0.0.0.0", "::", "-bad.example.org", "bad_.example.org"}) {
        auto value = minimal_config();
        value["fallback_host"] = host;
        value["fallback_port"] = 18443;
        EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    }
    for (const auto& port : {nlohmann::json(-1), nlohmann::json(65536), nlohmann::json(true),
                            nlohmann::json(1.5), nlohmann::json(14443), nlohmann::json(9090)}) {
        auto value = minimal_config();
        value["fallback_port"] = port;
        EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    }
}

TEST(Config, MaskingToggleParsesAndRejectsNonBoolean) {
    auto value = minimal_config();
    value["masking"] = false;
    EXPECT_FALSE(mtdd::Config::parse(value, "/work").masking);
    value["masking"] = "off";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, UniqueIpHistoryPathIsOptionalResolvedAndSeparateFromUsers) {
    EXPECT_TRUE(mtdd::Config::parse(minimal_config(), "/work").unique_ip_stats_path.empty());
    auto value = minimal_config();
    value["unique_ip_stats_path"] = "stats/unique-ips.json";
    EXPECT_EQ(mtdd::Config::parse(value, "/work").unique_ip_stats_path,
              "/work/stats/unique-ips.json");
    value["unique_ip_stats_path"] = "users.json";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["unique_ip_stats_path"] = 123;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["unique_ip_stats_path"] = "";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, ClientClockSkewDefaultsTo120AndIsRangeChecked) {
    EXPECT_EQ(mtdd::Config::parse(minimal_config(), "/work").client_clock_skew_seconds, 120U);
    auto value = minimal_config();
    value["client_clock_skew_seconds"] = 0;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").client_clock_skew_seconds, 0U);
    value["client_clock_skew_seconds"] = 600;
    const auto parsed = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(parsed.client_clock_skew_seconds, 600U);
    EXPECT_EQ(parsed.public_view().at("client_clock_skew_seconds"), 600);
    value["client_clock_skew_seconds"] = 86400;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").client_clock_skew_seconds, 86400U);
    value["client_clock_skew_seconds"] = 86401;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["client_clock_skew_seconds"] = -1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["client_clock_skew_seconds"] = "120";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Config, UniqueIpMinBytesDefaultsToOneMiBAndIsRangeChecked) {
    EXPECT_EQ(mtdd::Config::parse(minimal_config(), "/work").unique_ip_min_bytes, 1048576U);
    auto value = minimal_config();
    value["unique_ip_min_bytes"] = 0;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").unique_ip_min_bytes, 0U);
    value["unique_ip_min_bytes"] = 1ULL << 40;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").unique_ip_min_bytes, 1ULL << 40);
    value["unique_ip_min_bytes"] = (1ULL << 40) + 1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["unique_ip_min_bytes"] = -1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
    value["unique_ip_min_bytes"] = "100";
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

TEST(Metadata, ParsesSignedDcRoutesAndDeduplicates) {
    const auto endpoints = mtdd::parse_me_config(
        "# comment\ndefault 2;\nproxy_for 2 149.154.167.91:8888;\n"
        "proxy_for -2 [2001:db8::1]:443;\nproxy_for 2 149.154.167.91:8888;\n");
    ASSERT_EQ(endpoints.size(), 2U);
    EXPECT_EQ(endpoints[0].dc, 2);
    EXPECT_EQ(endpoints[1].dc, -2);
    EXPECT_EQ(endpoints[1].host, "2001:db8::1");
}

TEST(Metadata, RejectsMalformedAndEmptyRoutes) {
    for (const auto* bad : {"", "proxy_for 0 127.0.0.1:443;",
                            "proxy_for 2 localhost:443;", "proxy_for 2 1.2.3.4:0;",
                            "proxy_for 2 1.2.3.4:443; surprise 5;"}) {
        EXPECT_THROW(mtdd::parse_me_config(bad), std::invalid_argument);
    }
}

class ConfigFiles : public ::testing::Test {
protected:
    void SetUp() override {
        auto pattern = (std::filesystem::temp_directory_path() / "mtdd-config-XXXXXX").string();
        const auto* created = ::mkdtemp(pattern.data());
        ASSERT_NE(created, nullptr);
        directory = created;
    }
    void TearDown() override { std::filesystem::remove_all(directory); }
    void write(const char* name, const std::string& bytes) {
        std::ofstream file(directory / name, std::ios::binary);
        file << bytes;
        ASSERT_TRUE(file.good());
    }
    mtdd::Config metadata_config() {
        auto config = mtdd::Config::parse(minimal_config(), directory);
        config.me_config_path = directory / "me.conf";
        config.me_secret_path = directory / "me.secret";
        return config;
    }
    std::filesystem::path directory;
};

TEST_F(ConfigFiles, LoadResolvesPathsAndRejectsInvalidOrOversizedFiles) {
    write("config.json", minimal_config().dump());
    EXPECT_EQ(mtdd::Config::load(directory / "config.json").users_path, directory / "users.json");
    write("config.json", "{");
    EXPECT_THROW(mtdd::Config::load(directory / "config.json"), std::invalid_argument);
    write("config.json", std::string(65537, ' '));
    EXPECT_THROW(mtdd::Config::load(directory / "config.json"), std::invalid_argument);
    EXPECT_THROW(mtdd::Config::load(directory / "absent.json"), std::runtime_error);
}

TEST_F(ConfigFiles, MetadataUsesBoundedRegularFilesOnly) {
    const auto config = metadata_config();
    write("me.conf", "default 2; proxy_for 2 127.0.0.1:8888;");
    write("me.secret", std::string(128, '\x42'));
    const auto result = mtdd::load_me_metadata(config);
    ASSERT_EQ(result.endpoints.size(), 1U);
    EXPECT_EQ(result.secret.size(), 128U);
    write("me.secret", "short");
    EXPECT_THROW(mtdd::load_me_metadata(config), std::invalid_argument);
    std::filesystem::remove(config.me_config_path);
    ASSERT_EQ(::mkfifo(config.me_config_path.c_str(), 0600), 0);
    EXPECT_THROW(mtdd::load_me_metadata(config), std::runtime_error);
    std::filesystem::remove(config.me_config_path);
    std::filesystem::create_symlink(directory / "me.secret", config.me_config_path);
    EXPECT_THROW(mtdd::load_me_metadata(config), std::runtime_error);
}

TEST_F(ConfigFiles, CancelledMetadataLoadDoesNotStartIO) {
    std::stop_source stop;
    stop.request_stop();
    EXPECT_THROW(mtdd::load_me_metadata(metadata_config(), stop.get_token()), std::runtime_error);
}

TEST_F(ConfigFiles, Ipv6MetadataIsOptionalAndNeverCostsIpv4Routes) {
    auto config = metadata_config();
    write("me.conf", "default 2; proxy_for 2 127.0.0.1:8888;");
    write("me.secret", std::string(128, '\x42'));
    // Local IPv4 metadata without a local IPv6 file: no IPv6 list, no download.
    auto result = mtdd::load_me_metadata(config);
    EXPECT_EQ(result.endpoints.size(), 1U);
    EXPECT_TRUE(result.endpoints_v6.empty());

    config.me_config_v6_path = directory / "me6.conf";
    write("me6.conf", "default 2; proxy_for 2 [2001:b28:f23d:f001::d]:8888;\n"
                      "proxy_for -2 [2001:67c:4e8:f002::d]:80;");
    result = mtdd::load_me_metadata(config);
    ASSERT_EQ(result.endpoints_v6.size(), 2U);
    EXPECT_EQ(result.endpoints_v6[0].host, "2001:b28:f23d:f001::d");
    EXPECT_EQ(result.endpoints_v6[1].dc, -2);
    EXPECT_EQ(result.endpoints.size(), 1U);

    // A broken IPv6 list keeps the previous one (or none) and the IPv4 routes.
    const auto previous = result.endpoints_v6;
    write("me6.conf", "proxy_for 2 nonsense;");
    result = mtdd::load_me_metadata(config, {}, &previous);
    EXPECT_EQ(result.endpoints.size(), 1U);
    EXPECT_EQ(result.endpoints_v6, previous);
    result = mtdd::load_me_metadata(config);
    EXPECT_EQ(result.endpoints.size(), 1U);
    EXPECT_TRUE(result.endpoints_v6.empty());
    std::filesystem::remove(config.me_config_v6_path);
    result = mtdd::load_me_metadata(config, {}, &previous);
    EXPECT_EQ(result.endpoints_v6, previous);

    // "off" never reads the IPv6 list.
    write("me6.conf", "proxy_for 2 [2001:db8::1]:443;");
    config.me_ipv6 = mtdd::Config::MeIpv6::off;
    EXPECT_TRUE(mtdd::load_me_metadata(config).endpoints_v6.empty());
    // The IPv4 list stays mandatory in every mode.
    config.me_ipv6 = mtdd::Config::MeIpv6::on;
    write("me.conf", "");
    EXPECT_THROW(mtdd::load_me_metadata(config), std::invalid_argument);
}
} // namespace

TEST(Config, MeWriterCapDefaultsOffAndIsBounded) {
    auto value = minimal_config();
    auto config = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(config.me_connections_per_dc_total, 0U);
    EXPECT_EQ(config.public_view()["me_connections_per_dc_total"], 0U);
    for (const std::uint32_t valid : {0U, 1U, 64U, 1024U}) {
        value["me_connections_per_dc_total"] = valid;
        EXPECT_EQ(mtdd::Config::parse(value, "/work").me_connections_per_dc_total, valid);
    }
    value["me_connections_per_dc_total"] = 48;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").public_view()["me_connections_per_dc_total"], 48U);
    for (const auto* invalid : {"1025", "-1", "\"8\"", "1.5"}) {
        auto bad = value;
        bad["me_connections_per_dc_total"] = nlohmann::json::parse(invalid);
        EXPECT_THROW(mtdd::Config::parse(bad, "/work"), std::invalid_argument) << invalid;
    }
}

TEST(Config, MeIpv6ModesAndLocalIpv6List) {
    auto value = minimal_config();
    auto config = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(config.me_ipv6, mtdd::Config::MeIpv6::automatic);
    EXPECT_TRUE(config.me_config_v6_path.empty());
    EXPECT_EQ(config.public_view()["me_ipv6"], "auto");
    value["me_ipv6"] = "on";
    EXPECT_EQ(mtdd::Config::parse(value, "/work").me_ipv6, mtdd::Config::MeIpv6::on);
    value["me_ipv6"] = "off";
    config = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(config.me_ipv6, mtdd::Config::MeIpv6::off);
    EXPECT_EQ(config.public_view()["me_ipv6"], "off");
    value["me_ipv6"] = "auto";
    value["me_config_v6_path"] = "me6.txt";
    config = mtdd::Config::parse(value, "/work");
    EXPECT_EQ(config.me_config_v6_path, std::filesystem::path("/work/me6.txt"));
    EXPECT_EQ(config.public_view()["me_config_v6_path"], "/work/me6.txt");
    for (const auto* patch : {R"({"me_ipv6": "yes"})", R"({"me_ipv6": true})",
                              R"({"me_ipv6": "off", "me_config_v6_path": "me6.txt"})",
                              R"({"me_config_v6_path": "x.bin", "unique_ip_stats_path": "x.bin"})",
                              R"({"me_config_v6_path": "q.json", "usage_state_path": "q.json"})"}) {
        auto bad = minimal_config();
        bad.update(nlohmann::json::parse(patch));
        EXPECT_THROW(mtdd::Config::parse(bad, "/work"), std::invalid_argument) << patch;
    }
}

TEST(Config, DirectFallbackIsOptInAndOnlyAcceptsSignedDcOneToFive) {
    auto value = minimal_config();
    auto config = mtdd::Config::parse(value, "/work");
    EXPECT_FALSE(config.direct_fallback_enabled);
    EXPECT_TRUE(config.direct_fallback_dcs.empty());

    value["direct_fallback_enabled"] = true;
    value["direct_fallback_dcs"] = {1, 2, -2, 5};
    config = mtdd::Config::parse(value, "/work");
    EXPECT_TRUE(config.direct_fallback_enabled);
    ASSERT_EQ(config.direct_fallback_dcs.size(), 4U);
    EXPECT_EQ(config.direct_fallback_dcs[2], -2);

    for (const auto invalid : {0, 6, -6, 203, -203}) {
        auto bad = value;
        bad["direct_fallback_dcs"] = {invalid};
        EXPECT_THROW(mtdd::Config::parse(bad, "/work"), std::invalid_argument)
            << "direct DC " << invalid;
    }
    auto duplicate = value;
    duplicate["direct_fallback_dcs"] = {2, 2};
    EXPECT_THROW(mtdd::Config::parse(duplicate, "/work"), std::invalid_argument);
    auto not_array = value;
    not_array["direct_fallback_dcs"] = 2;
    EXPECT_THROW(mtdd::Config::parse(not_array, "/work"), std::invalid_argument);
}

TEST(Config, PublicViewOmitsAdTagAndReportsPosture) {
    mtdd::Config config;
    config.ad_tag[0] = 0xab;
    config.api_token_env = "MTDD_API_TOKEN";
    const auto view = config.public_view();
    EXPECT_EQ(view["ad_tag_set"], true);
    EXPECT_FALSE(view.contains("ad_tag"));
    EXPECT_EQ(view["api_token_env"], "MTDD_API_TOKEN");
    const auto posture = config.security_posture();
    EXPECT_EQ(posture["api"]["loopback_only"], true);
    EXPECT_EQ(posture["metrics"]["enabled"], true);
    EXPECT_EQ(posture["metrics"]["token"], false);
    config.metrics_port = 0;
    EXPECT_TRUE(config.security_posture()["metrics"]["host"].is_null());
}

namespace {

// Builds a fake /proc + /sys tree under a fresh temporary directory.
class MemoryRoot {
public:
    MemoryRoot() {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "mtdd-memory-XXXXXX").string();
        const char* made = ::mkdtemp(pattern.data());
        if (made == nullptr) throw std::runtime_error("mkdtemp failed");
        root_ = made;
    }
    ~MemoryRoot() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }
    MemoryRoot(const MemoryRoot&) = delete;
    MemoryRoot& operator=(const MemoryRoot&) = delete;

    void write(const std::string& relative, const std::string& text) const {
        const auto path = root_ / relative;
        std::filesystem::create_directories(path.parent_path());
        std::ofstream(path) << text;
    }
    const std::filesystem::path& path() const { return root_; }

private:
    std::filesystem::path root_;
};

constexpr std::uint64_t kGiB = 1ULL << 30;

} // namespace

TEST(Config, DefaultBufferBudgetIsAQuarterOfMemoryWithinBounds) {
    EXPECT_EQ(mtdd::default_global_buffer_bytes(0), 256ULL << 20);
    EXPECT_EQ(mtdd::default_global_buffer_bytes(128ULL << 20), 64ULL << 20);
    EXPECT_EQ(mtdd::default_global_buffer_bytes(16 * kGiB), 4 * kGiB);
    EXPECT_EQ(mtdd::default_global_buffer_bytes(1024 * kGiB), mtdd::kMaxGlobalBufferBytes);
}

TEST(Config, MemoryLimitIsMemTotalWithoutCgroupLimits) {
    MemoryRoot root;
    root.write("proc/meminfo", "MemFree:  1000 kB\nMemTotal:  8388608 kB\n");
    root.write("proc/self/cgroup", "0::/system.slice/mtdd.service\n");
    root.write("sys/fs/cgroup/system.slice/mtdd.service/memory.max", "max\n");
    EXPECT_EQ(mtdd::detect_memory_limit_bytes(root.path()), 8 * kGiB);
}

TEST(Config, MemoryLimitHonoursTheTightestCgroupOnThePath) {
    MemoryRoot root;
    root.write("proc/meminfo", "MemTotal:  16777216 kB\n");
    root.write("proc/self/cgroup", "0::/system.slice/mtdd.service\n");
    // The unit's own MemoryMax= and a looser ancestor limit.
    root.write("sys/fs/cgroup/system.slice/mtdd.service/memory.max", "2147483648\n");
    root.write("sys/fs/cgroup/system.slice/memory.max", "4294967296\n");
    EXPECT_EQ(mtdd::detect_memory_limit_bytes(root.path()), 2 * kGiB);
    // An ancestor tighter than the leaf wins as well (container limit).
    root.write("sys/fs/cgroup/system.slice/memory.max", "1073741824\n");
    EXPECT_EQ(mtdd::detect_memory_limit_bytes(root.path()), 1 * kGiB);
}

TEST(Config, MemoryLimitReadsCgroupV1MemoryController) {
    MemoryRoot root;
    root.write("proc/meminfo", "MemTotal:  16777216 kB\n");
    root.write("proc/self/cgroup", "4:cpu,cpuacct:/docker/abc\n3:memory:/docker/abc\n");
    root.write("sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes", "3221225472\n");
    EXPECT_EQ(mtdd::detect_memory_limit_bytes(root.path()), 3 * kGiB);
}

TEST(Config, MemoryLimitStaysInsideTheMountedHierarchy) {
    MemoryRoot root;
    root.write("proc/meminfo", "MemTotal:  16777216 kB\n");
    // A cgroup namespace can report a path above its root; nothing outside
    // sys/fs/cgroup may be read.
    root.write("proc/self/cgroup", "0::/../../outside\n");
    root.write("sys/fs/outside/memory.max", "1048576\n");
    root.write("sys/fs/cgroup/memory.max", "max\n");
    EXPECT_EQ(mtdd::detect_memory_limit_bytes(root.path()), 16 * kGiB);
}

TEST(Config, MemoryLimitIsUnknownWithoutMeminfo) {
    MemoryRoot root;
    EXPECT_EQ(mtdd::detect_memory_limit_bytes(root.path()), 0U);
}

TEST(Config, OmittedBufferBudgetIsDerivedAndMarkedAuto) {
    const auto derived = mtdd::Config::parse(minimal_config(), "/work");
    EXPECT_TRUE(derived.global_buffer_auto);
    EXPECT_EQ(derived.global_buffer_bytes,
              mtdd::default_global_buffer_bytes(mtdd::detect_memory_limit_bytes()));
    auto value = minimal_config();
    value["global_buffer_bytes"] = 64U << 20;
    const auto explicit_value = mtdd::Config::parse(value, "/work");
    EXPECT_FALSE(explicit_value.global_buffer_auto);
    EXPECT_EQ(explicit_value.global_buffer_bytes, 64U << 20);
}

TEST(Config, AutoBufferBudgetCoversExplicitWorkers) {
    // 256 reactors need far more than a quarter of a small host: the derived
    // budget grows to the per-reactor minimum instead of failing the config.
    auto value = minimal_config();
    value["workers"] = 256;
    const auto config = mtdd::Config::parse(value, "/work");
    EXPECT_GE(config.global_buffer_bytes / 256,
              2 * config.max_frame_bytes + 2 * config.connection_queue_bytes + 65536);
}

TEST(Config, BufferBudgetAcceptsMoreThanOneGibibyte) {
    auto value = minimal_config();
    value["global_buffer_bytes"] = 8 * kGiB;
    EXPECT_EQ(mtdd::Config::parse(value, "/work").global_buffer_bytes, 8 * kGiB);
    value["global_buffer_bytes"] = mtdd::kMaxGlobalBufferBytes + 1;
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
}

#include "mtdd/config.hpp"
#include "mtdd/metadata.hpp"

#include <gtest/gtest.h>
#include <fstream>
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

TEST(Config, RequiresExplicitAdTagAndValidDomain) {
    auto value = minimal_config();
    value.erase("ad_tag");
    EXPECT_THROW(mtdd::Config::parse(value, "/work"), std::invalid_argument);
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
} // namespace

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

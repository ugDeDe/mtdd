#include "../support/fake_socks5.hpp"
#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// Outbound upstreams (Config::upstreams): ME, Direct and masking connections
// through a SOCKS5 proxy or from a chosen source address.
// ---------------------------------------------------------------------------

namespace {

using mtdd::UpstreamConfig;
using mtdd::test::FakeSocks5;

UpstreamConfig socks_upstream(const FakeSocks5& socks, std::string user = {}, std::string pass = {}) {
    UpstreamConfig upstream;
    upstream.name = "socks";
    upstream.type = UpstreamConfig::Type::socks5;
    upstream.host = "127.0.0.1";
    upstream.port = socks.port();
    upstream.username = std::move(user);
    upstream.password = std::move(pass);
    return upstream;
}

bool has_port(const std::vector<std::uint16_t>& ports, std::uint16_t port) {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

struct UpDirectScope {
    explicit UpDirectScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~UpDirectScope() { mtdd::detail::set_direct_endpoint_override(std::nullopt); }
    UpDirectScope(const UpDirectScope&) = delete;
    UpDirectScope& operator=(const UpDirectScope&) = delete;
};

struct UpMaskingScope {
    explicit UpMaskingScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~UpMaskingScope() { mtdd::detail::set_masking_endpoint_override(std::nullopt); }
    UpMaskingScope(const UpMaskingScope&) = delete;
    UpMaskingScope& operator=(const UpMaskingScope&) = delete;
};

// One ME relay round: the fake ME derives its keys from the address it sees,
// so a completed relay proves the key derivation used the proxy's exit.
void expect_me_relay(Daemon& daemon, FakeMe& me) {
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const Bytes request = burst_payload(0);
    ASSERT_TRUE(client.send_message(request));
    ASSERT_EQ(me.future().wait_for(5s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    EXPECT_EQ(observation.inner, request);
    Bytes response;
    ASSERT_TRUE(client.read_message(response));
    EXPECT_EQ(response, (Bytes{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}));
}

}  // namespace

TEST(Upstream, MiddleEndRelaysThroughSocks5) {
    FakeSocks5 socks;
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [&](mtdd::Config& config) {
        config.upstreams = {socks_upstream(socks)};
    });
    expect_me_relay(daemon, me);
    EXPECT_GE(socks.connects(), 1U);
    EXPECT_TRUE(has_port(socks.target_ports(), me.port()));
}

TEST(Upstream, MiddleEndRelaysThroughSocks5WithPassword) {
    FakeSocks5 socks(FakeSocks5::Options{"mtdd", "s3cret", 0});
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [&](mtdd::Config& config) {
        config.upstreams = {socks_upstream(socks, "mtdd", "s3cret")};
    });
    expect_me_relay(daemon, me);
    EXPECT_EQ(socks.auth_failures(), 0U);
}

TEST(Upstream, RefusedSocks5KeepsTheMiddleEndDown) {
    for (const bool wrong_password : {true, false}) {
        SCOPED_TRACE(wrong_password ? "wrong password" : "connect refused");
        FakeSocks5 socks(wrong_password ? FakeSocks5::Options{"mtdd", "right", 0}
                                        : FakeSocks5::Options{"", "", 5});
        FakeMe me{me_secret()};
        Daemon daemon(me.port(), true, [&](mtdd::Config& config) {
            config.upstreams = {wrong_password ? socks_upstream(socks, "mtdd", "wrong")
                                               : socks_upstream(socks)};
        });
        ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
        ASSERT_TRUE(wait_for([&] {
            return wrong_password ? socks.auth_failures() >= 1U : socks.connects() >= 1U;
        }, 5s));
        std::this_thread::sleep_for(300ms);
        EXPECT_FALSE(daemon.services.stats.ready());
    }
}

TEST(Upstream, BindAddressIsTheMiddleEndSourceAddress) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [&](mtdd::Config& config) {
        UpstreamConfig upstream;
        upstream.bind_address = "127.0.0.2";
        config.upstreams = {upstream};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    ASSERT_EQ(me.future().wait_for(5s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    ASSERT_TRUE(observation.saw_sender_pid);
    // Reversed IPv4 octets of the source address: 127.0.0.2.
    EXPECT_EQ(observation.sender_pid[0], 2);
    EXPECT_EQ(observation.sender_pid[3], 127);
}

TEST(Upstream, DirectDcRelaysThroughSocks5) {
    FakeSocks5 socks;
    mtdd::test::FakeDirectDc dc(2);
    UpDirectScope endpoint(dc.port());
    Daemon daemon(1, true, [&](mtdd::Config& config) {
        config.direct_fallback_enabled = true;
        config.direct_fallback_dcs = {2};
        config.upstreams = {socks_upstream(socks)};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const Bytes payload(96, 0x42);
    ASSERT_TRUE(client.send_message(payload));
    Bytes echoed;
    ASSERT_TRUE(client.read_message(echoed));
    EXPECT_EQ(echoed, payload);
    EXPECT_TRUE(has_port(socks.target_ports(), dc.port()));
}

TEST(Upstream, MaskingUsesItsOwnScope) {
    FakeSocks5 socks;
    EchoBackend echo;
    UpMaskingScope scope(echo.port());
    Daemon daemon(1, false, [&](mtdd::Config& config) {
        config.masking = true;
        UpstreamConfig plain;  // Telegram traffic: the default scope
        UpstreamConfig masked = socks_upstream(socks);
        masked.scopes = {"mask"};
        config.upstreams = {plain, masked};
        config.masking_scope = "mask";
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    A16 wrong{};
    wrong.fill(0xaa);
    const Bytes probe = make_client_hello(wrong, current_timestamp(), kDomain, 1);
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, probe));
    Bytes echoed(probe.size());
    EXPECT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
    EXPECT_EQ(echoed, probe);
    ::close(fd);
    EXPECT_EQ(socks.connects(), 1U);
    EXPECT_TRUE(has_port(socks.target_ports(), echo.port()));
}

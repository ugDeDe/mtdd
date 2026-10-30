#include "../support/runtime_fixture.hpp"

namespace {

TEST(Runtime, UniqueIpsSameIpMultiplePortsAndGenerationClose) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{10};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient first(daemon.port(), secret_bytes());
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(first.send_hello(0, 11));
    ASSERT_TRUE(second.send_hello(0, 12));
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().active_unique_ips == 1; }, 2000ms));
    {
        const auto snapshot = daemon.services.stats.snapshot();
        ASSERT_NE(snapshot.users.find("alice"), snapshot.users.end());
        EXPECT_EQ(snapshot.users.at("alice").active_connections, 2U);
        EXPECT_EQ(snapshot.users.at("alice").unique_ips_active, 1U);
    }
    first.close();
    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto user = snapshot.users.find("alice");
            return snapshot.active_unique_ips == 1 && user != snapshot.users.end() &&
                   user->second.active_connections == 1;
        },
        2000ms));
    second.close();
    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto user = snapshot.users.find("alice");
            return snapshot.active_unique_ips == 0 && user != snapshot.users.end() &&
                   user->second.unique_ips_active == 0 &&
                   user->second.active_connections == 0;
        },
        2000ms));
}

TEST(Runtime, UniqueIpsDifferentSourceIpsShareAcrossUsers) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{10};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(daemon.services.add_user("bob", std::string("101112131415161718191a1b1c1d1e1f")));

    TestClient local(daemon.port(), secret_bytes());
    ASSERT_TRUE(local.valid());
    const int foreign_fd = connect_loopback_from(daemon.port(), "127.0.0.2");
    ASSERT_GE(foreign_fd, 0);
    TestClient foreign(TestClient::Adopt{}, foreign_fd, bob_secret_bytes());
    ASSERT_TRUE(foreign.valid());
    ASSERT_TRUE(local.send_hello(0, 21));
    ASSERT_TRUE(foreign.send_hello(0, 22));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().active_unique_ips == 2; },
                         2000ms));
    {
        const auto snapshot = daemon.services.stats.snapshot();
        ASSERT_NE(snapshot.users.find("alice"), snapshot.users.end());
        ASSERT_NE(snapshot.users.find("bob"), snapshot.users.end());
        EXPECT_EQ(snapshot.users.at("alice").unique_ips_active, 1U);
        EXPECT_EQ(snapshot.users.at("bob").unique_ips_active, 1U);
    }
    local.close();
    foreign.close();
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().active_unique_ips == 0; },
                         2000ms));
}

TEST(Runtime, UniqueIpsSharedIpAcrossUsersIsGlobalOncePerUserOnce) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{10};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(daemon.services.add_user("bob", std::string("101112131415161718191a1b1c1d1e1f")));
    TestClient alice(daemon.port(), secret_bytes());
    TestClient bob(daemon.port(), bob_secret_bytes());
    ASSERT_TRUE(alice.valid());
    ASSERT_TRUE(bob.valid());
    ASSERT_TRUE(alice.send_hello(0, 31));
    ASSERT_TRUE(bob.send_hello(0, 32));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().active_unique_ips == 1; },
                         2000ms));
    const auto snapshot = daemon.services.stats.snapshot();
    ASSERT_NE(snapshot.users.find("alice"), snapshot.users.end());
    ASSERT_NE(snapshot.users.find("bob"), snapshot.users.end());
    EXPECT_EQ(snapshot.users.at("alice").unique_ips_active, 1U);
    EXPECT_EQ(snapshot.users.at("bob").unique_ips_active, 1U);
    alice.close();
    bob.close();
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().active_unique_ips == 0; },
                         2000ms));
}

TEST(Runtime, UniqueIpKeyNormalizesIpv4MappedAndKeepsNativeV6Distinct) {
    const auto v4 = mtdd::protocol::Endpoint::v4({127, 0, 0, 1}, 1234).wire20();
    const auto mapped = mtdd::protocol::Endpoint::v6(
                            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}, 4321)
                            .wire20();
    const auto v4_other_port =
        mtdd::protocol::Endpoint::v4({127, 0, 0, 1}, 9999).wire20();
    const auto native =
        mtdd::protocol::Endpoint::v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 1)
            .wire20();
    EXPECT_TRUE(std::equal(v4.begin(), v4.begin() + 16, mapped.begin()));
    EXPECT_TRUE(std::equal(v4.begin(), v4.begin() + 16, v4_other_port.begin()));
    EXPECT_FALSE(std::equal(v4.begin(), v4.begin() + 16, native.begin()));
}

TEST(Runtime, UniqueIpCollapseKeepsIpv4AndMappedAndTruncatesIpv6ToSlash64) {
    using mtdd::detail::collapse_ip_key;
    using mtdd::detail::IpKey;
    const auto key_of = [](const std::array<std::uint8_t, 16>& address) {
        const auto wire = mtdd::protocol::Endpoint::v6(address, 1).wire20();
        IpKey key{};
        std::copy_n(wire.begin(), key.size(), key.begin());
        return collapse_ip_key(key);
    };
    // Same /64, different interface identifiers (privacy-address rotation).
    const std::array<std::uint8_t, 16> a{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8};
    auto b = a;
    b[8] = 0xfe;
    b[15] = 0x99;
    auto other_prefix = a;
    other_prefix[7] = 3;
    EXPECT_EQ(key_of(a), key_of(b));
    EXPECT_NE(key_of(a), key_of(other_prefix));
    // The collapsed key keeps the /64 and zeroes the host half.
    const IpKey collapsed = key_of(a);
    EXPECT_TRUE(std::equal(a.begin(), a.begin() + 8, collapsed.begin()));
    EXPECT_TRUE(std::all_of(collapsed.begin() + 8, collapsed.end(),
                            [](std::uint8_t byte) { return byte == 0; }));
    // IPv4 and IPv4-mapped addresses are untouched, so /32 hosts stay distinct.
    const auto v4a = mtdd::protocol::Endpoint::v4({192, 0, 2, 1}, 1).wire20();
    const auto v4b = mtdd::protocol::Endpoint::v4({192, 0, 2, 2}, 1).wire20();
    IpKey ka{};
    IpKey kb{};
    std::copy_n(v4a.begin(), ka.size(), ka.begin());
    std::copy_n(v4b.begin(), kb.size(), kb.begin());
    EXPECT_EQ(collapse_ip_key(ka), ka);
    EXPECT_NE(collapse_ip_key(ka), collapse_ip_key(kb));
}

// A handshake alone counts as "seen" but not "active" (default 1 MiB).
TEST(Runtime, UniqueIpHandshakeOnlyIsSeenButNotActive) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{10};
    }, true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().unique_ip_history.hour == 1; }, 2000ms));
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_EQ(snapshot.unique_ip_min_bytes, 1048576U);
    EXPECT_EQ(snapshot.active_unique_ips, 1U);
    EXPECT_EQ(snapshot.qualified_unique_ips, 0U);
    EXPECT_EQ(snapshot.users.at("alice").unique_ips_active, 1U);
    EXPECT_EQ(snapshot.users.at("alice").unique_ips_qualified, 0U);
    EXPECT_EQ(snapshot.unique_ip_history.day, 1U);
    EXPECT_EQ(snapshot.unique_ip_history.week, 1U);
    EXPECT_EQ(snapshot.unique_ip_history.hour_active, 0U);
    EXPECT_EQ(snapshot.unique_ip_history.day_active, 0U);
    EXPECT_EQ(snapshot.unique_ip_history.week_active, 0U);
}

// unique_ip_min_bytes == 0 means active == seen: qualified at handshake.
TEST(Runtime, UniqueIpMinBytesZeroMakesActiveEqualSeen) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{10};
        config.unique_ip_min_bytes = 0;
    }, true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().unique_ip_history.hour_active == 1; },
        2000ms));
    auto snapshot = daemon.services.stats.snapshot();
    EXPECT_EQ(snapshot.active_unique_ips, 1U);
    EXPECT_EQ(snapshot.qualified_unique_ips, 1U);
    EXPECT_EQ(snapshot.users.at("alice").unique_ips_qualified, 1U);
    EXPECT_EQ(snapshot.unique_ip_history.hour, 1U);
    EXPECT_EQ(snapshot.unique_ip_history.day_active, 1U);
    EXPECT_EQ(snapshot.unique_ip_history.week_active, 1U);
    client.close();
    ASSERT_TRUE(wait_for(
        [&] {
            const auto current = daemon.services.stats.snapshot();
            return current.active_unique_ips == 0 && current.qualified_unique_ips == 0;
        },
        2000ms));
    snapshot = daemon.services.stats.snapshot();
    EXPECT_EQ(snapshot.users.at("alice").unique_ips_qualified, 0U);
    EXPECT_EQ(snapshot.unique_ip_history.hour_active, 1U);  // history outlives the session
}

// The IP becomes active once, on the first connection that crosses the byte
// threshold; more qualified connections from the same IP do not add to it, and
// it stays active until the last qualified connection closes.
TEST(Runtime, UniqueIpBecomesActiveAfterByteThresholdExactlyOnce) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.unique_ip_min_bytes = 1;
    }, true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient first(daemon.port(), secret_bytes());
    TestClient second(daemon.port(), secret_bytes());
    TestClient idle(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(idle.valid());
    ASSERT_TRUE(first.send_hello(0, 21));
    ASSERT_TRUE(second.send_hello(0, 22));
    ASSERT_TRUE(idle.send_hello(0, 23));
    ASSERT_TRUE(first.start_obfuscation(2));
    ASSERT_TRUE(second.start_obfuscation(2));
    ASSERT_TRUE(idle.start_obfuscation(2));
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().unique_ip_history.hour == 1; }, 2000ms));
    {
        const auto snapshot = daemon.services.stats.snapshot();
        EXPECT_EQ(snapshot.active_unique_ips, 1U);
        EXPECT_EQ(snapshot.qualified_unique_ips, 0U);
        EXPECT_EQ(snapshot.unique_ip_history.hour_active, 0U);
    }

    ASSERT_TRUE(first.send_message(burst_payload(0)));
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().qualified_unique_ips == 1; }, 3000ms));
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().unique_ip_history.hour_active == 1; },
        2000ms));
    ASSERT_TRUE(second.send_message(burst_payload(1)));
    ASSERT_TRUE(first.send_message(burst_payload(2)));
    const std::uint64_t floor = burst_payload(0).size() * 3;
    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            return snapshot.users.at("alice").payload_c2s_bytes >= floor;
        },
        3000ms));
    {
        const auto snapshot = daemon.services.stats.snapshot();
        EXPECT_EQ(snapshot.active_unique_ips, 1U);
        EXPECT_EQ(snapshot.qualified_unique_ips, 1U);
        EXPECT_EQ(snapshot.users.at("alice").unique_ips_qualified, 1U);
        EXPECT_EQ(snapshot.unique_ip_history.hour_active, 1U);
        EXPECT_EQ(snapshot.unique_ip_history.day_active, 1U);
        EXPECT_EQ(snapshot.unique_ip_history.week_active, 1U);
        EXPECT_EQ(snapshot.unique_ip_history.hour, 1U);
    }

    // Closing a connection that never qualified, then one of two qualified
    // ones, must keep the IP active.
    idle.close();
    first.close();
    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            return snapshot.users.at("alice").active_connections == 1;
        },
        2000ms));
    {
        const auto snapshot = daemon.services.stats.snapshot();
        EXPECT_EQ(snapshot.qualified_unique_ips, 1U);
        EXPECT_EQ(snapshot.users.at("alice").unique_ips_qualified, 1U);
    }
    // A half-closed client with an unanswered ME request is held until
    // shutdown_timeout (2 s in the fixture), so wait past it.
    second.close();
    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            return snapshot.active_unique_ips == 0 && snapshot.qualified_unique_ips == 0;
        },
        5000ms))
        << "active=" << daemon.services.stats.snapshot().active_unique_ips
        << " qualified=" << daemon.services.stats.snapshot().qualified_unique_ips
        << " conns=" << daemon.services.stats.snapshot().users.at("alice").active_connections;
    const auto after = daemon.services.stats.snapshot();
    EXPECT_EQ(after.users.at("alice").unique_ips_qualified, 0U);
    EXPECT_EQ(after.unique_ip_history.hour_active, 1U);
    EXPECT_EQ(after.ip_history_observation_failures, 0U);
}

TEST(Runtime, UniqueIpsShutdownClearsActiveCounts) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{10};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().active_unique_ips == 1; }, 2000ms));
    daemon.stop();
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_EQ(snapshot.active_unique_ips, 0U);
    const auto user = snapshot.users.find("alice");
    if (user != snapshot.users.end()) {
        EXPECT_EQ(user->second.unique_ips_active, 0U);
    }
}


TEST(Runtime, UniqueIpsHistoryObservesAuthAdmissionsAndKeepsAfterClose) {
    Daemon daemon(1, false,
                  [](mtdd::Config& config) {
                      config.handshake_timeout = std::chrono::seconds{10};
                  },
                  true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));

    TestClient first(daemon.port(), secret_bytes());
    TestClient duplicate(daemon.port(), secret_bytes());
    const int foreign_fd = connect_loopback_from(daemon.port(), "127.0.0.2");
    ASSERT_GE(foreign_fd, 0);
    TestClient foreign(TestClient::Adopt{}, foreign_fd, secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(duplicate.valid());
    ASSERT_TRUE(foreign.valid());
    ASSERT_TRUE(first.send_hello(0, 41));
    ASSERT_TRUE(duplicate.send_hello(0, 42));
    ASSERT_TRUE(foreign.send_hello(0, 43));

    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            return snapshot.active_unique_ips == 2 &&
                   snapshot.unique_ip_history.hour == 2 &&
                   snapshot.unique_ip_history.day == 2 &&
                   snapshot.unique_ip_history.week == 2;
        },
        3000ms));
    EXPECT_EQ(daemon.services.stats.snapshot().ip_history_observation_failures, 0U);

    first.close();
    duplicate.close();
    foreign.close();
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().active_unique_ips == 0; }, 2000ms));
    const auto after = daemon.services.stats.snapshot();
    EXPECT_EQ(after.unique_ip_history.hour, 2U);
    EXPECT_EQ(after.unique_ip_history.day, 2U);
    EXPECT_EQ(after.unique_ip_history.week, 2U);
}

TEST(Runtime, FullRelayThroughFakeMiddleEnd) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

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
    EXPECT_EQ(observation.frames, 1U);
    EXPECT_EQ(observation.ad_tag, daemon.services.config.ad_tag);
    // RPC_PROXY_REQ advertises the proxy listener endpoint; the ME socket's
    // ephemeral source port is KDF-only and must never appear here.
    const auto expected_our =
        mtdd::protocol::Endpoint::v4({127, 0, 0, 1}, daemon.port()).wire20();
    EXPECT_EQ(observation.our_addr, expected_our);
    // The handshake identifies the process, not a placeholder constant.
    ASSERT_TRUE(observation.saw_sender_pid);
    const Bytes sender(observation.sender_pid.begin(), observation.sender_pid.end());
    // Reference layout: reversed IPv4 octets, outbound KDF socket port.
    EXPECT_EQ(sender[0], 1);
    EXPECT_EQ(sender[1], 0);
    EXPECT_EQ(sender[2], 0);
    EXPECT_EQ(sender[3], 127);
    EXPECT_NE(observation.peer_port, 0);
    EXPECT_EQ(rd32(sender, 4) & 0xffffu, observation.peer_port);
    EXPECT_NE(rd32(sender, 4) & 0xffffu, daemon.port());
    EXPECT_EQ(rd32(sender, 4) >> 16, static_cast<std::uint16_t>(::getpid() & 0xffff));
    EXPECT_NE(rd32(sender, 8), 0u);
    const Bytes placeholder{'I', 'P', 'I', 'P', 'P', 'R', 'P', 'D', 'T', 'I', 'M', 'E'};
    EXPECT_NE(sender, placeholder);

    Bytes response;
    ASSERT_TRUE(client.read_message(response));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);

    const auto snapshot = daemon.services.stats.snapshot();
    const auto user = snapshot.users.find("alice");
    ASSERT_NE(user, snapshot.users.end());
    EXPECT_GE(user->second.payload_c2s_bytes, request.size());
    EXPECT_GE(user->second.payload_s2c_bytes, expected.size());
    ASSERT_NE(snapshot.me_dcs.find("2"), snapshot.me_dcs.end());
    EXPECT_TRUE(snapshot.me_dcs.at("2").connected);
    EXPECT_GE(snapshot.me_dcs.at("2").requests_success, 1U);
}

// Late answers for conn ids no client owns must release the remote mapping with
// RPC_CLOSE_CONN, without touching the shared transport or live sessions.
TEST(Runtime, OrphanMiddleEndAnswersSendRemoteClose) {
    // 3 orphan answers; short idle timeout so the fake's observation finishes.
    FakeMe me{me_secret(), 1, std::chrono::milliseconds{0}, 1, std::chrono::milliseconds{0},
              std::chrono::milliseconds{0}, false, 0, 400, kBurstSize, true, 3};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const Bytes request = burst_payload(0);
    ASSERT_TRUE(client.send_message(request));

    ASSERT_EQ(me.future().wait_for(6s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    ASSERT_EQ(observation.remote_closes.size(), 3u);
    for (std::size_t i = 0; i < observation.remote_closes.size(); ++i) {
        EXPECT_EQ(observation.remote_closes[i], orphan_conn_id(i)) << "i=" << i;
    }

    // The shared transport and the live client are unaffected.
    Bytes response;
    ASSERT_TRUE(client.read_message(response));
    EXPECT_EQ(response, (Bytes{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}));

    const auto snapshot = daemon.services.stats.snapshot();
    ASSERT_NE(snapshot.me_dcs.find("2"), snapshot.me_dcs.end());
    const auto& dc = snapshot.me_dcs.at("2");
    EXPECT_TRUE(dc.connected);
    EXPECT_EQ(dc.proxy_ans_received_total, 4U);
    EXPECT_EQ(dc.proxy_ans_delivered_total, 1U);
    EXPECT_EQ(dc.proxy_ans_dropped_unknown_total, 3U);
}

// A flood of orphan answers must not become unbounded/full-rate ME control
// traffic: the per-window budget and the pending bound cap the feedback.
TEST(Runtime, OrphanMiddleEndAnswerFloodIsBounded) {
    constexpr std::size_t kOrphans = 40;
    FakeMe me{me_secret(), 1, std::chrono::milliseconds{0}, 1, std::chrono::milliseconds{0},
              std::chrono::milliseconds{0}, false, 0, 400, kBurstSize, true, kOrphans};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));

    ASSERT_EQ(me.future().wait_for(6s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    // 32 = the default per-second budget / pending bound.
    EXPECT_EQ(observation.remote_closes.size(), 32u);
    EXPECT_LE(observation.remote_closes.size(), kOrphans);

    const auto snapshot = daemon.services.stats.snapshot();
    ASSERT_NE(snapshot.me_dcs.find("2"), snapshot.me_dcs.end());
    const auto& dc = snapshot.me_dcs.at("2");
    EXPECT_EQ(dc.proxy_ans_received_total, kOrphans + 1);
    EXPECT_EQ(dc.proxy_ans_dropped_unknown_total, kOrphans);
}

// Inbound control constructors must be visible to operators: the protocol
// counters are published into the ME statistics and Prometheus text so a live
// node can be classified (which close Telegram actually sends) without guessing.
TEST(Runtime, InboundMeControlCountersReachStatistics) {
    // 0 orphan answers, but the fake sends CLOSE_CONN + unknown + malformed.
    FakeMe me{me_secret(), 1, std::chrono::milliseconds{0}, 1, std::chrono::milliseconds{0},
              std::chrono::milliseconds{0}, false, 0, 300, kBurstSize, true, 0, true};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));

    ASSERT_EQ(me.future().wait_for(6s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    Bytes response;
    ASSERT_TRUE(client.read_message(response));

    const auto snapshot = daemon.services.stats.snapshot();
    ASSERT_NE(snapshot.me_dcs.find("2"), snapshot.me_dcs.end());
    const auto& dc = snapshot.me_dcs.at("2");
    EXPECT_EQ(dc.control_close_conn, 1U);
    EXPECT_EQ(dc.control_close_ext, 0U);
    EXPECT_EQ(dc.control_unknown, 1U);
    EXPECT_EQ(dc.control_malformed, 1U);

    const std::string text = daemon.services.stats.prometheus_text();
    EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"close_conn\"} 1\n"),
              std::string::npos);
    EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"unknown\"} 1\n"),
              std::string::npos);
    EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"malformed\"} 1\n"),
              std::string::npos);
    EXPECT_EQ(text.find("mtdd_me_control_frames{dc=\"2\",type=\"close_ext\"}"),
              std::string::npos);  // zero-valued gauges are omitted
}

// ---------------------------------------------------------------------------
// Relay-buffer accounting and idle retention
// ---------------------------------------------------------------------------

// End-to-end regression for the live overload signature. With a bounded global
// buffer budget, a burst of authenticated sessions fills the budget; once they
// are idle, their retained capacity must be returned, otherwise the listener
// stays paused and every later client is refused admission even though no
// payload is pending. The burst length is discovered by the test itself, so the
// assertion does not depend on machine speed.
TEST(Runtime, IdleConnectionBuffersAreTrimmedSoAdmissionStaysOpen) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.max_frame_bytes = 4096;
        c.connection_queue_bytes = 4096;
        c.global_buffer_bytes = 256U * 1024U;
        c.max_handshakes = 64;
        c.max_connections = 64;
        c.handshake_timeout = 30s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    using ClientPtr = std::unique_ptr<TestClient>;
    auto handshake = [&](int variant) -> ClientPtr {
        auto client = std::make_unique<TestClient>(daemon.port(), secret_bytes());
        if (!client->valid()) return nullptr;
        if (!client->send_hello(0, static_cast<std::uint8_t>(variant))) return nullptr;
        return client;
    };
    auto active = [&] { return daemon.services.stats.snapshot().connections_active; };

    // Open a burst of authenticated sessions. Their retained capacity must be
    // returned once they go idle; otherwise the bounded budget never returns to
    // a level that lets the listener admit new clients.
    std::vector<ClientPtr> sessions;
    for (int i = 0; i < 24; ++i) {
        auto client = handshake(i);
        if (!client) break;
        sessions.push_back(std::move(client));
    }
    // The buffered gauge is published at 1 Hz. Sample across the handshake
    // window so the peak retained capacity is observed before the idle trim.
    std::uint64_t used_peak = 0;
    for (int i = 0; i < 40; ++i) {
        used_peak = std::max(used_peak, daemon.services.stats.snapshot().buffer_budget_used);
        std::this_thread::sleep_for(50ms);
    }
    const int accepted = static_cast<int>(active());
    EXPECT_GE(accepted, 3) << "the bounded budget admitted too few sessions";
    EXPECT_GT(used_peak, 0U) << "the buffered gauge never observed retained capacity";
    // If the burst overran the budget the listener paused and the surplus
    // sockets are still queued in the backlog. Drop them so a listener that
    // resumes after the idle trim cannot turn them into sessions.
    sessions.resize(static_cast<std::size_t>(std::max(accepted, 0)));
    std::this_thread::sleep_for(100ms);
    const std::uint64_t active_before_idle = active();

    // Idle window: the release runs on the 1 Hz gauge tick, so wait for the
    // 1 s idle threshold plus one full tick period.
    std::this_thread::sleep_for(2500ms);
    const std::uint64_t used_after = daemon.services.stats.snapshot().buffer_budget_used;
    EXPECT_LT(used_after, used_peak) << "idle sessions kept their retained capacity";
    EXPECT_EQ(active(), active_before_idle) << "idle trim closed an idle session";

    // Admission still works after the trim without any traffic from the idle
    // sessions.
    int admitted_after = 0;
    for (int i = 0; i < 3; ++i) {
        auto client = handshake(40 + i);
        if (!client) break;
        sessions.push_back(std::move(client));
        ++admitted_after;
    }
    EXPECT_EQ(admitted_after, 3);
    EXPECT_TRUE(wait_for(
        [&] { return active() == active_before_idle + static_cast<std::uint64_t>(admitted_after); },
        2s)) << "new sessions were still refused after idle capacity was released";
}

// Deterministic accounting regression: every close path must release exactly
// the capacity it charged. This covers an authenticated hello, an abruptly
// closed partial hello, and a rejected non-TLS request, plus the handshake
// counter. If any path forgot accounting (or leaked a handshake slot), the
// charged total or the pending count would grow with churn instead of
// returning to baseline.
TEST(Runtime, BufferBudgetReturnsToBaselineAfterClientChurn) {
    Daemon daemon(1, false, [](mtdd::Config& c) {
        c.global_buffer_bytes = 8U * 1024U * 1024U;
        c.max_handshakes = 512;
        c.max_connections = 512;
        c.handshake_timeout = 1s;
        c.idle_timeout = 5s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.worker_tid() != 0; }, 2s));
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().buffer_budget_used != 0; }, 2s));
    const std::uint64_t baseline =
        daemon.services.stats.snapshot().buffer_budget_used;

    const std::string junk = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for (int cycle = 0; cycle < 60; ++cycle) {
        {
            TestClient client(daemon.port(), secret_bytes());
            ASSERT_TRUE(client.valid());
            ASSERT_TRUE(client.send_hello(0, static_cast<std::uint8_t>(cycle)));
        }
        {
            const int fd = connect_loopback(daemon.port());
            if (fd >= 0) {
                const std::uint8_t partial[3] = {0x16, 0x03, 0x03};
                (void)send_all(fd, std::span<const std::uint8_t>(partial, 3));
                ::close(fd);
            }
        }
        {
            const int fd = connect_loopback(daemon.port());
            if (fd >= 0) {
                (void)send_all(fd, std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t*>(junk.data()),
                                       junk.size()));
                ::close(fd);
            }
        }
    }
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 10000ms));
    ASSERT_TRUE(wait_for(
        [&] {
            return daemon.services.stats.snapshot().buffer_budget_used <=
                   baseline + 128U * 1024U;
        },
        5000ms))
        << "budget accounting did not return to baseline: " << baseline << " -> "
        << daemon.services.stats.snapshot().buffer_budget_used;
    EXPECT_EQ(daemon.services.stats.snapshot().handshakes_pending, 0U);
}

// ---------------------------------------------------------------------------
// Replay cache admission
// ---------------------------------------------------------------------------

// A saturated replay cache is fail-closed: it never evicts a live entry to make
// room, and it rejects new unique handshakes with reason="overload". Retention
// (not capacity pressure) is the only way entries leave, so the capacity must
// cover the full timestamp horizon at the offered hello rate.
TEST(ReplayCache, SaturationIsFailClosedAndRetentionReleasesEntries) {
    using Outcome = mtdd::detail::ReplayCache::Outcome;
    mtdd::detail::ReplayCache cache{2};
    EXPECT_EQ(cache.capacity(), 2U);
    const auto key = [](std::uint8_t seed) {
        std::array<std::uint8_t, 32> out{};
        out.fill(seed);
        return out;
    };
    const auto now = std::chrono::steady_clock::now();
    EXPECT_EQ(cache.insert(key(1), now), Outcome::accepted);
    EXPECT_EQ(cache.insert(key(2), now), Outcome::accepted);
    EXPECT_EQ(cache.insert(key(3), now), Outcome::saturated);
    EXPECT_EQ(cache.size(), 2U);
    EXPECT_EQ(cache.insert(key(1), now), Outcome::duplicate);

    const auto later = now + mtdd::detail::kReplayRetention + std::chrono::seconds{1};
    EXPECT_EQ(cache.insert(key(3), later), Outcome::accepted);
    EXPECT_EQ(cache.size(), 1U);
}

TEST(ReplayCache, CapacityCoversDesignHelloRateForRetentionWindow) {
    // Documented live peak is ~890 authenticated hellos/s; size for 2180/s so
    // the cache is not the binding admission limit below that rate.
    constexpr std::size_t kDesignHellosPerSecond = 2180;
    EXPECT_GE(mtdd::detail::kReplayCapacity,
              static_cast<std::size_t>(mtdd::detail::kReplayRetention.count()) *
                  kDesignHellosPerSecond);
}

// ---------------------------------------------------------------------------
// Client object pool and post-auth retention
// ---------------------------------------------------------------------------

// The reactor recycles Client objects instead of allocating one per accepted
// socket. Recycling must be indistinguishable from a fresh Client: this test
// runs a full session with TLS/decoder/metrics/user_name/ip_counted/relay state
// set, closes it, and then runs a *different user's* session on the same object.
// Pointer identity proves the freelist was used; per-user counters prove no
// field (optionals, flags, metrics, user name, IP bookkeeping) bled across.
TEST(Runtime, ClientObjectsAreReusedWithoutStateBleed) {
    FakeMe me{me_secret(), 100000, 0ms, 1, 0ms, 0ms, true, 0, 30000};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.max_connections = 32;
        c.max_handshakes = 32;
        c.handshake_timeout = 10s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    // bob_secret_bytes() = 0x10..0x1f
    ASSERT_TRUE(daemon.services.add_user("bob", "101112131415161718191a1b1c1d1e1f"));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    reset_client_lifecycle_telemetry();
    auto& telemetry = mtdd::detail::client_lifecycle_telemetry();

    const auto run_session = [&](const A16& secret, std::size_t payload_seed) {
        TestClient client(daemon.port(), secret);
        EXPECT_TRUE(client.valid());
        EXPECT_TRUE(client.send_hello());
        EXPECT_TRUE(client.start_obfuscation(2));
        EXPECT_TRUE(client.send_message(burst_payload(payload_seed)));
        Bytes response;
        EXPECT_TRUE(client.read_message(response, 5000));
        return response.size();
    };

    ASSERT_GT(run_session(secret_bytes(), 0), 0U);
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 5000ms));
    const auto alice_after_close = daemon.services.stats.snapshot().users.at("alice");
    const std::uintptr_t recycled = telemetry.last_recycled.load(std::memory_order_relaxed);
    ASSERT_NE(recycled, 0U) << "closed client was not returned to the freelist";
    EXPECT_GE(telemetry.releases.load(std::memory_order_relaxed), 1U);

    ASSERT_GT(run_session(bob_secret_bytes(), 1), 0U);
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_GE(telemetry.reuses.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(telemetry.last_reused.load(std::memory_order_relaxed), recycled)
        << "new session did not reuse the recycled Client object";
    // The same counters are published for operations, so the live node can
    // prove reuse without a debug build.
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().client_reuses_total >= 1U; }, 2s));

    // If any state had bled, the second session would either fail above or be
    // accounted to the first user / the wrong IP bookkeeping.
    ASSERT_NE(snapshot.users.find("alice"), snapshot.users.end());
    ASSERT_NE(snapshot.users.find("bob"), snapshot.users.end());
    EXPECT_EQ(snapshot.users.at("alice").active_connections, 0U);
    EXPECT_EQ(snapshot.users.at("bob").active_connections, 1U);
    EXPECT_EQ(snapshot.users.at("alice").payload_c2s_bytes,
              alice_after_close.payload_c2s_bytes);
    EXPECT_EQ(snapshot.users.at("alice").payload_s2c_bytes,
              alice_after_close.payload_s2c_bytes);
    EXPECT_GE(snapshot.users.at("bob").payload_c2s_bytes, 16U * 1024U);
    EXPECT_EQ(snapshot.users.at("bob").unique_ips_active, 1U);
    EXPECT_EQ(snapshot.active_unique_ips, 1U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "success"), 2U);
    EXPECT_EQ(snapshot.connections_active, 1U);
}

// The freelist is bounded by config.max_connections and is released with the
// runtime: no unbounded growth and no retained objects after shutdown.
TEST(Runtime, ClientPoolIsBoundedAndReleasedAtShutdown) {
    reset_client_lifecycle_telemetry();
    auto& telemetry = mtdd::detail::client_lifecycle_telemetry();
    {
        Daemon daemon(1, false, [](mtdd::Config& c) {
            c.max_connections = 4;
            c.max_handshakes = 4;
            c.handshake_timeout = 1s;
        });
        ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
        ASSERT_TRUE(wait_for([&] { return daemon.worker_tid() != 0; }, 2s));
        const std::string junk = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        std::vector<int> fds;
        for (int i = 0; i < 4; ++i) {
            const int fd = connect_loopback(daemon.port());
            ASSERT_GE(fd, 0);
            (void)send_all(fd, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t*>(junk.data()),
                                   junk.size()));
            fds.push_back(fd);
        }
        // Rejected/closed sockets return their objects; four concurrent closes
        // can fill at most max_connections entries. `connection_closed()` is
        // published before the object is recycled, so wait for both facts
        // instead of racing the recycle step (this test was ~25% flaky under
        // ASan before).
        for (const int fd : fds) ::close(fd);
        ASSERT_TRUE(wait_for([&] {
            return daemon.services.stats.snapshot().connections_active == 0 &&
                   telemetry.releases.load(std::memory_order_relaxed) >= 1U;
        }, 5000ms));
        EXPECT_GE(telemetry.releases.load(std::memory_order_relaxed), 1U)
            << "no client object reached the freelist";
        EXPECT_LE(telemetry.pooled.load(std::memory_order_relaxed), 4U);
    }
    EXPECT_EQ(telemetry.pooled.load(std::memory_order_relaxed), 0U)
        << "client pool was not released with the runtime";
}

// A relay session must not retain the ClientHello buffer. `hello` is consumed
// only in Phase::tls_hello / process_client_hello() (verified by grep: no relay
// path reads it); capacity is released on the relay transition and asserted via
// the lifecycle seam. The session still relays afterwards.
TEST(Runtime, AuthenticatedSessionRetainsNoClientHelloCapacity) {
    FakeMe me{me_secret(), 100000, 0ms, 1, 0ms, 0ms, true, 0, 30000};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.handshake_timeout = 10s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    reset_client_lifecycle_telemetry();
    auto& telemetry = mtdd::detail::client_lifecycle_telemetry();

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(wait_for(
        [&] { return telemetry.relay_transitions.load(std::memory_order_relaxed) >= 1U; },
        3000ms));
    EXPECT_EQ(telemetry.relay_with_hello_capacity.load(std::memory_order_relaxed), 0U)
        << "relay transition still carried ClientHello capacity";

    // The connection is fully usable after the release.
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    Bytes response;
    ASSERT_TRUE(client.read_message(response, 5000));
    ASSERT_EQ(response.size(), 8U);
    EXPECT_EQ(daemon.services.stats.snapshot().users.at("alice").active_connections, 1U);
}

// ---------------------------------------------------------------------------
// ME ready-queue invariant and per-DC answer observability
// ---------------------------------------------------------------------------


// RED (base): one logical client whose first message is larger than the shared
// ME output queue leaves staged frames; every pump re-enqueues the same token
// twice. The live invariant is depth <= unique queued clients.
TEST(Runtime, MeReadyQueueNeverDuplicatesBlockedClient) {
    FakeMe me{me_secret(), 2, 700ms, 1, 0ms, 0ms, true, 0, 15000, 0};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.connection_queue_bytes = 4096;
        c.max_frame_bytes = 8U * 1024U * 1024U;
        c.global_buffer_bytes = 256U * 1024U * 1024U;
        c.handshake_timeout = 10s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    // One 4 MiB transport message (several TLS records) cannot be buffered by
    // the socket while the fake ME is not reading, so the ME frame stays
    // staged; the second message keeps this client's C2S queue non-empty.
    Bytes large(4U * 1024U * 1024U, 0x7e);
    large[0] = 0x01;
    ASSERT_TRUE(client.send_message_chunked(large));
    Bytes tail(32, 0x02);
    ASSERT_TRUE(client.send_message(tail));

    std::uint64_t max_depth = 0;
    std::uint64_t max_clients = 0;
    for (int sample = 0; sample < 120; ++sample) {
        const auto dc = me_dc(daemon.services.stats, "2");
        max_depth = std::max(max_depth, dc.ready_queue_depth);
        max_clients = std::max(max_clients, dc.ready_queue_clients);
        if (dc.ready_queue_depth == 0 && sample > 20) break;
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_LE(max_depth, std::max<std::uint64_t>(1, max_clients))
        << "ready queue contained duplicate/stale entries: depth=" << max_depth
        << " unique_clients=" << max_clients;
    EXPECT_LE(me_dc(daemon.services.stats, "2").ready_queue_depth,
              std::max<std::uint64_t>(
                  1, me_dc(daemon.services.stats, "2").ready_queue_clients));

    ASSERT_EQ(me.future().wait_for(5s), std::future_status::ready);
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok);
    EXPECT_EQ(observation.frames, 2U);

    // Both requests must round-trip through the fake ME.
    Bytes response;
    EXPECT_TRUE(client.read_message(response, 3000));
    EXPECT_TRUE(client.read_message(response, 3000));

    // Once the transport drains, the queue must not retain duplicates.
    EXPECT_TRUE(wait_for(
        [&] {
            const auto dc = me_dc(daemon.services.stats, "2");
            return dc.ready_queue_depth == 0 && dc.ready_queue_clients == 0;
        },
        3000ms))
        << "ready queue did not drain after the ME writer caught up";
}

// RED (base): >2 per-turn batches are queued while the ME handshake is delayed.
// After the last readiness event there is no ME event left, so the remainder
// must be resumed by an explicit wake, not by unrelated traffic.
TEST(Runtime, MeReadyQueueSelfWakesBeyondBatch) {
#if defined(__SANITIZE_ADDRESS__)
    // Creating 150 real loopback clients is slower than the fake handshake delay
    // under ASan, so the test no longer creates the >2-batch backlog it needs.
    // The wake behaviour is proven in the normal build and in RED-B; the ASan
    // suite still exercises the same queue code via the duplicate/blocked tests.
    GTEST_SKIP() << "timing-sensitive under ASan; covered by normal build and RED-B";
#endif
    constexpr std::size_t kClients = 150;
    FakeMe me{me_secret(), kClients, 0ms, 1, 8000ms, 0ms, false, 0, 12000, 0,
              false};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.max_connections = 256;
        c.max_handshakes = 256;
        c.connection_queue_bytes = 256U * 1024U;
        c.global_buffer_bytes = 64U * 1024U * 1024U;
        c.handshake_timeout = 30s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    std::vector<std::unique_ptr<TestClient>> clients;
    clients.reserve(kClients);
    for (std::size_t index = 0; index < kClients; ++index) {
        auto client = std::make_unique<TestClient>(daemon.port(), secret_bytes());
        ASSERT_TRUE(client->valid()) << "client " << index;
        ASSERT_TRUE(client->send_hello(0, static_cast<std::uint8_t>(index)))
            << "hello " << index;
        ASSERT_TRUE(client->start_obfuscation(2)) << "obfuscation " << index;
        Bytes request(32, 0x5a);
        request[0] = static_cast<std::uint8_t>(index);
        ASSERT_TRUE(client->send_message(request)) << "message " << index;
        clients.push_back(std::move(client));
    }

    ASSERT_EQ(me.future().wait_for(15s), std::future_status::ready)
        << "ME never received every queued request (lost wakeup)";
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok);
    EXPECT_EQ(observation.frames, kClients);
    EXPECT_TRUE(wait_for(
        [&] {
            const auto dc = me_dc(daemon.services.stats, "2");
            return dc.proxy_ans_delivered_total >= 1;
        },
        5000ms));
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_LE(dc.ready_queue_depth, dc.ready_queue_clients);
}

// The explicit wake must not become a spin while the ME socket cannot make
// progress (frames staged / out full). No wake is armed in that state.
TEST(Runtime, BlockedMeReadyQueueDoesNotSpinReactor) {
    FakeMe me{me_secret(), 2, 900ms, 1, 0ms, 0ms, true, 0, 4000, 0};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.connection_queue_bytes = 4096;
        c.max_frame_bytes = 8U * 1024U * 1024U;
        c.global_buffer_bytes = 256U * 1024U * 1024U;
        c.handshake_timeout = 10s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    Bytes large(4U * 1024U * 1024U, 0x6d);
    ASSERT_TRUE(client.send_message_chunked(large));
    ASSERT_TRUE(client.send_message(Bytes(32, 0x03)));
    ASSERT_TRUE(wait_for(
        [&] { return me_dc(daemon.services.stats, "2").ready_queue_depth != 0; }, 3000ms));

    const double before = thread_cpu_seconds(daemon.worker_tid());
    std::this_thread::sleep_for(600ms);
    const double after = thread_cpu_seconds(daemon.worker_tid());
    ASSERT_GE(before, 0.0);
    ASSERT_GE(after, 0.0);
    EXPECT_LT(after - before, 0.30)
        << "reactor burned CPU while the ME writer was blocked";
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_LE(dc.ready_queue_depth, std::max<std::uint64_t>(1, dc.ready_queue_clients));
}

// A queued client that closes must not leave a membership flag on the recycled
// Client object. The new connection reuses the address and must work normally;
// the late answer for the closed conn id is counted as unknown, not delivered.
TEST(Runtime, QueuedClientCloseDoesNotCorruptRecycledClient) {
#if defined(__SANITIZE_ADDRESS__)
    // The test needs the fake ME to stay in handshake while the first client is
    // verifiably queued. Under ASan the test-side handshake and the 1 s gauge
    // cadence race; the same invariant is covered by the normal build and by
    // MeReadyQueueNeverDuplicatesBlockedClient under ASan.
    GTEST_SKIP() << "timing-sensitive under ASan; covered by normal build";
#endif
    // The ME handshake is delayed, so both clients' requests are queued before
    // readiness. Client one closes while its token is still in the queue; the
    // successor reuses the Client object and must relay normally.
    FakeMe me{me_secret(), 1, 0ms, 1, 8000ms, 0ms, true, 0, 15000, 0};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.connection_queue_bytes = 256U * 1024U;
        c.max_frame_bytes = 2U * 1024U * 1024U;
        c.global_buffer_bytes = 64U * 1024U * 1024U;
        c.handshake_timeout = 30s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    reset_client_lifecycle_telemetry();
    auto& telemetry = mtdd::detail::client_lifecycle_telemetry();

    {
        TestClient first(daemon.port(), secret_bytes());
        ASSERT_TRUE(first.valid());
        ASSERT_TRUE(first.send_hello());
        ASSERT_TRUE(first.start_obfuscation(2));
        ASSERT_TRUE(first.send_message(Bytes(32, 0x41)));
        ASSERT_TRUE(wait_for([&] {
            const auto snapshot = daemon.services.stats.snapshot();
            return snapshot.me_dcs.at("2").ready_queue_depth != 0 &&
                   !snapshot.me_dcs.at("2").connected;
        }, 30000ms)) << "client was not queued before ME readiness";
        first.close();
    }
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 3000ms));
    EXPECT_GE(telemetry.releases.load(std::memory_order_relaxed), 1U);

    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(second.send_hello(0, 1));
    ASSERT_TRUE(second.start_obfuscation(2));
    ASSERT_TRUE(second.send_message(Bytes(32, 0x42)));
    ASSERT_EQ(me.future().wait_for(12000ms), std::future_status::ready)
        << "the ME never received the recycled client's request";
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok);
    EXPECT_EQ(observation.frames, 1U);
    Bytes response;
    ASSERT_TRUE(second.read_message(response, 5000))
        << "recycled client did not receive its answer";
    EXPECT_EQ(response.size(), 8U);
    EXPECT_GE(telemetry.reuses.load(std::memory_order_relaxed), 1U);
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_GE(dc.proxy_ans_delivered_total, 1U);
    EXPECT_LE(dc.ready_queue_depth, dc.ready_queue_clients);
}

// Sustained req_pq-shaped load from NEW logical clients: every request must
// round-trip through the shared ME writer within bounded turns.
TEST(Runtime, SustainedReqPqAcrossNewClientsThroughFakeMe) {
    constexpr std::size_t kClients = 40;
    constexpr std::size_t kPerClient = 3;
    FakeMe me{me_secret(), kClients * kPerClient, 0ms, 1, 0ms, 0ms, true, 0, 5000, 0};
    Daemon daemon(me.port(), true, [](mtdd::Config& c) {
        c.max_connections = 128;
        c.max_handshakes = 128;
        c.connection_queue_bytes = 256U * 1024U;
        c.global_buffer_bytes = 64U * 1024U * 1024U;
        c.handshake_timeout = 10s;
        c.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    std::vector<std::unique_ptr<TestClient>> clients;
    clients.reserve(kClients);
    for (std::size_t index = 0; index < kClients; ++index) {
        auto client = std::make_unique<TestClient>(daemon.port(), secret_bytes());
        ASSERT_TRUE(client->valid()) << "client " << index;
        ASSERT_TRUE(client->send_hello(0, static_cast<std::uint8_t>(index)));
        ASSERT_TRUE(client->start_obfuscation(2));
        for (std::size_t message = 0; message < kPerClient; ++message) {
            Bytes request(32, 0x11);
            request[0] = static_cast<std::uint8_t>(index);
            request[1] = static_cast<std::uint8_t>(message);
            ASSERT_TRUE(client->send_message(request));
        }
        clients.push_back(std::move(client));
    }
    for (std::size_t index = 0; index < clients.size(); ++index) {
        for (std::size_t message = 0; message < kPerClient; ++message) {
            Bytes response;
            ASSERT_TRUE(clients[index]->read_message(response, 5000))
                << "client " << index << " reply " << message;
            EXPECT_EQ(response.size(), 8U);
        }
    }
    ASSERT_EQ(me.future().wait_for(10s), std::future_status::ready);
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok);
    EXPECT_EQ(observation.frames, kClients * kPerClient);
    const auto dc = me_dc(daemon.services.stats, "2");
    EXPECT_GE(dc.proxy_ans_delivered_total, kClients * kPerClient);
    EXPECT_EQ(dc.ready_queue_depth, 0U);
}

// Two signed DCs must keep independent queues and answer counters. No queue or
// conn id may cross the DC boundary.
TEST(Runtime, SeparateSignedDcQueuesAndAnswersStayIsolated) {
    FakeMe dc2{me_secret(), 4, 0ms, 1, 0ms, 0ms, true, 0, 5000, 0};
    FakeMe dc4{me_secret(), 4, 0ms, 1, 0ms, 0ms, true, 0, 5000, 0};
    Daemon daemon(dc2.port(), true, [&](mtdd::Config& c) {
        std::ofstream file{c.me_config_path, std::ios::binary};
        file << "proxy_for 2 127.0.0.1:" << dc2.port() << ";\n";
        file << "proxy_for 4 127.0.0.1:" << dc4.port() << ";\n";
        c.max_connections = 32;
        c.max_handshakes = 32;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    // The signed-DC route must be installed by the reactor before a client can
    // be authenticated: a client that reaches relay while metadata_snapshot_ is
    // still empty is rejected with reason="other" (cold-start race, ~6% flaky
    // under ASan before this wait).
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    // ME connections are opened on demand (or lazily warmed one DC at a time),
    // so the second DC only connects once a client asks for it below.
    TestClient two(daemon.port(), secret_bytes());
    ASSERT_TRUE(two.valid());
    ASSERT_TRUE(two.send_hello(0, 0));
    ASSERT_TRUE(two.start_obfuscation(2));
    TestClient four(daemon.port(), secret_bytes());
    ASSERT_TRUE(four.valid());
    ASSERT_TRUE(four.send_hello(0, 1));
    ASSERT_TRUE(four.start_obfuscation(4));
    for (int index = 0; index < 2; ++index) {
        Bytes request(32, 0x22);
        request[0] = static_cast<std::uint8_t>(index);
        ASSERT_TRUE(two.send_message(request));
        ASSERT_TRUE(four.send_message(request));
    }
    for (int index = 0; index < 2; ++index) {
        Bytes response;
        ASSERT_TRUE(two.read_message(response, 5000));
        ASSERT_TRUE(four.read_message(response, 5000));
    }
    ASSERT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        return snapshot.me_dcs.at("2").connected && snapshot.me_dcs.at("4").connected;
    }, 5s));
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_GE(snapshot.me_dcs.at("2").proxy_ans_delivered_total, 2U);
    EXPECT_GE(snapshot.me_dcs.at("4").proxy_ans_delivered_total, 2U);
    // Socket byte counters are published on the 1 Hz gauge tick.
    EXPECT_TRUE(wait_for([&] {
        const auto now = daemon.services.stats.snapshot();
        return now.me_dcs.at("2").tx_bytes_total >= 1U &&
               now.me_dcs.at("4").tx_bytes_total >= 1U;
    }, 3000ms));
    EXPECT_EQ(snapshot.me_dcs.at("2").ready_queue_depth, 0U);
    EXPECT_EQ(snapshot.me_dcs.at("4").ready_queue_depth, 0U);
}

} // namespace

namespace {
// Fetches `count` 128 KiB answers from media DC -2, one request at a time, and
// returns the elapsed time (or a negative duration on failure).
std::chrono::milliseconds fetch_media(std::uint64_t user_kbps, std::size_t count,
                                      std::uint64_t* throttled = nullptr) {
    constexpr std::size_t kAnswer = 128U * 1024U;
    FakeMe me{me_secret(), 100000, 0ms, 1, 0ms, 0ms, true, kAnswer, 30000};
    Daemon daemon(me.port(), true, [&](mtdd::Config& config) {
        std::ofstream file{config.me_config_path, std::ios::binary};
        file << "proxy_for -2 127.0.0.1:" << me.port() << ";\n";
        config.media_user_rate_kbps = user_kbps;
        config.idle_timeout = 60s;
    });
    if (!daemon.services.add_user("alice", std::string(kSecretHex))) return -1ms;
    if (!wait_for([&] { return daemon.services.stats.ready(); }, 4s)) return -1ms;
    TestClient client(daemon.port(), secret_bytes());
    if (!client.valid() || !client.send_hello() || !client.start_obfuscation(-2)) return -1ms;
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t index = 0; index < count; ++index) {
        if (!client.send_message(burst_payload(index))) return -1ms;
        Bytes response;
        if (!client.read_message(response, 10000) || response.size() != kAnswer) return -1ms;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    if (throttled != nullptr) *throttled = daemon.services.stats.snapshot().media_throttled_total;
    return elapsed;
}
} // namespace

TEST(Runtime, MediaUserRateLimitSlowsDownloadsWithoutDroppingThem) {
    // 12 x 128 KiB = 1.5 MiB. Unlimited this is a loopback copy.
    const auto unlimited = fetch_media(0, 12);
    ASSERT_GE(unlimited.count(), 0);
    EXPECT_LT(unlimited, 1500ms);
    // 4000 kbit/s = 500 KB/s with a one-second burst: >= ~2 s for the rest.
    std::uint64_t throttled = 0;
    const auto limited = fetch_media(4000, 12, &throttled);
    ASSERT_GE(limited.count(), 0) << "a shaped download must complete, not be dropped";
    EXPECT_GE(limited, 1800ms);
    EXPECT_LT(limited, 8000ms);
    EXPECT_GE(throttled, 1U);
}

TEST(RateBucket, LimitsAverageRateWithOneSecondBurstAndDebt) {
    mtdd::detail::RateBucket bucket;
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(bucket.blocked(start)) << "rate 0 is unlimited";
    bucket.consume(10'000'000, start);
    EXPECT_FALSE(bucket.blocked(start));
    bucket.set_rate(1000);  // bytes per second
    EXPECT_FALSE(bucket.blocked(start));  // starts with a full one-second burst
    bucket.consume(1500, start);
    EXPECT_TRUE(bucket.blocked(start)) << "debt of 500 bytes";
    EXPECT_TRUE(bucket.blocked(start + 400ms));
    EXPECT_FALSE(bucket.blocked(start + 600ms)) << "debt repaid after 0.5 s";
    // The burst is capped at one second of rate.
    EXPECT_FALSE(bucket.blocked(start + 60s));
    bucket.consume(1001, start + 60s);
    EXPECT_TRUE(bucket.blocked(start + 60s));
}

TEST(RateBucket, InterleavedStaleTimestampsDoNotInflateTheRate) {
    // Two reactors feed the shared bucket with times that alternate between a
    // fresh and a 2 ms stale stamp. Over 10 s at 1 MB/s at most 10 MB + the
    // 1 s burst may pass, regardless of the interleaving.
    mtdd::detail::RateBucket bucket;
    bucket.set_rate(1'000'000);
    const auto start = std::chrono::steady_clock::now();
    std::uint64_t passed = 0;
    for (int tick = 0; tick < 100'000; ++tick) {
        const auto fresh = start + std::chrono::microseconds(tick * 100);
        const auto stale = fresh - std::chrono::milliseconds(2);
        for (const auto now : {fresh, stale}) {
            if (!bucket.blocked(now)) {
                bucket.consume(1000, now);
                passed += 1000;
            }
        }
    }
    EXPECT_LE(passed, 11'100'000U) << "stale stamps re-credited elapsed time";
    EXPECT_GE(passed, 10'000'000U);
}

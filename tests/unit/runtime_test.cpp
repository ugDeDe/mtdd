#include "../support/runtime_fixture.hpp"

namespace {

// The reactor batches readiness and accepts in fixed, stack-safe arrays. The
// sizes are part of the overload contract: too small starves a busy reactor,
// while an unbounded batch would let one event monopolise the worker.
TEST(Runtime, EpollAndAcceptBatchesStayBoundedAndLargeEnough) {
    EXPECT_EQ(mtdd::detail::kEpollBatch, 512U);
    EXPECT_LE(sizeof(std::array<epoll_event, mtdd::detail::kEpollBatch>),
              std::size_t{64} * 1024U);
    EXPECT_EQ(mtdd::detail::kAcceptBatch, 128U);
}

TEST(Runtime, BindsAndStops) {
    Daemon daemon(1, false);
    ASSERT_NE(daemon.port(), 0);
    EXPECT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));

    // No usable ME metadata: readiness must stay false.
    std::this_thread::sleep_for(400ms);
    EXPECT_FALSE(daemon.services.stats.ready());

    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    EXPECT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().connections_active == 1; },
                         2s));
    daemon.stop();
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
    EXPECT_FALSE(daemon.services.stats.ready());
}

TEST(Runtime, InvalidHelloRejectedAndClosed) {
    Daemon daemon(1, false);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    const std::string junk = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(junk.data()), junk.size())));
    EXPECT_TRUE(wait_closed(fd, 3000));
    EXPECT_GE(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 1U);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
    EXPECT_EQ(daemon.services.stats.snapshot().active_unique_ips, 0U);
    ::close(fd);
}

TEST(Runtime, HandshakeTimeoutIsBoundedAndReported) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.handshake_timeout = std::chrono::seconds{1};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    EXPECT_TRUE(wait_closed(fd, 4000));
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "timeout"), 1U);
    ::close(fd);
}

TEST(Runtime, MaxHandshakesRejectsExcessAdmission) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.max_handshakes = 1;
        config.max_connections = 8;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int first = connect_loopback(daemon.port());
    ASSERT_GE(first, 0);
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 1; }, 2s));
    const int second = connect_loopback(daemon.port());
    if (second >= 0) {
        EXPECT_TRUE(wait_closed(second, 3000));
        ::close(second);
    }
    // The rejection counter is published by the reactor thread just before it
    // closes the socket; observing FIN does not order the atomic snapshot read.
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "rejected", "overload") >= 1U; },
        1000ms));
    ::close(first);
}

TEST(Runtime, ZeroConnectionAndHandshakeLimitsAreUnlimited) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.max_connections = 0;
        config.max_handshakes = 0;
    });
    const int first = connect_loopback(daemon.port());
    const int second = connect_loopback(daemon.port());
    ASSERT_GE(first, 0);
    ASSERT_GE(second, 0);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 2; }, 2s));
    EXPECT_FALSE(wait_closed(first, 100));
    EXPECT_FALSE(wait_closed(second, 100));
    ::close(first);
    ::close(second);
}

TEST(Runtime, GlobalBufferAdmissionLimitPausesListenerWithoutAccepting) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.connection_queue_bytes = 4096;
        config.max_frame_bytes = 4096;
        // Below make_client()'s admission reservation (headroom + 8 KiB), so the
        // reactor must never accept: accepting and closing would strand an
        // orphan socket per attempt.
        config.global_buffer_bytes = 100U * 1024U;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    // The kernel completes the handshake into the listen backlog, but the
    // listener stays paused: no FIN, no overload rejection, no active client.
    EXPECT_FALSE(wait_closed(fd, 500));
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "overload"), 0U);
    ::close(fd);
}

TEST(Runtime, ClientHelloReplayIsRejectedBeforeServerHello) {
    Daemon daemon(1, false);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    ASSERT_FALSE(first.wait_closed_for(200));

    TestClient replay(daemon.port(), secret_bytes());
    ASSERT_TRUE(replay.valid());
    ASSERT_TRUE(replay.send_hello_bytes(first.hello_bytes()));
    EXPECT_FALSE(replay.peer_sent_data(1000));
    EXPECT_TRUE(replay.wait_closed_for(1000));
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "replay"), 1U);
}

TEST(Runtime, UserDeletionClosesAuthenticatedSessionAndAcknowledges) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::this_thread::sleep_for(300ms);
    EXPECT_FALSE(client.wait_closed_for(0));
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().active_unique_ips == 1; }, 2000ms));
    {
        const auto snapshot = daemon.services.stats.snapshot();
        ASSERT_NE(snapshot.users.find("alice"), snapshot.users.end());
        EXPECT_EQ(snapshot.users.at("alice").unique_ips_active, 1U);
    }

    auto deleted = daemon.services.store->delete_user(mtdd::control::DeleteUserRequest{"alice", {}});
    ASSERT_TRUE(deleted.ok());
    EXPECT_TRUE(deleted.value().applied);
    EXPECT_FALSE(deleted.value().pending);
    EXPECT_TRUE(client.wait_closed_for(3000));
    ASSERT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto user = snapshot.users.find("alice");
            return snapshot.active_unique_ips == 0 && user != snapshot.users.end() &&
                   user->second.unique_ips_active == 0;
        },
        2000ms));
}

TEST(Runtime, ProactiveWarmupConnectsWithoutClients) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 4s));
    EXPECT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto found = snapshot.me_dcs.find("2");
            return found != snapshot.me_dcs.end() && found->second.connected;
        },
        4s));
    ASSERT_EQ(daemon.services.stats.snapshot().connections_active, 0U);
}

TEST(Runtime, WarmupFallsBackToAlternateDc) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [&](mtdd::Config& config) {
        std::ofstream file{config.me_config_path, std::ios::binary};
        file << "proxy_for 2 127.0.0.1:1;\n";
        file << "proxy_for 4 127.0.0.1:" << me.port() << ";\n";
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));
    EXPECT_TRUE(wait_for(
        [&] {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto found = snapshot.me_dcs.find("4");
            return found != snapshot.me_dcs.end() && found->second.connected;
        },
        5s));
}

TEST(Runtime, WarmupConnectsEveryPrimaryDcWithoutClients) {
    FakeMe primary{me_secret()};
    FakeMe secondary{me_secret()};
    Daemon daemon(primary.port(), true, [&](mtdd::Config& config) {
        std::ofstream file{config.me_config_path, std::ios::binary};
        file << "proxy_for 2 127.0.0.1:" << primary.port() << ";\n";
        file << "proxy_for 4 127.0.0.1:" << secondary.port() << ";\n";
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    const auto connected = [&](const char* dc) {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto found = snapshot.me_dcs.find(dc);
        return found != snapshot.me_dcs.end() && found->second.connected;
    };
    EXPECT_TRUE(wait_for([&] { return connected("2") && connected("4"); }, 5s));
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 0U);
}

TEST(Runtime, BurstIsChunkedThroughSharedMiddleEndWriter) {
    FakeMe me{me_secret(), kBurstCount, 120ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    for (std::size_t index = 0; index < kBurstCount; ++index) {
        ASSERT_TRUE(client.send_message(burst_payload(index)));
    }
    ASSERT_EQ(me.future().wait_for(8s), std::future_status::ready);
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok);
    EXPECT_EQ(observation.frames, kBurstCount);

    Bytes response;
    ASSERT_TRUE(client.read_message(response));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);
    const auto snapshot = daemon.services.stats.snapshot();
    const auto user = snapshot.users.find("alice");
    ASSERT_NE(user, snapshot.users.end());
    EXPECT_GE(user->second.payload_c2s_bytes, kBurstCount * kBurstSize);
}


TEST(Runtime, ReadinessRequiresActualMiddleEnd) {
    FakeMe me{me_secret(), 1, std::chrono::milliseconds{0}, 1, 400ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    std::this_thread::sleep_for(150ms);
    EXPECT_FALSE(daemon.services.stats.ready());
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    const auto snapshot = daemon.services.stats.snapshot();
    const auto found = snapshot.me_dcs.find("2");
    ASSERT_NE(found, snapshot.me_dcs.end());
    EXPECT_TRUE(found->second.connected);
}

TEST(Runtime, ReadinessDropsAndRecoversAcrossMeReconnect) {
    FakeMe me{me_secret(), 1, std::chrono::milliseconds{0}, 2, std::chrono::milliseconds{0},
              200ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 4s));
    EXPECT_TRUE(wait_for([&] { return !daemon.services.stats.ready(); }, 4s));
    EXPECT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 6s));
}

TEST(Runtime, RelayCloseReasonsAreCounted) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 4s));
    const auto closes = [&](mtdd::control::RelayCloseReason reason) {
        return daemon.services.stats.snapshot()
            .relay_closes_total[static_cast<std::size_t>(reason)];
    };
    {
        TestClient client(daemon.port(), secret_bytes());
        ASSERT_TRUE(client.valid());
        ASSERT_TRUE(client.send_hello());
        ASSERT_TRUE(client.start_obfuscation(2));
        ASSERT_TRUE(client.send_message(burst_payload(0)));
        Bytes response;
        ASSERT_TRUE(client.read_message(response, 3000));
        client.close();
    }
    EXPECT_TRUE(wait_for(
        [&] { return closes(mtdd::control::RelayCloseReason::client_eof) == 1; }, 3s));
    EXPECT_EQ(closes(mtdd::control::RelayCloseReason::other), 0U);

    // A user revocation is attributed to "revoked", not to the peer.
    TestClient revoked(daemon.port(), secret_bytes());
    ASSERT_TRUE(revoked.valid());
    ASSERT_TRUE(revoked.send_hello(0, 1));
    ASSERT_TRUE(revoked.start_obfuscation(2));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().connections_active == 1; },
                         3s));
    ASSERT_TRUE(daemon.services.store->delete_user(mtdd::control::DeleteUserRequest{"alice", {}})
                    .ok());
    EXPECT_TRUE(revoked.wait_closed_for(3000));
    EXPECT_TRUE(wait_for(
        [&] { return closes(mtdd::control::RelayCloseReason::revoked) == 1; }, 3s));
    const auto metrics = daemon.services.stats.prometheus_text();
    EXPECT_NE(metrics.find("mtdd_relay_closes_total{reason=\"client_eof\"} 1"),
              std::string::npos);
}

TEST(Runtime, FailedDcDoesNotCollapseOtherReadyDcOrItsClient) {
    FakeMe unstable{me_secret(), 1, 0ms, 2, 0ms, 1500ms};
    FakeMe healthy{me_secret()};
    Daemon daemon(unstable.port(), true, [&](mtdd::Config& config) {
        std::ofstream file{config.me_config_path, std::ios::binary};
        file << "proxy_for 2 127.0.0.1:" << unstable.port() << ";\n";
        file << "proxy_for 4 127.0.0.1:" << healthy.port() << ";\n";
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().me_dcs.at("2").connected;
    }, 4s));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(4));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    Bytes response;
    ASSERT_TRUE(client.read_message(response, 3000));
    EXPECT_EQ(response, (Bytes{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}));
    ASSERT_TRUE(wait_for([&] {
        return !daemon.services.stats.snapshot().me_dcs.at("2").connected;
    }, 4s));
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_TRUE(snapshot.me_dcs.at("4").connected);
    EXPECT_TRUE(snapshot.ready);
    EXPECT_EQ(snapshot.users.at("alice").active_connections, 1U);
    EXPECT_FALSE(client.wait_closed_for(0));
}

TEST(Runtime, HalfCloseDrainsRequestAndDeliversDelayedReply) {
    FakeMe me{me_secret(), 1, 300ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    Bytes response;
    ASSERT_TRUE(client.read_message(response, 3000));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);
    EXPECT_TRUE(client.wait_closed_for(3000));
}

TEST(Runtime, ShutdownDrainsInflightReply) {
    FakeMe me{me_secret(), 1, 400ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    std::this_thread::sleep_for(80ms);
    daemon.stop();

    Bytes response;
    ASSERT_TRUE(client.read_message(response, 3000));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);
}

TEST(Runtime, ShutdownDeadlineClosesWithoutReply) {
    FakeMe me{me_secret(), 1, 3000ms};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.shutdown_timeout = std::chrono::seconds{1};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    std::this_thread::sleep_for(80ms);

    const auto started = std::chrono::steady_clock::now();
    daemon.stop();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, 2500ms);
    Bytes response;
    EXPECT_FALSE(client.read_message(response, 300));
}

TEST(Runtime, SharedMiddleEndSurvivesOneLogicalClientClose) {
    FakeMe me{me_secret(), 3, std::chrono::milliseconds{0}, 1, std::chrono::milliseconds{0},
              std::chrono::milliseconds{0}, true};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient first(daemon.port(), secret_bytes());
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(first.send_hello(0, 1));
    ASSERT_TRUE(second.send_hello(0, 2));
    ASSERT_TRUE(first.start_obfuscation(2));
    ASSERT_TRUE(second.start_obfuscation(2));

    ASSERT_TRUE(first.send_message(burst_payload(0)));
    ASSERT_TRUE(second.send_message(burst_payload(1)));
    Bytes response;
    ASSERT_TRUE(first.read_message(response, 3000));
    ASSERT_TRUE(second.read_message(response, 3000));

    second.close();
    // Closing a logical client is observed asynchronously: a half-close is
    // drained by the 150 ms housekeeping pass (or the bounded EOF deadline),
    // so a fixed sleep here is a test race, not a runtime guarantee. Wait for
    // the required observable state with a bound instead.
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 1; }, 1500ms))
        << "closed logical client was not released within the bounded drain window";
    ASSERT_TRUE(first.send_message(burst_payload(2)));
    ASSERT_TRUE(first.read_message(response, 3000));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);
    const auto snapshot = daemon.services.stats.snapshot();
    const auto found = snapshot.me_dcs.find("2");
    ASSERT_NE(found, snapshot.me_dcs.end());
    EXPECT_TRUE(found->second.connected);
    EXPECT_EQ(snapshot.connections_active, 1U);
}

TEST(Runtime, MeWriterLimitsAcceptConfiguredMaximum) {
    Services services(1, false, [](mtdd::Config& config) {
        config.me_connections_per_dc = 24;
        config.me_clients_per_writer = 400;
    });
    EXPECT_NO_THROW({
        mtdd::Runtime runtime(services.config, *services.store, services.stats,
                              *services.metadata, services.barrier);
    });
    // 2 * 24 = 48 pool slots per DC stay below the reactor's 63-writer cap.
    EXPECT_LE(2U * services.config.me_connections_per_dc, 63U);

    Services invalid(1, false, [](mtdd::Config& config) {
        config.me_connections_per_dc = 25;
    });
    EXPECT_THROW(
        {
            mtdd::Runtime runtime(invalid.config, *invalid.store, invalid.stats,
                                  *invalid.metadata, invalid.barrier);
        },
        std::invalid_argument);
}

TEST(Runtime, DestructorWaitsForConcurrentReactor) {
    Services services(1, false);
    ASSERT_TRUE(services.add_user("alice", std::string(kSecretHex)));
    auto runtime = std::make_unique<mtdd::Runtime>(services.config, *services.store,
                                                   services.stats, *services.metadata,
                                                   services.barrier);
    mtdd::Runtime* reactor = runtime.get();
    std::thread worker([reactor] { reactor->run(); });
    std::this_thread::sleep_for(100ms);
    reactor->request_stop();
    runtime.reset(); // must block until run() has exited, then destroy safely
    worker.join();
    EXPECT_FALSE(services.stats.ready());
}


TEST(Runtime, EofDrainDoesNotSpinReactor) {
    FakeMe me{me_secret(), 1, 2000ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.worker_tid() != 0; }, 2s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    std::this_thread::sleep_for(100ms);
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    std::this_thread::sleep_for(50ms); // let the FIN be observed

    const pid_t tid = daemon.worker_tid();
    const double cpu0 = thread_cpu_seconds(tid);
    const auto wall0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(700ms);
    const double cpu1 = thread_cpu_seconds(tid);
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall0).count();
    ASSERT_GE(cpu0, 0.0);
    ASSERT_GE(cpu1, 0.0);
    EXPECT_LT(cpu1 - cpu0, 0.3 * wall);
}

// Regression for the drain-lane rollback: after the full-drain restoration the
// proven vector sweep must still release a fully drained EOF client without any
// further readiness event or per-event synchronous close hook.
TEST(RuntimeDrain, RestoredSweepReleasesDrainedEofWithoutReadiness) {
    SilentMe silent;
    Daemon daemon(silent.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.worker_tid() != 0; }, 2s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    // No payload and no reply: C2S is empty, no client wire is pending and the
    // client is not awaiting a reply, so the next sweep sees a drained EOF.
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms))
        << "restored paced sweep failed to release a drained EOF client";
    EXPECT_NE(daemon.worker_tid(), 0);
}

// The retained EOF client below has nothing to write and is waiting for a
// delayed ME reply. Unrelated epoll batches must not rescan it, and the sweep
// must not call the no-progress output pump. The second connection dribbles a
// ClientHello one byte at a time, producing one reactor batch per byte.
TEST(RuntimeDrain, RetainedEofIsNotRescannedPerBatch) {
    FakeMe me{me_secret(), 1, 5000ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    reset_eof_drain_counts();

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    std::this_thread::sleep_for(250ms); // ME handshake + forward (awaiting_reply)
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    std::this_thread::sleep_for(200ms); // FIN observed, tail read to recv()==0
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 1; }, 1000ms));
    ASSERT_TRUE(wait_for([&] { return EofDrainCounts::read().visits > 0; }, 1500ms))
        << "retained EOF was never visited by a sweep";

    const EofDrainCounts before = EofDrainCounts::read();
    const Bytes hello = make_client_hello(secret_bytes(), current_timestamp(), kDomain, 0x5a);
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    const auto window_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < 40 && i < hello.size(); ++i) {
        ASSERT_EQ(::send(fd, hello.data() + i, 1, MSG_NOSIGNAL), 1);
        std::this_thread::sleep_for(5ms);
    }
    const auto window_end = std::chrono::steady_clock::now();
    ::close(fd);
    const EofDrainCounts after = EofDrainCounts::read();
    const std::uint64_t window_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(window_end - window_start).count());

    EXPECT_NE(peer_state(client.fd(), 0), 0)
        << "awaiting-reply EOF was closed without its reply";
    // The window is ~200 ms of unrelated single-byte batches. Housekeeping still
    // forces one sweep per 150 ms period, and the coalesced post-batch sweep that
    // follows each forced sweep forms a PAIR, so a window of N ms legitimately
    // contains up to 2 sweeps per 150 ms period plus a margin pair for scheduling
    // slop on loaded hosts (2 * (N/150 + 2) == 6 for a 203 ms window). This is a
    // measurement margin, not the protective invariant: a true per-batch rescan
    // regression yields ~one sweep per batch (~40 here), so the derived bound
    // still discriminates. The real protections are the output_pumps and
    // map_lookups assertions below.
    const std::uint64_t max_sweeps = 2U * (window_ms / 150U + 2U);
    EXPECT_LE(after.sweeps - before.sweeps, max_sweeps)
        << "sweeps=" << (after.sweeps - before.sweeps) << " max_sweeps=" << max_sweeps
        << " window_ms=" << window_ms;
    EXPECT_LE(after.visits - before.visits, max_sweeps)
        << "visits=" << (after.visits - before.visits) << " max_sweeps=" << max_sweeps
        << " window_ms=" << window_ms;
    // No client wire is pending, so the sweep must not call pump_client_out.
    EXPECT_EQ(after.output_pumps - before.output_pumps, 0U);
    // One token: one lookup per sweep is enough (old code did three).
    EXPECT_LE(after.map_lookups - before.map_lookups,
              (after.visits - before.visits) + (after.sweeps - before.sweeps));
}

// A fully drained EOF client (no payload, no reply) must be released by the
// sweep machinery, and the release must be visible as a sweep close. This is
// the closest observable proxy for "destruction happens at the sweep boundary,
// not synchronously inside the client event".
TEST(RuntimeDrain, DrainedEofIsReleasedBySweep) {
    SilentMe silent;
    Daemon daemon(silent.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    std::this_thread::sleep_for(350ms); // metadata poll installs the exact-DC route
    reset_eof_drain_counts();

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::this_thread::sleep_for(50ms);
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2500ms))
        << "drained EOF client was not released";
    const EofDrainCounts counts = EofDrainCounts::read();
    EXPECT_GE(counts.sweeps, 1U);
    EXPECT_GE(counts.closes, 1U) << "EOF release was not performed by the sweep path";
    EXPECT_EQ(counts.output_pumps, 0U);
}

// While a reply is outstanding, a half-closed client must stay until the
// bounded read-EOF deadline, then close within a generous bound. This also
// exercises the deadline that is published to wait_timeout_ms.
TEST(RuntimeDrain, AwaitingReplyEofHonorsReadEofDeadline) {
    FakeMe me{me_secret(), 1, 5000ms};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.shutdown_timeout = std::chrono::seconds{1};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    reset_eof_drain_counts();

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    std::this_thread::sleep_for(250ms);
    const auto started = std::chrono::steady_clock::now();
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    std::this_thread::sleep_for(400ms);
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 1U)
        << "awaiting-reply EOF closed before its bounded deadline";
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2500ms))
        << "awaiting-reply EOF did not close at the read-EOF deadline";
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, 700ms);
    EXPECT_LT(elapsed, 2500ms);
    EXPECT_GE(EofDrainCounts::read().closes, 1U);
}

// With the default 10 s shutdown_timeout, a half-closed client whose only
// pending work is an unanswered ME request is kept just for the short reply
// grace (kEofReplyGrace), not the whole shutdown_timeout.
TEST(RuntimeDrain, AwaitingReplyEofUsesShortReplyGrace) {
    FakeMe me{me_secret(), 1, 8000ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    std::this_thread::sleep_for(250ms);
    const auto started = std::chrono::steady_clock::now();
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    std::this_thread::sleep_for(1200ms);
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 1U)
        << "awaiting-reply EOF closed before the reply grace";
    ASSERT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 3000ms));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, 1800ms);
    EXPECT_LT(elapsed, 3500ms);
    EXPECT_EQ(daemon.services.stats.snapshot()
                  .relay_closes_total[static_cast<std::size_t>(
                      mtdd::control::RelayCloseReason::client_eof)],
              1U);
}

// A delayed ME reply is the only progress event. The half-closed client must be
// retained until that reply is delivered and then released without any further
// client readiness event.
TEST(RuntimeDrain, DelayedMeReplyReleasesHalfClosedClient) {
    FakeMe me{me_secret(), 1, 350ms};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    std::this_thread::sleep_for(120ms);
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 1U)
        << "EOF was closed before the ME reply arrived";

    Bytes response;
    ASSERT_TRUE(client.read_message(response, 3000));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2500ms))
        << "drained EOF was not released after the ME reply";
}

// Regression for the live failure mode: many authenticated clients half-close
// while the shared ME transport repeatedly drops and reconnects. The reactor
// must survive, release all clients, and still admit new work.
TEST(Runtime, MassFinAndMeReconnectChurnKeepsReactorResponsive) {
    // Every connection handshakes and is then dropped; the proxy reconnects and
    // churns the shared transport for the duration of the test.
    FakeMe me{me_secret(), 1, 0ms, 100000, 0ms, 5ms, false};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.worker_tid() != 0; }, 2s));

    constexpr int kClients = 32;
    std::vector<std::unique_ptr<TestClient>> clients;
    clients.reserve(kClients);
    for (int i = 0; i < kClients; ++i) {
        auto client = std::make_unique<TestClient>(
            daemon.port(), secret_bytes());
        ASSERT_TRUE(client->valid());
        ASSERT_TRUE(client->send_hello(0, static_cast<std::uint8_t>(i)));
        ASSERT_TRUE(client->start_obfuscation(2));
        // The ME may drop mid-setup; a failed send is an acceptable outcome.
        (void)client->send_message(burst_payload(static_cast<std::size_t>(i)));
        clients.push_back(std::move(client));
    }
    for (const auto& client : clients) {
        if (client->fd() >= 0) (void)::shutdown(client->fd(), SHUT_WR);
    }

    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 8000ms))
        << "restored drain did not release clients under FIN/ME churn";
    ASSERT_NE(daemon.worker_tid(), 0);

    // The worker must still accept and authenticate a fresh client.
    TestClient probe(daemon.port(), secret_bytes());
    ASSERT_TRUE(probe.valid());
    ASSERT_TRUE(probe.send_hello(0, 0x7f));
    EXPECT_GE(daemon.services.stats.snapshot().connections_active, 1U);
}

TEST(Runtime, OrdinaryCloseDoesNotSpinReactor) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.worker_tid() != 0; }, 2s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::this_thread::sleep_for(100ms);

    const pid_t tid = daemon.worker_tid();
    const double cpu0 = thread_cpu_seconds(tid);
    const auto wall0 = std::chrono::steady_clock::now();
    client.close();
    std::this_thread::sleep_for(300ms);
    const double cpu1 = thread_cpu_seconds(tid);
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall0).count();
    ASSERT_GE(cpu0, 0.0);
    ASSERT_GE(cpu1, 0.0);
    EXPECT_LT(cpu1 - cpu0, 0.3 * wall);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 1500ms));
}

TEST(Runtime, FinWhileBudgetPausedKeepsTailOrFailsClosed) {
    SilentMe silent;
    Daemon daemon(silent.port(), true, [](mtdd::Config& config) {
        config.global_buffer_bytes = 200U * 1024U;
        config.connection_queue_bytes = 32U * 1024U;
        // Keep the silent ME in handshaking longer than the FIN fail-closed
        // bound, so this test observes the FIN path, not ME failure cleanup.
        config.handshake_timeout = std::chrono::seconds{30};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    // The provider publishes asynchronously; the reactor polls every 150 ms.
    // Give it two poll intervals so the exact-DC route is installed before the
    // client reaches relay setup.
    std::this_thread::sleep_for(350ms);

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::this_thread::sleep_for(100ms);

    auto snapshot = [&] { return daemon.services.stats.snapshot(); };
    auto accepted = [&] {
        const auto current = snapshot();
        const auto user = current.users.find("alice");
        return user == current.users.end() ? 0ULL : user->second.payload_c2s_bytes;
    };
    auto backpressure = [&] { return snapshot().backpressure_c2s_total; };
    auto rejected_other = [&] {
        const auto current = snapshot();
        const auto found = current.rejected_by_reason.find("other");
        return found == current.rejected_by_reason.end() ? 0ULL : found->second;
    };

    for (int i = 0; i < 16 && backpressure() == 0; ++i) {
        ASSERT_TRUE(client.send_message(burst_payload(static_cast<std::size_t>(i))));
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_GT(backpressure(), 0U) << "test requires the documented budget pause";

    const std::uint64_t accepted_before = accepted();
    const std::uint64_t bp_before = backpressure();
    const std::uint64_t rejected_before = rejected_other();
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    bool progressed = false;
    bool failed_closed = false;
    const auto deadline = std::chrono::steady_clock::now() + 2500ms;
    while (std::chrono::steady_clock::now() < deadline) {
        if (accepted() > accepted_before) {
            progressed = true;
            break;
        }
        if (snapshot().connections_active == 0) {
            failed_closed = backpressure() > bp_before || rejected_other() > rejected_before;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_TRUE(progressed || failed_closed)
        << "FIN discarded the unread tail without progress or fail-closed accounting";
}

TEST(Runtime, LargeFinTailAcrossReadBatchesIsPreserved) {
    SilentMe silent;
    Daemon daemon(silent.port(), true, [](mtdd::Config& config) {
        config.shutdown_timeout = std::chrono::seconds{1};
        config.handshake_timeout = std::chrono::seconds{30};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    std::this_thread::sleep_for(350ms); // wait for the 150 ms reactor metadata poll

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::this_thread::sleep_for(50ms);

    std::vector<Bytes> payloads;
    constexpr std::size_t kCount = 4; // 64 KiB > one 32 KiB read batch
    for (std::size_t i = 0; i < kCount; ++i) payloads.push_back(burst_payload(i));
    ASSERT_TRUE(client.send_bulk_messages(payloads));
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    auto accepted = [&] {
        const auto current = daemon.services.stats.snapshot();
        const auto user = current.users.find("alice");
        return user == current.users.end() ? 0ULL : user->second.payload_c2s_bytes;
    };
    EXPECT_TRUE(wait_for([&] { return accepted() >= kCount * kBurstSize; }, 3000ms));
}


TEST(Runtime, FallbackRoutesNonTlsAndPreservesPrefixAndTail) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.fallback_port = echo.port(); },
                 true);
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    Bytes request;
    const std::string head = "GET / HTTP/1.1\r\nHost: mtddtest.ddproxy.xyz\r\n\r\n";
    append(request, std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(head.data()), head.size()));
    for (int i = 0; i < 2048; ++i) request.push_back(static_cast<std::uint8_t>(i));
    ASSERT_TRUE(send_all(fd, request));
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 1; }, 2000ms));
    Bytes echoed(request.size());
    ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 5000))
        << "backend accepted=" << echo.accepted() << " received=" << echo.received();
    EXPECT_EQ(echoed, request);
    EXPECT_GE(echo.accepted(), 1U);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
    EXPECT_EQ(daemon.services.stats.snapshot().active_unique_ips, 0U);
    EXPECT_EQ(daemon.services.stats.snapshot().unique_ip_history.hour, 0U);
    EXPECT_EQ(daemon.services.stats.snapshot().unique_ip_history.day, 0U);
    EXPECT_EQ(daemon.services.stats.snapshot().unique_ip_history.week, 0U);
    EXPECT_EQ(daemon.services.stats.snapshot().ip_history_observation_failures, 0U);
    EXPECT_TRUE(daemon.services.stats.snapshot().users.empty());
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
}

TEST(Runtime, FallbackPreservesOversizeClientHelloHeaderAndBody) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.fallback_port = echo.port(); });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    Bytes record(5 + 5000, 0x41);
    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x01;
    record[3] = static_cast<std::uint8_t>(5000 >> 8);
    record[4] = static_cast<std::uint8_t>(5000);
    ASSERT_TRUE(send_all(fd, record));
    Bytes echoed(record.size());
    ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 5000));
    EXPECT_EQ(echoed, record);
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
}

TEST(Runtime, FallbackPreservesUnauthenticatedClientHelloAndTail) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.fallback_port = echo.port(); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    A16 wrong{};
    for (std::size_t i = 0; i < wrong.size(); ++i) wrong[i] = 0xaa;
    const auto timestamp = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    Bytes wire = make_client_hello(wrong, timestamp, kDomain, 7);
    for (int i = 0; i < 777; ++i) wire.push_back(static_cast<std::uint8_t>(0x5a));
    ASSERT_TRUE(send_all(fd, wire));
    Bytes echoed(wire.size());
    ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 5000));
    EXPECT_EQ(echoed, wire);
    EXPECT_EQ(daemon.services.stats.snapshot().active_unique_ips, 0U);
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
}

TEST(Runtime, FallbackReplayStaysClosedAndNeverConnectsBackend) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.fallback_port = echo.port(); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    TestClient replay(daemon.port(), secret_bytes());
    ASSERT_TRUE(replay.valid());
    ASSERT_TRUE(replay.send_hello_bytes(first.hello_bytes()));
    EXPECT_TRUE(replay.wait_closed_for(2000));
    EXPECT_EQ(echo.accepted(), 0U);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "replay"), 1U);
    first.close();
}

TEST(Runtime, FallbackEnabledAuthenticatedClientStaysOnMe) {
    FakeMe me{me_secret()};
    EchoBackend echo;
    Daemon daemon(me.port(), true, [&](mtdd::Config& config) { config.fallback_port = echo.port(); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    Bytes response;
    ASSERT_TRUE(client.read_message(response, 3000));
    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(response, expected);
    EXPECT_EQ(echo.accepted(), 0U);
}

TEST(Runtime, FallbackConnectRefusalClosesPairNotProcess) {
    const std::uint16_t port = closed_loopback_port();
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.fallback_port = port; });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    const std::string prefix = "GET / HTTP/1.1\r\n\r\n";
    ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(prefix.data()),
                                 prefix.size())));
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
}

TEST(Runtime, MaskingClosesProbeForForeignServerName) {
    // Auto masking is on and no fixed target is configured: a probe whose SNI
    // does not belong to tls_domain must be closed without touching the network.
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.masking = true; });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    A16 wrong{};
    for (std::size_t i = 0; i < wrong.size(); ++i) wrong[i] = 0xaa;
    const auto timestamp = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    const Bytes wire = make_client_hello(wrong, timestamp, "foreign.test", 3);
    ASSERT_TRUE(send_all(fd, wire));
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
}

TEST(Runtime, MaskingDisabledClosesProbeWithoutFixedTarget) {
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.masking = false; });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    const std::string prefix = "GET / HTTP/1.1\r\n\r\n";
    ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(prefix.data()),
                                 prefix.size())));
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
}

TEST(Runtime, FallbackSlowBackendPreservesBurstAcrossPauses) {
    EchoBackend echo{300ms};
    Daemon daemon(1, false, [&](mtdd::Config& config) {
        config.fallback_port = echo.port();
        config.connection_queue_bytes = 16U * 1024U;
    });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    Bytes request(64U * 1024U);
    for (std::size_t i = 0; i < request.size(); ++i) {
        request[i] = static_cast<std::uint8_t>((i * 31U) & 0xffU);
    }
    ASSERT_TRUE(send_all(fd, request));
    Bytes echoed(request.size());
    ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 8000));
    EXPECT_EQ(echoed, request);
    EXPECT_EQ(echo.received(), static_cast<std::uint64_t>(request.size()));
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 3000ms));
}

TEST(Runtime, FallbackHalfCloseDeliversEchoThenEof) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) { config.fallback_port = echo.port(); });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    Bytes request(8192);
    for (std::size_t i = 0; i < request.size(); ++i) {
        request[i] = static_cast<std::uint8_t>((i * 17U) & 0xffU);
    }
    ASSERT_TRUE(send_all(fd, request));
    ASSERT_EQ(::shutdown(fd, SHUT_WR), 0);
    Bytes echoed(request.size());
    ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 5000))
        << "backend accepted=" << echo.accepted() << " received=" << echo.received();
    EXPECT_EQ(echoed, request);
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
}


TEST(Runtime, FallbackIdleDeadlineClosesIdlePair) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) {
        config.fallback_port = echo.port();
        config.idle_timeout = std::chrono::seconds{1};
    });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    const std::string prefix = "GET / HTTP/1.1\r\n\r\n";
    ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(prefix.data()),
                                 prefix.size())));
    Bytes echoed(prefix.size());
    ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
    const auto started = std::chrono::steady_clock::now();
    EXPECT_TRUE(wait_closed(fd, 4000));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, 3500ms);
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
}

TEST(Runtime, FallbackStopIsBoundedAndAccountsPair) {
    EchoBackend echo{500ms};
    Daemon daemon(1, false, [&](mtdd::Config& config) {
        config.fallback_port = echo.port();
        config.shutdown_timeout = std::chrono::seconds{1};
    });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    const std::string prefix = "GET / HTTP/1.1\r\n\r\n";
    ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(prefix.data()),
                                 prefix.size())));
    ASSERT_TRUE(wait_for([&] { return echo.accepted() >= 1; }, 2000ms));
    const auto started = std::chrono::steady_clock::now();
    daemon.stop();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, 2500ms);
    EXPECT_TRUE(wait_closed(fd, 2000));
    ::close(fd);
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 0U);
}


TEST(Runtime, FallbackRejectsWildcardOrOverlappingDestination) {
    EXPECT_THROW(
        {
            Daemon invalid(1, false, [](mtdd::Config& config) {
                config.fallback_host = "0.0.0.0";
                config.fallback_port = 18443;
            });
        },
        std::invalid_argument);
    EXPECT_THROW(
        {
            Daemon overlapping(1, false, [](mtdd::Config& config) {
                config.fallback_port = config.control_port;
            });
        },
        std::invalid_argument);
}

TEST(Runtime, FallbackReleasesHandshakeSlotForNextClient) {
    EchoBackend echo;
    Daemon daemon(1, false, [&](mtdd::Config& config) {
        config.fallback_port = echo.port();
        config.max_handshakes = 1;
        config.max_connections = 8;
    });
    for (int index = 0; index < 2; ++index) {
        const int fd = connect_loopback(daemon.port());
        ASSERT_GE(fd, 0);
        const std::string prefix = "GET / HTTP/1.1\r\n\r\n";
        ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t*>(prefix.data()),
                                     prefix.size())));
        Bytes echoed(prefix.size());
        ASSERT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
        const Bytes expected(prefix.begin(), prefix.end());
        EXPECT_EQ(echoed, expected);
        ::close(fd);
        ASSERT_TRUE(wait_for(
            [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 2000ms));
    }
}


TEST(Runtime, FallbackStalledDrainClosesWithinIdleDeadline) {
    EchoBackend echo{5000ms}; // accepted but not reading
    Daemon daemon(1, false, [&](mtdd::Config& config) {
        config.fallback_port = echo.port();
        config.connection_queue_bytes = 32U * 1024U;
        config.idle_timeout = std::chrono::seconds{1};
    });
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    Bytes request(64U * 1024U, 0x7e);
    ASSERT_TRUE(send_all(fd, request));
    ASSERT_EQ(::shutdown(fd, SHUT_WR), 0);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 3000ms));
    ::close(fd);
}



} // namespace

TEST(Runtime, SetTunablesValidatesRanges) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    EXPECT_NO_THROW(daemon.set_tunables(1500, 6));
    EXPECT_THROW(daemon.set_tunables(0, 6), std::invalid_argument);
    EXPECT_THROW(daemon.set_tunables(400, 25), std::invalid_argument);
}

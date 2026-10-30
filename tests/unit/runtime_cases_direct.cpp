#include "../support/runtime_fixture.hpp"



// ---------------------------------------------------------------------------
// Direct Telegram DC fallback (loopback fake DC)
// ---------------------------------------------------------------------------

namespace {

struct DirectEndpointScope {
    explicit DirectEndpointScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~DirectEndpointScope() {
        mtdd::detail::set_direct_endpoint_override(std::nullopt);
    }
    DirectEndpointScope(const DirectEndpointScope&) = delete;
    DirectEndpointScope& operator=(const DirectEndpointScope&) = delete;
};

void enable_direct(std::int16_t dc, mtdd::Config& config) {
    config.direct_fallback_enabled = true;
    config.direct_fallback_dcs = {dc};
    config.max_connections = 8;
    config.max_handshakes = 8;
}

} // namespace

TEST(Runtime, DirectRelayIsVerbatimOrderedAndAccounted) {
    mtdd::test::FakeDirectDc dc(2);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));

    // Sizes are 4-byte aligned so the padded-intermediate frame length is
    // preserved; the fake DC asserts the exact bytes, order and count.
    std::vector<Bytes> payloads{
        Bytes(16, 0x11), Bytes(32, 0x22), Bytes(8, 0x33), Bytes(64, 0x44), Bytes(256, 0x55)};
    ASSERT_TRUE(client.send_bulk_messages(payloads));
    // One frame larger than a FakeTLS record: exercises multi-record C2S relay
    // and the DC->client 32 KiB read / multi-record TLS send path.
    payloads.emplace_back(64 * 1024, 0x66);
    ASSERT_TRUE(client.send_message_chunked(payloads.back(), 16000));
    ASSERT_TRUE(wait_for([&] { return dc.connections() > 0 && dc.frames() == payloads.size(); }, 5000ms))
        << "direct connections=" << dc.connections() << " frames=" << dc.frames()
        << " header_ok=" << dc.header_ok() << " tag=0x" << std::hex << dc.header_tag()
        << " dc=" << std::dec << dc.header_dc();
    for (const auto& expected : payloads) {
        Bytes received;
        ASSERT_TRUE(client.read_message(received, 5000));
        EXPECT_EQ(received, expected) << "verbatim padded-intermediate payload mismatch";
    }

    ASSERT_TRUE(wait_for([&] { return dc.frames() == payloads.size(); }, 4000ms));
    EXPECT_TRUE(dc.header_ok());
    EXPECT_EQ(dc.header_tag(), 0xddddddddU);
    EXPECT_EQ(dc.header_dc(), 2);
    std::uint64_t useful = 0;
    for (const auto& payload : payloads) useful += 4 + payload.size();
    EXPECT_EQ(dc.c2s_bytes() + 4 * payloads.size(), useful);
    const auto& seen = dc.payloads();
    ASSERT_EQ(seen.size(), payloads.size());
    for (std::size_t i = 0; i < payloads.size(); ++i) EXPECT_EQ(seen[i], payloads[i]);

    ASSERT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto found = snapshot.me_dcs.find("2");
        return found != snapshot.me_dcs.end() && found->second.direct_active == 1 &&
               found->second.direct_accepted_total >= 1;
    }, 3000ms));
    const auto snapshot = daemon.services.stats.snapshot();
    const auto& stats = snapshot.me_dcs.at("2");
    EXPECT_GE(stats.direct_rx_bytes_total, dc.s2c_bytes());
    EXPECT_GE(stats.direct_tx_bytes_total, dc.c2s_bytes());
    const auto handshakes = snapshot.handshakes_by_result.find("success");
    ASSERT_NE(handshakes, snapshot.handshakes_by_result.end());
    EXPECT_GE(handshakes->second, 1U);
    const std::string text = daemon.services.stats.prometheus_text();
    EXPECT_NE(text.find("mtdd_direct_accepted_total{dc=\"2\"}"), std::string::npos);
}

TEST(Runtime, DirectBackendEofClosesAfterClientOutputDrains) {
    mtdd::test::FakeDirectDc dc(2);
    dc.close_after_responses(1);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const Bytes payload(32, 0x5a);
    ASSERT_TRUE(client.send_message(payload));
    Bytes received;
    ASSERT_TRUE(client.read_message(received, 5000));
    EXPECT_EQ(received, payload);

    EXPECT_TRUE(client.wait_closed_for(4000)) << "DC EOF must close the client";
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 3000ms));
}

TEST(Runtime, DirectClientFinStillFlushesUpstreamBatch) {
    mtdd::test::FakeDirectDc dc(2);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const std::vector<Bytes> payloads{Bytes(16, 0x01), Bytes(16, 0x02),
                                      Bytes(16, 0x03), Bytes(16, 0x04)};
    ASSERT_TRUE(client.send_bulk_messages(payloads));
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    // The FIN path returns from read_client before the coalesced gate is
    // flushed by handle_client; all four frames must still reach the DC.
    ASSERT_TRUE(wait_for([&] { return dc.frames() == payloads.size(); }, 4000ms));
    for (const auto& expected : payloads) {
        Bytes received;
        ASSERT_TRUE(client.read_message(received, 5000));
        EXPECT_EQ(received, expected);
    }
}

TEST(Runtime, DirectConnectFailureClosesClientAndIsCounted) {
    DirectEndpointScope endpoint(1);  // loopback port 1: connection refused
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    EXPECT_TRUE(client.wait_closed_for(4000));
    const bool counted = wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto found = snapshot.me_dcs.find("2");
        return found != snapshot.me_dcs.end() &&
               found->second.direct_connect_fail_total >= 1;
    }, 5000ms);
    const auto final_snapshot = daemon.services.stats.snapshot();
    EXPECT_TRUE(counted) << "active=" << final_snapshot.me_dcs.at("2").direct_active
                         << " accepted=" << final_snapshot.me_dcs.at("2").direct_accepted_total
                         << " fail=" << final_snapshot.me_dcs.at("2").direct_connect_fail_total;
    // A failed connect is not an accepted/established connection and is not a
    // successful handshake. It must still be visible as a handshake failure.
    EXPECT_EQ(final_snapshot.me_dcs.at("2").direct_accepted_total, 0U);
    const auto success = final_snapshot.handshakes_by_result.find("success");
    EXPECT_TRUE(success == final_snapshot.handshakes_by_result.end() || success->second == 0U);
    const auto failure = final_snapshot.handshakes_by_result.find("failure");
    ASSERT_NE(failure, final_snapshot.handshakes_by_result.end());
    EXPECT_GE(failure->second, 1U);
}


TEST(Runtime, DirectBudgetPauseStopsReactorSpinAndResumes) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    std::vector<Bytes> burst;
    for (int i = 0; i < 256; ++i) burst.emplace_back(16 * 1024, static_cast<std::uint8_t>(i));
    dc.send_unsolicited(burst, false);

    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        // DC reads stop once the 256 KiB client queue is full; the budget must
        // be below queue + one read reservation (~96 KiB) so the budget gate,
        // not only the queue limit, is what pauses the DC socket.
        config.global_buffer_bytes = 300U * 1024U;
        config.connection_queue_bytes = 256U * 1024U;
        config.handshake_timeout = 10s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    const std::uint64_t bp_before = daemon.services.stats.snapshot().backpressure_s2c_total;

    TestClient client{TestClient::Adopt{}, connect_loopback_with_rcvbuf(daemon.port(), 8192),
                      secret_bytes()};
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));

    auto snapshot = [&] { return daemon.services.stats.snapshot(); };
    ASSERT_TRUE(wait_for([&] { return snapshot().backpressure_s2c_total > bp_before; }, 4000ms))
        << "Direct budget gate did not close; test cannot observe the spin";
    // A transition counter, not an iteration counter: a level-triggered spin
    // would make this grow without bound during the measured window.
    ASSERT_TRUE(wait_for([&] {
        return snapshot().me_dcs.at("2").direct_budget_pauses_total >= 1;
    }, 2000ms));

    const pid_t tid = daemon.worker_tid();
    const double cpu0 = thread_cpu_seconds(tid);
    const auto wall0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(400ms);
    const double cpu1 = thread_cpu_seconds(tid);
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall0).count();
    ASSERT_GE(cpu0, 0.0);
    ASSERT_GE(cpu1, 0.0);
    EXPECT_LT(cpu1 - cpu0, 0.3 * wall)
        << "Direct EPOLLIN re-armed while budget-paused: reactor spun";
    const std::uint64_t pauses_after = snapshot().me_dcs.at("2").direct_budget_pauses_total;
    std::this_thread::sleep_for(200ms);
    EXPECT_LE(snapshot().me_dcs.at("2").direct_budget_pauses_total, pauses_after + 2U)
        << "budget-pause counter advanced like a spin loop";

    // The paused queue must still make progress once the client drains.
    for (int i = 0; i < 256; ++i) {
        Bytes received;
        ASSERT_TRUE(client.read_message(received, 10000)) << "frame " << i;
        EXPECT_EQ(received.size(), 16U * 1024U);
        EXPECT_EQ(received.front(), static_cast<std::uint8_t>(i));
    }
    EXPECT_EQ(dc.unsolicited_sent(), 256U);
}

TEST(Runtime, DirectIdleClientReleasesRetainedCapacity) {
    mtdd::test::FakeDirectDc dc(2);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    std::this_thread::sleep_for(350ms);
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().buffer_budget_used != 0;
    }, 3000ms));
    const std::uint64_t baseline = daemon.services.stats.snapshot().buffer_budget_used;


    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(Bytes(32, 0x41)));
    Bytes response;
    ASSERT_TRUE(client.read_message(response, 5000));
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().me_dcs.at("2").direct_active == 1;
    }, 3000ms));

    // Keep the connection open and idle. kIdleTrimAfter is 1 s; the 1 Hz gauge
    // tick then releases every empty queue's retained block.
    const bool trimmed = wait_for([&] {
        return daemon.services.stats.snapshot().buffer_budget_used <= baseline + 12U * 1024U;
    }, 5000ms);
    EXPECT_TRUE(trimmed) << "idle Direct client retained capacity: baseline=" << baseline
                         << " now=" << daemon.services.stats.snapshot().buffer_budget_used;
}

TEST(Runtime, DirectRdhupDrainsTailBeforeClose) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    std::vector<Bytes> tail;
    for (int i = 0; i < 24; ++i) tail.emplace_back(16 * 1024, static_cast<std::uint8_t>(0x80 + i));
    dc.send_unsolicited(tail, /*shutdown_write=*/true);

    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.connection_queue_bytes = 256U * 1024U;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::this_thread::sleep_for(300ms);  // let the proxy queue fill and observe FIN
    for (int i = 0; i < 24; ++i) {
        Bytes received;
        ASSERT_TRUE(client.read_message(received, 8000)) << "tail frame " << i << " truncated";
        ASSERT_EQ(received.size(), 16U * 1024U);
        EXPECT_EQ(received.front(), static_cast<std::uint8_t>(0x80 + i));
    }
}

TEST(Runtime, DirectShutdownDrainsPendingUpload) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    dc.pause_reading();
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.connection_queue_bytes = 16U * 1024U * 1024U;
        config.global_buffer_bytes = 64U * 1024U * 1024U;
        config.shutdown_timeout = 8s;
        config.idle_timeout = 120s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::vector<Bytes> upload(512, Bytes(16 * 1024, 0x51));
    ASSERT_TRUE(client.send_bulk_messages(upload));
    // The fake DC is paused: its frames() counter cannot advance yet. Give the
    // reactor time to move client bytes into direct_out/socket buffers.
    std::this_thread::sleep_for(300ms);

    std::thread resume([&] {
        std::this_thread::sleep_for(150ms);
        dc.resume_reading();
    });
    daemon.stop();
    resume.join();

    EXPECT_TRUE(wait_for([&] { return dc.frames() == upload.size(); }, 3000ms))
        << "graceful shutdown dropped Direct upload: frames=" << dc.frames()
        << " expected=" << upload.size();
}

TEST(Runtime, DirectQueueBytesReachBufferGauge) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    dc.pause_reading();
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.connection_queue_bytes = 8U * 1024U * 1024U;
        config.global_buffer_bytes = 64U * 1024U * 1024U;
        config.idle_timeout = 120s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::vector<Bytes> upload(256, Bytes(16 * 1024, 0x52));
    ASSERT_TRUE(client.send_bulk_messages(upload));
    ASSERT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        return snapshot.buffer_bytes[static_cast<std::size_t>(mtdd::control::BufferState::queued)] > 0 &&
               snapshot.buffer_bytes[static_cast<std::size_t>(mtdd::control::BufferState::pending_write)] > 0;
    }, 4000ms)) << "Direct upload backlog is missing from the queued/pending gauges";
    EXPECT_LT(dc.frames(), upload.size());
    dc.resume_reading();
}


TEST(Runtime, DirectFinSweepPumpsPendingQueue) {
    auto& telemetry = mtdd::detail::direct_drain_telemetry();
    telemetry.pumps.store(0, std::memory_order_relaxed);

    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    dc.pause_reading();
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.connection_queue_bytes = 16U * 1024U * 1024U;
        config.global_buffer_bytes = 64U * 1024U * 1024U;
        config.shutdown_timeout = 10s;
        config.idle_timeout = 120s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    std::vector<Bytes> upload(512, Bytes(16 * 1024, 0x62));
    ASSERT_TRUE(client.send_bulk_messages(upload));
    std::this_thread::sleep_for(300ms);
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);

    // The FIN sweep must explicitly pump direct_out; without the branch this
    // counter stays zero and the queue would only move on a later EPOLLOUT.
    EXPECT_TRUE(wait_for([&] {
        return telemetry.pumps.load(std::memory_order_relaxed) > 0;
    }, 3000ms)) << "Direct FIN sweep never pumped the pending upstream queue";

    dc.resume_reading();
    EXPECT_TRUE(wait_for([&] { return dc.frames() == upload.size(); }, 5000ms))
        << "FIN drain lost bytes: frames=" << dc.frames();
}

TEST(Runtime, DirectBackendExceptionClosesOnlyOwner) {
    mtdd::test::FakeDirectDc dc(2);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    mtdd::detail::set_direct_event_throw_for_test(1);
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    ASSERT_TRUE(first.start_obfuscation(2));
    EXPECT_TRUE(first.wait_closed_for(4000));

    // The process must survive the per-event exception: a second client still
    // completes a request instead of hitting the fatal shutdown path. A
    // different hello variant avoids the deliberate replay-cache duplicate.
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(second.send_hello(0, 1));
    ASSERT_TRUE(second.start_obfuscation(2));
    ASSERT_TRUE(second.send_message(Bytes(32, 0x77)));
    Bytes response;
    ASSERT_TRUE(second.read_message(response, 5000));
}

TEST(Runtime, RemoteClosePostEncodeFailureFailsSharedSession) {
    mtdd::detail::set_remote_close_push_failure_for_test(1);
    FakeMe me{me_secret(), 1, std::chrono::milliseconds{0}, 1, std::chrono::milliseconds{0},
              std::chrono::milliseconds{0}, false, 0, 400, kBurstSize, true, 1};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));

    // Forcing the post-encode push to fail must tear down the shared session,
    // not silently drop a frame after write_seq/CBC advanced.
    EXPECT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto found = snapshot.me_dcs.find("2");
        return found != snapshot.me_dcs.end() && !found->second.connected;
    }, 4000ms)) << "session stayed ready after an encoded close frame was lost";
    mtdd::detail::set_remote_close_push_failure_for_test(0);
}



TEST(Runtime, DirectHalfCloseWithDcFinDrainsTail) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    std::vector<Bytes> tail;
    for (int i = 0; i < 256; ++i) {
        tail.emplace_back(16 * 1024, static_cast<std::uint8_t>(0x40 + (i & 0x3f)));
    }
    dc.send_unsolicited(tail, /*shutdown_write=*/true);

    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.connection_queue_bytes = 256U * 1024U;
        config.max_frame_bytes = 8U * 1024U * 1024U;
        config.shutdown_timeout = 8s;
        config.idle_timeout = 120s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client{TestClient::Adopt{}, connect_loopback_with_rcvbuf(daemon.port(), 8192),
                      secret_bytes()};
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    // Half-close the client write side, then let the queue fill / FIN arrive
    // before reading the DC tail.
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    std::this_thread::sleep_for(300ms);

    std::size_t delivered = 0;
    for (; delivered < 256; ++delivered) {
        Bytes received;
        if (!client.read_message(received, 10000)) break;
        if (received.size() != 16U * 1024U ||
            received.front() != static_cast<std::uint8_t>(0x40 + (delivered & 0x3f))) {
            break;
        }
    }
    const auto snapshot = daemon.services.stats.snapshot();
    const auto& dc_stats = snapshot.me_dcs.at("2");
    EXPECT_EQ(delivered, 256U)
        << "tail truncated after client SHUT_WR + DC FIN: delivered=" << delivered
        << " sent=" << dc.unsolicited_sent() << " s2c=" << dc.s2c_bytes()
        << " active=" << snapshot.connections_active
        << " eof_closes=" << mtdd::detail::eof_drain_telemetry().closes.load()
        << " direct_pumps=" << mtdd::detail::direct_drain_telemetry().pumps.load()
        << " direct_active=" << dc_stats.direct_active
        << " rx=" << dc_stats.direct_rx_bytes_total << " tx=" << dc_stats.direct_tx_bytes_total;
}

TEST(Runtime, DirectHalfCloseWithoutDcFinResumesTail) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    std::vector<Bytes> tail;
    for (int i = 0; i < 256; ++i) {
        tail.emplace_back(16 * 1024, static_cast<std::uint8_t>(0x60 + (i & 0x3f)));
    }
    dc.send_unsolicited(tail, /*shutdown_write=*/false);

    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.connection_queue_bytes = 256U * 1024U;
        config.max_frame_bytes = 8U * 1024U * 1024U;
        config.shutdown_timeout = 8s;
        config.idle_timeout = 120s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client{TestClient::Adopt{}, connect_loopback_with_rcvbuf(daemon.port(), 8192),
                      secret_bytes()};
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(Bytes(32, 0x31)));
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    std::this_thread::sleep_for(300ms);

    std::size_t delivered = 0;
    for (; delivered < 256; ++delivered) {
        Bytes received;
        if (!client.read_message(received, 5000)) break;
        if (received.size() != 16U * 1024U ||
            received.front() != static_cast<std::uint8_t>(0x60 + (delivered & 0x3f))) {
            break;
        }
    }
    const auto snapshot = daemon.services.stats.snapshot();
    const auto& dc_stats = snapshot.me_dcs.at("2");
    EXPECT_EQ(delivered, 256U)
        << "Direct tail stalled after SHUT_WR without a DC FIN: delivered=" << delivered
        << " sent=" << dc.unsolicited_sent() << " s2c=" << dc.s2c_bytes()
        << " active=" << snapshot.connections_active
        << " eof_closes=" << mtdd::detail::eof_drain_telemetry().closes.load()
        << " direct_pumps=" << mtdd::detail::direct_drain_telemetry().pumps.load()
        << " direct_active=" << dc_stats.direct_active
        << " rx=" << dc_stats.direct_rx_bytes_total << " tx=" << dc_stats.direct_tx_bytes_total;
}

// Opt-in controlled budget-pressure benchmark. It parks a Direct client behind
// the DC->client budget gate with unread DC data, measures the reactor for a
// fixed window, then proves the same frames/bytes still make progress. Compare
// the pre-fix and fixed builds with the same harness.
TEST(Runtime, DirectBudgetPressureBenchmark) {
    if (std::getenv("MTDD_DIRECT_BUDGET_BENCH") == nullptr) {
        GTEST_SKIP() << "set MTDD_DIRECT_BUDGET_BENCH=1 to run the budget-pressure benchmark";
    }
    constexpr std::size_t kFrames = 256;
    constexpr std::size_t kFrameBytes = 16 * 1024;

    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    std::vector<Bytes> burst;
    for (std::size_t i = 0; i < kFrames; ++i) {
        burst.emplace_back(kFrameBytes, static_cast<std::uint8_t>(i));
    }
    dc.send_unsolicited(burst, false);

    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.global_buffer_bytes = 400U * 1024U;
        config.connection_queue_bytes = 256U * 1024U;
        config.handshake_timeout = 10s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));

    auto snapshot = [&] { return daemon.services.stats.snapshot(); };
    const std::uint64_t bp_before = snapshot().backpressure_s2c_total;
    ASSERT_TRUE(wait_for([&] { return snapshot().backpressure_s2c_total > bp_before; }, 4000ms));
    const std::uint64_t bp_at_park = snapshot().backpressure_s2c_total;

    const pid_t tid = daemon.worker_tid();
    const double cpu0 = thread_cpu_seconds(tid);
    const auto wall0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(400ms);
    const auto wall1 = std::chrono::steady_clock::now();
    const double cpu1 = thread_cpu_seconds(tid);
    const double wall = std::chrono::duration<double>(wall1 - wall0).count();
    const std::uint64_t bp_delta = snapshot().backpressure_s2c_total - bp_at_park;

    std::size_t delivered = 0;
    for (; delivered < kFrames; ++delivered) {
        Bytes received;
        if (!client.read_message(received, 10000)) break;
        if (received.size() != kFrameBytes ||
            received.front() != static_cast<std::uint8_t>(delivered)) {
            break;
        }
    }
    std::cout << "DIRECT_H1_BENCH frames=" << kFrames
              << " useful_bytes=" << kFrames * kFrameBytes
              << " window_ms=" << static_cast<long long>(wall * 1000)
              << " reactor_cpu_s=" << (cpu1 - cpu0)
              << " backpressure_events_during_window=" << bp_delta
              << " delivered_frames=" << delivered << std::endl;
    EXPECT_EQ(delivered, kFrames);
}

// Synthetic loopback benchmark for the Direct C2S batching path. It is opt-in
// (MTDD_DIRECT_BENCH=1) so the normal suite stays deterministic. It reports
// reactor-thread CPU and fake-DC receive-call counts at a fixed useful byte
// count; it is not a production throughput claim.
TEST(Runtime, DirectLoopbackBatchBenchmark) {
    if (std::getenv("MTDD_DIRECT_BENCH") == nullptr) {
        GTEST_SKIP() << "set MTDD_DIRECT_BENCH=1 to run the loopback benchmark";
    }
    constexpr std::size_t kMessages = 60000;
    constexpr std::size_t kBatch = 1024;
    constexpr std::size_t kPayload = 64;
    constexpr std::size_t kWarmup = 512;

    mtdd::test::FakeDirectDc dc(2);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));

    const Bytes payload(kPayload, 0x6b);
    const auto run_batch = [&](std::size_t messages) {
        std::size_t done = 0;
        while (done < messages) {
            const std::size_t take = std::min(kBatch, messages - done);
            std::vector<Bytes> burst(take, payload);
            EXPECT_TRUE(client.send_bulk_messages(burst));
            for (std::size_t i = 0; i < take; ++i) {
                Bytes response;
                EXPECT_TRUE(client.read_message(response, 10000));
                EXPECT_EQ(response, payload);
            }
            done += take;
        }
    };
    run_batch(kWarmup);
    ASSERT_TRUE(wait_for([&] { return dc.frames() == kWarmup; }, 4000ms));

    const std::uint64_t recv_before = dc.recv_calls();
    const std::uint64_t send_before = dc.send_calls();
    const std::uint64_t frames_before = dc.frames();
    const double cpu_before = thread_cpu_seconds(daemon.worker_tid());
    const auto wall_before = std::chrono::steady_clock::now();

    run_batch(kMessages);

    const auto wall_after = std::chrono::steady_clock::now();
    const double cpu_after = thread_cpu_seconds(daemon.worker_tid());
    const std::uint64_t recv_after = dc.recv_calls();
    const std::uint64_t send_after = dc.send_calls();
    const std::uint64_t frames_after = dc.frames();
    ASSERT_TRUE(wait_for([&] { return dc.frames() == kWarmup + kMessages; }, 5000ms));

    const auto wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall_after - wall_before).count();
    const std::uint64_t useful = kMessages * kPayload;
    EXPECT_EQ(frames_after - frames_before, kMessages);
    EXPECT_EQ(dc.c2s_bytes(), (kWarmup + kMessages) * kPayload);
    std::cout << "DIRECT_BENCH messages=" << kMessages
              << " useful_bytes=" << useful
              << " wall_ms=" << wall_ms
              << " worker_cpu_s=" << (cpu_after - cpu_before)
              << " dc_recv_calls=" << (recv_after - recv_before)
              << " dc_send_calls=" << (send_after - send_before)
              << " payload_bytes_per_msg=" << kPayload
              << " batch=" << kBatch << std::endl;
}
TEST(DirectFlushGate, CoalescesMultipleMarksIntoOneFlush) {
    mtdd::detail::DirectFlushGate gate;
    gate.mark();
    gate.mark();
    gate.mark();
    EXPECT_TRUE(gate.pending());
    EXPECT_TRUE(gate.take());
    EXPECT_FALSE(gate.pending());
    EXPECT_FALSE(gate.take()) << "a drained batch must not spin a second flush";
}

TEST(DirectFlushGate, EmptyGateNeverReportsWork) {
    mtdd::detail::DirectFlushGate gate;
    for (int i = 0; i < 1000; ++i) EXPECT_FALSE(gate.take());
    EXPECT_FALSE(gate.pending());
}

TEST(DirectFlushGate, ClearDropsPendingWorkOnCloseOrEof) {
    mtdd::detail::DirectFlushGate gate;
    gate.mark();
    gate.clear();
    EXPECT_FALSE(gate.pending());
    EXPECT_FALSE(gate.take());
}

TEST(Runtime, DirectBudgetReturnsToBaselineAfterClientChurn) {
    mtdd::test::FakeDirectDc dc(2);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_direct(2, config);
        config.global_buffer_bytes = 2U * 1024U * 1024U;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    const std::uint64_t baseline = daemon.services.stats.snapshot().buffer_budget_used;
    {
        TestClient client(daemon.port(), secret_bytes());
        ASSERT_TRUE(client.valid());
        ASSERT_TRUE(client.send_hello());
        ASSERT_TRUE(client.start_obfuscation(2));
        std::vector<Bytes> burst(32, Bytes(4096, 0x7c));
        ASSERT_TRUE(client.send_bulk_messages(burst));
        for (std::size_t i = 0; i < burst.size(); ++i) {
            Bytes response;
            ASSERT_TRUE(client.read_message(response, 10000));
            EXPECT_EQ(response, burst[i]);
        }
    }
    EXPECT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().connections_active == 0;
    }, 4000ms));
    EXPECT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().buffer_budget_used <=
               baseline + 512U * 1024U;
    }, 4000ms)) << "Direct queue capacities did not return to baseline";
}

// ---------------------------------------------------------------------------
// Multi-reactor (SO_REUSEPORT) coverage
// ---------------------------------------------------------------------------

namespace {
std::size_t workers_with_traffic(const std::vector<std::uint64_t>& counts) {
    return static_cast<std::size_t>(
        std::count_if(counts.begin(), counts.end(),
                      [](std::uint64_t value) { return value != 0; }));
}
} // namespace

// 64 authenticated clients relay through one shared port while four reactors
// each own their own ME connection. Telemetry must prove that more than one
// reactor actually accepted TCP connections.
TEST(Runtime, FourWorkersRelaySixtyFourClientsAndDistributeAccepts) {
    MultiFakeMe me{me_secret(), 4};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 128;
        config.max_handshakes = 128;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_EQ(daemon.workers(), 4U);
    ASSERT_TRUE(me.wait_for_connections(4, 8s)) << "not every reactor reached the fake ME";
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    const Bytes expected{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    std::vector<std::unique_ptr<TestClient>> clients;
    clients.reserve(64);
    for (std::size_t index = 0; index < 64; ++index) {
        auto client = std::make_unique<TestClient>(daemon.port(), secret_bytes());
        ASSERT_TRUE(client->valid()) << "client " << index;
        ASSERT_TRUE(client->send_hello(0, static_cast<std::uint8_t>(index))) << index;
        ASSERT_TRUE(client->start_obfuscation(2)) << index;
        ASSERT_TRUE(client->send_message(Bytes(32, static_cast<std::uint8_t>(index))))
            << index;
        Bytes response;
        ASSERT_TRUE(client->read_message(response)) << index;
        EXPECT_EQ(response, expected) << index;
        clients.push_back(std::move(client));
    }
    EXPECT_EQ(me.frames(), 64U);

    const auto counts = daemon.accepted_per_worker();
    ASSERT_EQ(counts.size(), 4U);
    EXPECT_EQ(std::accumulate(counts.begin(), counts.end(), std::uint64_t{0}), 64U);
    EXPECT_GE(workers_with_traffic(counts), 2U) << "SO_REUSEPORT did not spread accepts";

    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_EQ(snapshot.connections_active, 64U);
    ASSERT_NE(snapshot.users.find("alice"), snapshot.users.end());
    EXPECT_EQ(snapshot.users.at("alice").active_connections, 64U);
    EXPECT_EQ(snapshot.active_unique_ips, 1U);
    EXPECT_TRUE(snapshot.ready);
    // Every reactor owns its own pooled ME connection, so the per-DC gauges must
    // report all four; a single shared slot would collapse this to one.
    ASSERT_NE(snapshot.me_dcs.find("2"), snapshot.me_dcs.end());
    EXPECT_TRUE(snapshot.me_dcs.at("2").connected);
    EXPECT_EQ(snapshot.me_dcs.at("2").connections, 4U);
    EXPECT_EQ(snapshot.me_dcs.at("2").proxy_ans_received_total, 64U);

    for (const auto& client : clients) client->close();
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 5s));
    EXPECT_EQ(daemon.services.stats.snapshot().active_unique_ips, 0U);
}

// The replay cache is shared, so a ClientHello accepted on one reactor must be
// rejected when it is replayed into another one.
TEST(Runtime, ReplayCacheRejectsHelloOnAnotherReactor) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 128;
        config.max_handshakes = 128;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));

    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    const auto accepted_before = daemon.accepted_per_worker();
    std::size_t first_worker = accepted_before.size();
    for (std::size_t index = 0; index < accepted_before.size(); ++index) {
        if (accepted_before[index] == 1) first_worker = index;
    }
    ASSERT_LT(first_worker, accepted_before.size());

    std::size_t rejected_here = 0;
    for (int attempt = 0; attempt < 32; ++attempt) {
        TestClient replay(daemon.port(), secret_bytes());
        ASSERT_TRUE(replay.valid());
        ASSERT_TRUE(replay.send_hello_bytes(first.hello_bytes()));
        EXPECT_FALSE(replay.peer_sent_data(500));
        if (replay.wait_closed_for(1500)) ++rejected_here;
    }
    EXPECT_GE(rejected_here, 31U);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "replay"), 31U);

    const auto rejected = daemon.replay_per_worker();
    ASSERT_EQ(rejected.size(), 4U);
    EXPECT_GE(workers_with_traffic(rejected), 2U);
    bool rejected_elsewhere = false;
    for (std::size_t index = 0; index < rejected.size(); ++index) {
        if (index != first_worker && rejected[index] != 0) rejected_elsewhere = true;
    }
    EXPECT_TRUE(rejected_elsewhere) << "replay cache did not reject across reactors";
}

// A per-user cap is a process-wide reservation. Four reactors may accept the
// TCP connections, but exactly one ClientHello establishes a session.
TEST(Runtime, PerUserConnectionCapIsGlobalAcrossReactors) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 128;
        config.max_handshakes = 128;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex), 1));

    std::vector<std::unique_ptr<TestClient>> clients;
    std::size_t established = 0;
    constexpr std::size_t kAttempts = 32;
    for (std::size_t index = 0; index < kAttempts; ++index) {
        auto client = std::make_unique<TestClient>(daemon.port(), secret_bytes());
        ASSERT_TRUE(client->valid()) << index;
        if (client->send_hello(0, static_cast<std::uint8_t>(index))) ++established;
        clients.push_back(std::move(client));
    }
    EXPECT_EQ(established, 1U) << "per-user cap admitted more than one session";
    EXPECT_EQ(daemon.services.stats.snapshot().users.at("alice").active_connections, 1U);
    EXPECT_GE(stat_counter(daemon.services.stats, "rejected", "user_connection_limit"),
              kAttempts - 1);

    const auto counts = daemon.accepted_per_worker();
    EXPECT_EQ(std::accumulate(counts.begin(), counts.end(), std::uint64_t{0}), kAttempts);
    EXPECT_GE(workers_with_traffic(counts), 2U)
        << "the cap test never exercised multiple reactors";

    for (const auto& client : clients) client->close();
    EXPECT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto user = snapshot.users.find("alice");
        return snapshot.connections_active == 0 && user != snapshot.users.end() &&
               user->second.active_connections == 0;
    }, 5s));
}

// Deleting a user must close sessions on every reactor before the mutation is
// acknowledged. The RevisionBarrier minimum proves that all workers applied it.
TEST(Runtime, UserDeletionClosesSessionsOnEveryReactorBeforeAck) {
    MultiFakeMe me{me_secret(), 4};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 128;
        config.max_handshakes = 128;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(me.wait_for_connections(4, 8s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));

    constexpr std::size_t kClients = 32;
    std::vector<std::unique_ptr<TestClient>> clients;
    clients.reserve(kClients);
    for (std::size_t index = 0; index < kClients; ++index) {
        auto client = std::make_unique<TestClient>(daemon.port(), secret_bytes());
        ASSERT_TRUE(client->valid()) << index;
        ASSERT_TRUE(client->send_hello(0, static_cast<std::uint8_t>(index))) << index;
        ASSERT_TRUE(client->start_obfuscation(2)) << index;
        ASSERT_TRUE(client->send_message(Bytes(32, 0x41))) << index;
        Bytes response;
        ASSERT_TRUE(client->read_message(response)) << index;
        clients.push_back(std::move(client));
    }
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().users.at("alice").active_connections ==
               kClients;
    }, 5s));
    EXPECT_GE(workers_with_traffic(daemon.accepted_per_worker()), 2U);

    auto deleted =
        daemon.services.store->delete_user(mtdd::control::DeleteUserRequest{"alice", {}});
    ASSERT_TRUE(deleted.ok());
    EXPECT_TRUE(deleted.value().applied);
    EXPECT_FALSE(deleted.value().pending);
    // The ack is returned only after every reactor applied the snapshot, so
    // every relay session must already be closing.
    for (const auto& client : clients) {
        EXPECT_TRUE(client->wait_closed_for(1000));
    }
    EXPECT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto user = snapshot.users.find("alice");
        return snapshot.connections_active == 0 && snapshot.active_unique_ips == 0 &&
               user != snapshot.users.end() && user->second.active_connections == 0 &&
               user->second.unique_ips_active == 0;
    }, 5s));
}

// request_stop() is process-wide: run() must join every reactor thread before
// returning, and no listener may stay bound behind it.
TEST(Runtime, GracefulStopJoinsAllReactorThreads) {
    MultiFakeMe me{me_secret(), 4};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 128;
        config.max_handshakes = 128;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(me.wait_for_connections(4, 8s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 5s));
    ASSERT_EQ(daemon.workers(), 4U);

    const std::uint16_t port = daemon.port();
    daemon.stop();
    EXPECT_FALSE(daemon.services.stats.ready());
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 0U);
    const int after_stop = connect_loopback(port);
    if (after_stop >= 0) {
        ::close(after_stop);
        FAIL() << "a reactor listener was still accepting after run() returned";
    }
}

// workers=0 resolves to hardware_concurrency() (bounded by the reactor cap and
// by the per-reactor buffer budget). Verify the documented default end to end.
TEST(Runtime, WorkersZeroUsesHardwareConcurrency) {
    const std::size_t cores = std::max<std::size_t>(
        std::thread::hardware_concurrency(), 1U);
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.workers = 0;
        config.max_frame_bytes = 4096;
        config.connection_queue_bytes = 4096;
        // Room for the full 256-reactor cap: 256 * ~80 KiB.
        config.global_buffer_bytes = 64U * 1024U * 1024U;
    });
    EXPECT_EQ(daemon.workers(), std::min<std::size_t>(cores, 256U));
    EXPECT_NE(daemon.port(), 0U);
}

// A fatal exception in one reactor must stop every reactor, be rethrown by
// Runtime::run(), and leave no listener accepting.
TEST(Runtime, FatalErrorInOneReactorStopsEveryReactor) {
    mtdd::detail::clear_reactor_fatal_for_test();
    Services services(1, false, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 128;
        config.max_handshakes = 128;
    });
    ASSERT_TRUE(services.add_user("alice", std::string(kSecretHex)));
    mtdd::Runtime runtime{services.config, *services.store, services.stats,
                          *services.metadata, services.barrier};
    ASSERT_EQ(runtime.worker_count(), 4U);
    const std::uint16_t port = runtime.port();
    ASSERT_NE(port, 0U);

    // Target a worker thread, not the reactor driven by run() itself.
    mtdd::detail::set_reactor_fatal_for_test(2);
    EXPECT_THROW(runtime.run(), std::runtime_error);
    mtdd::detail::clear_reactor_fatal_for_test();

    EXPECT_FALSE(services.stats.ready());
    EXPECT_EQ(services.stats.snapshot().connections_active, 0U);
    const int after = connect_loopback(port);
    if (after >= 0) {
        ::close(after);
        FAIL() << "a reactor listener stayed bound after the fatal error";
    }
}

// The global max_connections cap is process-wide, not per reactor, and a
// reactor that paused accepting at the cap resumes after another reactor frees
// a slot.
TEST(Runtime, GlobalConnectionCapAcrossReactors) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 8;
        config.max_handshakes = 8;
        // Keep admitted sockets alive: this test never completes a handshake.
        config.handshake_timeout = 30s;
    });
    // A small global cap also means a small listen backlog, so the client opens
    // only cap + a few sockets. Opening many more would overflow the accept
    // queue of a paused reactor and block connect() on SYN retries.
    constexpr std::size_t kAttempts = 12;
    std::vector<int> sockets;
    sockets.reserve(kAttempts);
    for (std::size_t index = 0; index < kAttempts; ++index) {
        const int fd = connect_loopback(daemon.port());
        ASSERT_GE(fd, 0) << index;
        sockets.push_back(fd);
    }

    auto admitted = [&] {
        const auto counts = daemon.accepted_per_worker();
        return std::accumulate(counts.begin(), counts.end(), std::uint64_t{0});
    };
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.snapshot().connections_active == 8; },
                         5s));
    EXPECT_EQ(admitted(), 8U) << "the per-reactor cap admitted more than the global cap";
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 8U);

    // Free four slots. Listeners of every reactor were paused at the global cap;
    // the housekeeping tick must re-arm them and admit the queued sockets even
    // when the free slot was released by a *different* reactor.
    for (std::size_t index = 0; index < 4; ++index) {
        ::close(sockets[index]);
        sockets[index] = -1;
    }
    EXPECT_TRUE(wait_for([&] { return admitted() >= 9U; }, 5s))
        << "listeners paused at the global cap never re-armed: admitted=" << admitted();
    EXPECT_LE(admitted(), 12U);

    for (const int fd : sockets) {
        if (fd >= 0) ::close(fd);
    }
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 5s));
}

// max_handshakes is a process-wide admission budget: four reactors may accept
// TCP sockets, but only the global number of handshake slots gets a Client.
TEST(Runtime, MaxHandshakesIsProcessWideAcrossReactors) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.workers = 4;
        config.max_connections = 64;
        config.max_handshakes = 2;
        config.handshake_timeout = 30s;
    });
    constexpr std::size_t kAttempts = 12;
    std::vector<int> sockets;
    sockets.reserve(kAttempts);
    for (std::size_t index = 0; index < kAttempts; ++index) {
        const int fd = connect_loopback(daemon.port());
        ASSERT_GE(fd, 0) << index;
        sockets.push_back(fd);
    }
    ASSERT_TRUE(wait_for([&] {
        return stat_counter(daemon.services.stats, "rejected", "overload") >=
               kAttempts - 2;
    }, 5s)) << "per-reactor handshake budgets multiplied the global limit";
    // Every socket is still admitted at the TCP layer; only two get a Client.
    const auto counts = daemon.accepted_per_worker();
    EXPECT_EQ(std::accumulate(counts.begin(), counts.end(), std::uint64_t{0}), kAttempts);
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 2U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "overload"), kAttempts - 2);
    for (const int fd : sockets) ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return daemon.services.stats.snapshot().connections_active == 0; }, 5s));
}

// Unidirectional C2S variant: the fake DC never answers, so an external
// strace can attribute sendto() calls to the proxy's Direct flush path without
// the 60k response writes dominating the count. Opt-in only.
TEST(Runtime, DirectLoopbackC2sBenchmark) {
    if (std::getenv("MTDD_DIRECT_BENCH_C2S") == nullptr) {
        GTEST_SKIP() << "set MTDD_DIRECT_BENCH_C2S=1 to run the C2S benchmark";
    }
    constexpr std::size_t kMessages = 60000;
    constexpr std::size_t kBatch = 1024;
    constexpr std::size_t kPayload = 64;

    mtdd::test::FakeDirectDc dc(2, /*respond=*/false);
    DirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_direct(2, config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));

    const Bytes payload(kPayload, 0x6b);
    const double cpu_before = thread_cpu_seconds(daemon.worker_tid());
    const auto wall_before = std::chrono::steady_clock::now();
    std::size_t done = 0;
    while (done < kMessages) {
        const std::size_t take = std::min(kBatch, kMessages - done);
        std::vector<Bytes> burst(take, payload);
        ASSERT_TRUE(client.send_bulk_messages(burst));
        done += take;
    }
    ASSERT_TRUE(wait_for([&] { return dc.frames() == kMessages; }, 15000ms));
    const auto wall_after = std::chrono::steady_clock::now();
    const double cpu_after = thread_cpu_seconds(daemon.worker_tid());
    const auto wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall_after - wall_before).count();
    std::cout << "DIRECT_BENCH_C2S messages=" << kMessages
              << " useful_bytes=" << kMessages * kPayload
              << " wall_ms=" << wall_ms
              << " worker_cpu_s=" << (cpu_after - cpu_before)
              << " dc_recv_calls=" << dc.recv_calls()
              << " batch=" << kBatch << std::endl;
}

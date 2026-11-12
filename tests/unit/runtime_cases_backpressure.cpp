#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// Client->server backpressure: a slow upstream pauses client reads (TCP
// backpressure) instead of closing the client once a queue limit is reached.
// ---------------------------------------------------------------------------

namespace {

struct BackpressureDirectScope {
    explicit BackpressureDirectScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~BackpressureDirectScope() { mtdd::detail::set_direct_endpoint_override(std::nullopt); }
    BackpressureDirectScope(const BackpressureDirectScope&) = delete;
    BackpressureDirectScope& operator=(const BackpressureDirectScope&) = delete;
};

constexpr std::size_t kUploadFrameBytes = 16U * 1024U;
// Upper bound for one upload; the stall point is far below it (proxy queue
// plus kernel socket buffers), so reaching it means the proxy never paused.
constexpr std::size_t kUploadMaxFrames = 4096;  // 64 MiB

// Client socket with a small send buffer: the client's own kernel buffering is
// part of what must fill before its send blocks.
int connect_small_sndbuf(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    const int sndbuf = 64 * 1024;
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    timeval timeout{};
    timeout.tv_sec = 3;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

Bytes direct_upload_payload(std::size_t index) {
    Bytes payload(kUploadFrameBytes);
    for (std::size_t k = 0; k < payload.size(); ++k) {
        payload[k] = static_cast<std::uint8_t>((index * 31U + k * 7U) & 0xffU);
    }
    for (std::size_t k = 0; k < 4; ++k) {
        payload[k] = static_cast<std::uint8_t>(index >> (8 * k));
    }
    return payload;
}

// Non-blocking FakeTLS uploader for a session set up by TestClient (hello and
// obfuscation record). make_obfuscation() is deterministic, so this mirrors
// TestClient's client->proxy cipher; TestClient::send_* must not be used after
// it starts. read_message() is unaffected (separate direction).
class Uploader {
public:
    enum class Result { done, stalled, failed };

    Uploader(int fd, std::int16_t dc, std::function<Bytes(std::size_t)> payload)
        : fd_(fd), payload_(std::move(payload)) {
        const auto obfuscation = make_obfuscation(secret_bytes(), dc);
        c2s_.emplace(obfuscation.decrypt_key, obfuscation.decrypt_iv);
        c2s_->skip(64);
    }

    // Sends frames until `count` frames are fully accepted by the kernel
    // (done), no byte was accepted for `stall` (stalled), or the socket fails.
    Result pump(std::size_t count, std::chrono::milliseconds stall) {
        auto last_progress = std::chrono::steady_clock::now();
        while (true) {
            if (offset_ == pending_.size()) {
                if (next_ >= count) return Result::done;
                Bytes frame;
                const Bytes payload = payload_(next_);
                put32(frame, static_cast<std::uint32_t>(payload.size()));
                append(frame, payload);
                c2s_->apply(frame);
                pending_ = tls_record(0x17, frame);
                offset_ = 0;
                ++next_;
            }
            const ssize_t sent = ::send(fd_, pending_.data() + offset_, pending_.size() - offset_,
                                        MSG_DONTWAIT | MSG_NOSIGNAL);
            if (sent > 0) {
                offset_ += static_cast<std::size_t>(sent);
                bytes_ += static_cast<std::uint64_t>(sent);
                last_progress = std::chrono::steady_clock::now();
                continue;
            }
            if (sent < 0 && errno == EINTR) continue;
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (std::chrono::steady_clock::now() - last_progress >= stall) {
                    return Result::stalled;
                }
                pollfd entry{fd_, POLLOUT, 0};
                (void)::poll(&entry, 1, 20);
                continue;
            }
            return Result::failed;
        }
    }

    // Frames whose TLS record was completely accepted by the kernel.
    std::size_t complete_frames() const {
        return offset_ == pending_.size() ? next_ : next_ - 1;
    }
    std::uint64_t bytes() const { return bytes_; }

private:
    int fd_{-1};
    std::function<Bytes(std::size_t)> payload_;
    std::optional<mtdd::protocol::crypto::AesCtr> c2s_;
    Bytes pending_;
    std::size_t offset_{0};
    std::size_t next_{0};
    std::uint64_t bytes_{0};
};

bool peer_closed(int fd) { return peer_state(fd, 0) == 0; }

void direct_config(mtdd::Config& config) {
    config.direct_fallback_enabled = true;
    config.direct_fallback_dcs = {2};
    config.max_connections = 8;
    config.max_handshakes = 8;
    config.connection_queue_bytes = 256U * 1024U;
    config.global_buffer_bytes = 64U * 1024U * 1024U;
    config.handshake_timeout = 10s;
    config.idle_timeout = 60s;
    // Bounds the FIN-while-paused wait and the graceful drain at teardown.
    config.shutdown_timeout = 3s;
}

std::uint64_t c2s_backpressure(const Daemon& daemon) {
    return daemon.services.stats.snapshot().backpressure_c2s_total;
}

} // namespace

// A Direct upstream that stops reading must stall the client (its send blocks)
// instead of closing it, without spinning the reactor, and every byte must
// arrive intact and in order once the upstream resumes.
TEST(RuntimeBackpressure, DirectStalledUpstreamPausesClientReads) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false, /*recv_buffer_bytes=*/16 * 1024);
    dc.pause_reading();
    BackpressureDirectScope endpoint(dc.port());
    Daemon daemon(1, true, direct_config);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(TestClient::Adopt{}, connect_small_sndbuf(daemon.port()), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(wait_for([&] { return dc.connections() == 1; }, 3000ms));
    const std::uint64_t bp_before = c2s_backpressure(daemon);

    Uploader upload(client.fd(), 2, direct_upload_payload);
    const auto stalled = upload.pump(kUploadMaxFrames, 500ms);
    ASSERT_EQ(stalled, Uploader::Result::stalled)
        << "client was not paused (failed = closed by the proxy) after "
        << upload.bytes() << " bytes";
    EXPECT_FALSE(peer_closed(client.fd()));
    EXPECT_EQ(dc.frames(), 0U);
    // One transition into the pause, counted once.
    ASSERT_TRUE(wait_for([&] { return c2s_backpressure(daemon) == bp_before + 1; }, 2000ms))
        << "backpressure_c2s_total=" << c2s_backpressure(daemon) << " before=" << bp_before;

    // EPOLLIN must be out of the mask while paused: a level-triggered reactor
    // would otherwise wake for the unread client bytes forever.
    const pid_t tid = daemon.worker_tid();
    const double cpu0 = thread_cpu_seconds(tid);
    const auto wall0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(400ms);
    const double cpu1 = thread_cpu_seconds(tid);
    const double wall =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - wall0).count();
    ASSERT_GE(cpu0, 0.0);
    ASSERT_GE(cpu1, 0.0);
    EXPECT_LT(cpu1 - cpu0, 0.3 * wall) << "paused client spun the reactor";
    EXPECT_EQ(c2s_backpressure(daemon), bp_before + 1) << "pause counted per event";
    EXPECT_FALSE(peer_closed(client.fd()));

    // Resume: the rest of the upload goes through on the same connection.
    dc.resume_reading();
    const std::size_t total = upload.complete_frames() + 64;
    ASSERT_EQ(upload.pump(total, 10000ms), Uploader::Result::done);
    ASSERT_TRUE(wait_for([&] { return dc.frames() == total; }, 10000ms))
        << "frames=" << dc.frames() << " expected=" << total;
    const auto& seen = dc.payloads();
    ASSERT_EQ(seen.size(), total);
    for (std::size_t i = 0; i < total; ++i) {
        ASSERT_EQ(seen[i], direct_upload_payload(i)) << "frame " << i << " corrupted/reordered";
    }
    // Still the same open, relaying connection.
    ASSERT_EQ(upload.pump(total + 1, 5000ms), Uploader::Result::done);
    EXPECT_TRUE(wait_for([&] { return dc.frames() == total + 1; }, 5000ms));
    EXPECT_FALSE(peer_closed(client.fd()));
    EXPECT_EQ(daemon.services.stats.snapshot().connections_active, 1U);
}

// A FIN that arrives while the client is paused is latched, and the tail queued
// in the kernel before it is still read and forwarded after the resume.
TEST(RuntimeBackpressure, DirectHalfCloseWhilePausedDrainsTail) {
    mtdd::test::FakeDirectDc dc(2, /*respond=*/false, /*recv_buffer_bytes=*/16 * 1024);
    dc.pause_reading();
    BackpressureDirectScope endpoint(dc.port());
    Daemon daemon(1, true, direct_config);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(TestClient::Adopt{}, connect_small_sndbuf(daemon.port()), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(wait_for([&] { return dc.connections() == 1; }, 3000ms));
    const std::uint64_t bp_before = c2s_backpressure(daemon);

    Uploader upload(client.fd(), 2, direct_upload_payload);
    ASSERT_EQ(upload.pump(kUploadMaxFrames, 500ms), Uploader::Result::stalled)
        << "client was not paused after " << upload.bytes() << " bytes";
    ASSERT_TRUE(wait_for([&] { return c2s_backpressure(daemon) > bp_before; }, 2000ms));
    // FIN behind the unread tail, while paused. A trailing partial record is
    // never completed and is therefore not expected upstream.
    const std::size_t complete = upload.complete_frames();
    ASSERT_EQ(::shutdown(client.fd(), SHUT_WR), 0);
    std::this_thread::sleep_for(300ms);
    EXPECT_FALSE(peer_closed(client.fd())) << "FIN while paused closed the client early";
    EXPECT_EQ(dc.frames(), 0U);

    dc.resume_reading();
    ASSERT_TRUE(wait_for([&] { return dc.frames() == complete; }, 10000ms))
        << "tail behind the FIN was lost: frames=" << dc.frames() << " expected=" << complete;
    const auto& seen = dc.payloads();
    ASSERT_EQ(seen.size(), complete);
    for (std::size_t i = 0; i < complete; ++i) {
        ASSERT_EQ(seen[i], direct_upload_payload(i)) << "frame " << i;
    }
}

// The ME route: a fake ME that stops reading fills the shared writer; the
// uploading client is paused (not closed) and its whole upload is delivered in
// order after the ME resumes.
TEST(RuntimeBackpressure, MeStalledWriterPausesClientReads) {
    constexpr std::size_t kFrames = 1024;  // 16 MiB, verified in order by FakeMe
    FakeMe me{me_secret(), kFrames, 4000ms, 1, 0ms, 0ms, false, 0, 15000};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.max_frame_bytes = 256U * 1024U;
        config.connection_queue_bytes = 256U * 1024U;
        config.global_buffer_bytes = 64U * 1024U * 1024U;
        config.handshake_timeout = 10s;
        config.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(TestClient::Adopt{}, connect_small_sndbuf(daemon.port()), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const std::uint64_t bp_before = c2s_backpressure(daemon);

    Uploader upload(client.fd(), 2, burst_payload);
    const auto stalled = upload.pump(kFrames, 500ms);
    ASSERT_EQ(stalled, Uploader::Result::stalled)
        << "client was not paused (failed = closed by the proxy) after "
        << upload.bytes() << " bytes";
    EXPECT_FALSE(peer_closed(client.fd()));
    ASSERT_TRUE(wait_for([&] { return c2s_backpressure(daemon) == bp_before + 1; }, 2000ms))
        << "backpressure_c2s_total=" << c2s_backpressure(daemon) << " before=" << bp_before;

    // The fake ME resumes reading on its own; the rest of the upload follows.
    ASSERT_EQ(upload.pump(kFrames, 15000ms), Uploader::Result::done);
    ASSERT_EQ(me.future().wait_for(20s), std::future_status::ready);
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok) << "upload not delivered intact and in order";
    EXPECT_EQ(observation.frames, kFrames);
    Bytes response;
    EXPECT_TRUE(client.read_message(response, 5000)) << "connection lost after resume";
    EXPECT_FALSE(peer_closed(client.fd()));
}

// One client stalled behind the shared ME writer must not close (or fail the
// writer for) another client bound to the same ME connection.
TEST(RuntimeBackpressure, MeStalledUploadDoesNotCloseOtherClients) {
    constexpr std::size_t kFrames = 768;  // uploader frames; +1 from the bystander
    FakeMe me{me_secret(), kFrames + 1, 4000ms, 1, 0ms, 0ms, true, 0, 15000,
              /*min_inner=*/16, /*require_sequence=*/false};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) {
        config.max_frame_bytes = 256U * 1024U;
        config.connection_queue_bytes = 256U * 1024U;
        config.global_buffer_bytes = 64U * 1024U * 1024U;
        config.handshake_timeout = 10s;
        config.idle_timeout = 60s;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient bystander(daemon.port(), secret_bytes());
    ASSERT_TRUE(bystander.valid());
    ASSERT_TRUE(bystander.send_hello(0, 31));
    ASSERT_TRUE(bystander.start_obfuscation(2));

    TestClient uploader(TestClient::Adopt{}, connect_small_sndbuf(daemon.port()),
                        secret_bytes());
    ASSERT_TRUE(uploader.valid());
    ASSERT_TRUE(uploader.send_hello(0, 32));
    ASSERT_TRUE(uploader.start_obfuscation(2));
    const std::uint64_t bp_before = c2s_backpressure(daemon);
    const std::uint64_t reconnects_before = me_dc(daemon.services.stats, "2").reconnects_total;

    Uploader upload(uploader.fd(), 2, burst_payload);
    ASSERT_EQ(upload.pump(kFrames, 500ms), Uploader::Result::stalled)
        << "uploader was not paused after " << upload.bytes() << " bytes";
    ASSERT_TRUE(wait_for([&] { return c2s_backpressure(daemon) > bp_before; }, 2000ms));
    // The bystander's request queues behind the stalled shared writer.
    ASSERT_TRUE(bystander.send_message(Bytes(16, 0x42)));
    std::this_thread::sleep_for(200ms);
    EXPECT_FALSE(peer_closed(bystander.fd()));
    EXPECT_FALSE(peer_closed(uploader.fd()));

    ASSERT_EQ(upload.pump(kFrames, 15000ms), Uploader::Result::done);
    ASSERT_EQ(me.future().wait_for(20s), std::future_status::ready);
    const auto observation = me.future().get();
    EXPECT_TRUE(observation.ok);
    EXPECT_EQ(observation.frames, kFrames + 1);
    Bytes response;
    EXPECT_TRUE(bystander.read_message(response, 5000)) << "bystander lost its answer";
    EXPECT_FALSE(peer_closed(bystander.fd()));
    // The shared writer was neither failed nor replaced because of one client.
    const auto writer = me_dc(daemon.services.stats, "2");
    EXPECT_EQ(writer.ready_connections, 1U);
    EXPECT_EQ(writer.reconnects_total, reconnects_before);
}

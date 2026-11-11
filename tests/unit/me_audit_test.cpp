// Regression tests for five ME/relay audit findings:
//   1. close_client() must not advance ME write_seq/CBC when the close frame
//      cannot be staged.
//   2. An ME FIN/EPOLLRDHUP must drain the readable tail before failing, even
//      when the tail exceeds one kReadBatch read event.
//   3. Partially staged client wire must not retain an unbounded consumed
//      prefix.
//   4. A positive sub-millisecond deadline must not become epoll_wait(..., 0).
//   5. ME reassembly growth must be admitted against the global buffer budget.
//
// The runtime reactor model lives in src/runtime/internal.hpp and names the
// private nested type Runtime::Impl. Exposing it through a test-only friend in
// the public header would change the production API for tests alone, so the
// access adjustment is confined to this translation unit.

#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mtdd/config.hpp"
#include "mtdd/control.hpp"
#include "mtdd/io.hpp"
#include "mtdd/metadata.hpp"
#include "mtdd/protocol.hpp"
#include "mtdd/runtime_support.hpp"

#define private public
#include "mtdd/runtime.hpp"
#undef private
#include "../../src/runtime/internal.hpp"

namespace {

using namespace mtdd::protocol;

using Bytes = std::vector<std::uint8_t>;
using A16 = std::array<std::uint8_t, 16>;
using A32 = std::array<std::uint8_t, 32>;

Bytes from_hex(std::string_view hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    const auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("bad hex");
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> arr(const Bytes& b) {
    std::array<std::uint8_t, N> out{};
    std::copy_n(b.begin(), std::min(b.size(), N), out.begin());
    return out;
}

Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

Bytes le32(std::uint32_t v) {
    return {static_cast<std::uint8_t>(v), static_cast<std::uint8_t>(v >> 8),
            static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 24)};
}

const A32 kMeSecret = [] {
    A32 s{};
    for (int i = 0; i < 32; ++i) s[i] = static_cast<std::uint8_t>(i);
    return s;
}();
const Endpoint kMeServer = Endpoint::v4({149, 154, 175, 50}, 8888);
const Endpoint kMeLocal = Endpoint::v4({203, 0, 113, 9}, 54321);
const Endpoint kMeAdvertised = Endpoint::v4({203, 0, 113, 9}, 443);
const std::array<std::uint8_t, 16> kAdTag{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
constexpr std::uint16_t kMeProcessId = 0x1f3a;
constexpr std::uint32_t kMeProcessTime = 1600000000u;
constexpr std::int64_t kNow = 1600000000;
constexpr std::string_view kHandshakeAnswerEnc =
    "ca56a51dead27a7ec16e658762b13591dfd6e87a9bcae4d3896b8f8fae573601"
    "f339b98bfa546aff74a6a4ad662d08d6";

Bytes me_plain_frame(std::int32_t seq, std::span<const std::uint8_t> payload) {
    if (payload.size() % 4 != 0) throw std::invalid_argument("unaligned payload");
    Bytes f = cat({le32(static_cast<std::uint32_t>(payload.size() + 12)),
                   le32(static_cast<std::uint32_t>(seq))});
    f.insert(f.end(), payload.begin(), payload.end());
    return cat({f, le32(crypto::crc32(f))});
}

Bytes me_encrypted_frame(crypto::AesCbc& cbc, std::int32_t seq,
                         std::span<const std::uint8_t> payload) {
    Bytes f = me_plain_frame(seq, payload);
    while (f.size() % 16 != 0) f = cat({f, le32(4)});
    cbc.encrypt(f);
    return f;
}

struct TestSink : MiddleEndSession::Sink {
    void on_proxy_payload(const MiddleEndSession::ConnId&,
                          std::span<const std::uint8_t>) override {}
    void on_quick_ack(const MiddleEndSession::ConnId&,
                      std::array<std::uint8_t, 4>) override {}
    void on_remote_close(const MiddleEndSession::ConnId&) override {}
};

MiddleEndConfig me_config(std::size_t max_frame = 1u << 20) {
    MiddleEndConfig cfg;
    cfg.secret.assign(kMeSecret.begin(), kMeSecret.end());
    cfg.server = kMeServer;
    cfg.local = kMeLocal;
    cfg.advertised = kMeAdvertised;
    cfg.ad_tag.bytes = kAdTag;
    cfg.max_frame = max_frame;
    cfg.process_id = kMeProcessId;
    cfg.process_time = kMeProcessTime;
    cfg.random = [](std::span<std::uint8_t> out) {
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<std::uint8_t>(i);
        }
    };
    cfg.clock = [] { return kNow; };
    return cfg;
}

Bytes nonce_answer() {
    Bytes n(16);
    for (int i = 0; i < 16; ++i) n[i] = static_cast<std::uint8_t>(0xa0 + i);
    return me_plain_frame(
        -2, cat({from_hex("aa87cb7a"), Bytes(kMeSecret.begin(), kMeSecret.begin() + 4),
                 le32(1), le32(1600000000), n}));
}

MiddleProxyKeys keys_for(const MiddleEndConfig& cfg) {
    MiddleProxyKdfInput in;
    in.nonce_server = arr<16>([&] {
        Bytes n(16);
        for (int i = 0; i < 16; ++i) n[i] = static_cast<std::uint8_t>(0xa0 + i);
        return n;
    }());
    in.nonce_client = arr<16>(Bytes{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
    in.client_timestamp = 1600000000;
    in.server = cfg.server;
    in.local = cfg.local;
    in.secret = cfg.secret;
    return derive_middle_proxy_keys(in);
}

A16 last_block(std::span<const std::uint8_t> b) {
    A16 out{};
    std::copy(b.end() - 16, b.end(), out.begin());
    return out;
}

struct ReadyMe {
    std::unique_ptr<MiddleEndSession> session;
    Bytes handshake_request_enc;
    Bytes handshake_answer_enc;
    std::unique_ptr<crypto::AesCbc> read_enc;
};

ReadyMe make_ready_config(MiddleEndConfig cfg) {
    const auto k = keys_for(cfg);
    ReadyMe out;
    out.session = std::make_unique<MiddleEndSession>(std::move(cfg),
                                                     std::make_unique<TestSink>());
    const auto start = out.session->start();
    if (start.size() != 44u) throw std::runtime_error("ME start size");
    std::vector<std::uint8_t> to_me;
    if (out.session->feed(nonce_answer(), to_me) != Status::Ok) {
        throw std::runtime_error("ME nonce feed");
    }
    out.handshake_request_enc = to_me;
    if (out.handshake_request_enc.size() != 48u) {
        throw std::runtime_error("ME handshake request size");
    }
    out.handshake_answer_enc = from_hex(kHandshakeAnswerEnc);
    to_me.clear();
    if (out.session->feed(out.handshake_answer_enc, to_me) != Status::Ok ||
        !out.session->ready()) {
        throw std::runtime_error("ME handshake answer");
    }
    out.read_enc =
        std::make_unique<crypto::AesCbc>(k.read_key, last_block(out.handshake_answer_enc));
    return out;
}

ReadyMe make_ready(std::size_t max_frame = 1u << 20) {
    return make_ready_config(me_config(max_frame));
}

// Minimal reactor owner matching the production construction order.
class AuditReactor {
public:
    explicit AuditReactor(const char* tag) {
        static std::uint64_t sequence = 0;
        path_ = std::filesystem::temp_directory_path() /
                ("mtdd-me-audit-" + std::to_string(::getpid()) + "-" + tag + "-" +
                 std::to_string(sequence++));
        std::filesystem::create_directories(path_);
        config.proxy_host = "127.0.0.1";
        config.proxy_port = 0;
        config.ad_tag.fill(1);
        config.max_frame_bytes = 4096;
        config.connection_queue_bytes = 4096;
        config.global_buffer_bytes = 1U << 20;
        config.me_config_path = path_ / "absent-me-config";
        config.me_secret_path = path_ / "absent-me-secret";
        auto opened = mtdd::control::UserStore::open((path_ / "users.json").string());
        if (!opened) throw std::runtime_error("open test store");
        store = std::make_unique<mtdd::control::UserStore>(std::move(opened).value());
        metadata = std::make_unique<mtdd::MetadataProvider>(config);
        reactor = std::make_unique<mtdd::Runtime::Impl>(config, *store, stats, *metadata,
                                                        barrier);
    }

    ~AuditReactor() {
        reactor.reset();
        metadata.reset();
        store.reset();
        std::error_code ec;
        std::filesystem::remove(path_ / "users.json", ec);
        std::filesystem::remove(path_, ec);
    }

    AuditReactor(const AuditReactor&) = delete;
    AuditReactor& operator=(const AuditReactor&) = delete;

    std::filesystem::path path_;
    mtdd::Config config;
    mtdd::control::Statistics stats{100};
    mtdd::RevisionBarrier barrier;
    std::unique_ptr<mtdd::control::UserStore> store;
    std::unique_ptr<mtdd::MetadataProvider> metadata;
    std::unique_ptr<mtdd::Runtime::Impl> reactor;
};

TEST(MeAudit, NormalCloseMustNotLoseAdvancedCbcFrame) {
    AuditReactor test("close");
    auto ready = make_ready();
    mtdd::Runtime::Impl::MeConn me;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.frame_bytes = test.reactor->me_frame_capacity();
    auto client = std::make_unique<mtdd::Runtime::Impl::Client>();
    client->token = 12345;
    client->me = &me;
    test.reactor->clients_.emplace(client->token, std::move(client));
    const auto seq_before = me.session->write_seq();
    test.reactor->close_client(12345);
    EXPECT_TRUE(me.failure_deferred || me.session->write_seq() == seq_before)
        << "CBC/seq advanced but the close frame was discarded";
}

TEST(MeAudit, MeFinMustReadPendingPayloadBeforeFailure) {
    AuditReactor test("fin");
    auto ready = make_ready();
    mtdd::Runtime::Impl::MeConn me;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, &me});
    int sockets[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    me.fd.reset(sockets[0]);
    mtdd::io::UniqueFd witness(::dup(me.fd.get()));
    mtdd::io::UniqueFd peer(sockets[1]);
    const auto wire = me_encrypted_frame(*ready.read_enc, 0,
                                         cat({from_hex("a234b65e"), Bytes(8, 0x11)}));
    ASSERT_EQ(::send(peer.get(), wire.data(), wire.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(wire.size()));
    ASSERT_EQ(::shutdown(peer.get(), SHUT_WR), 0);
    test.reactor->update_me_interest(me);
    test.reactor->handle_me(me, EPOLLIN | EPOLLRDHUP,
                            mtdd::Runtime::Impl::Clock::now());
    std::array<std::uint8_t, 256> unread{};
    EXPECT_LE(::recv(witness.get(), unread.data(), unread.size(), MSG_DONTWAIT), 0)
        << "ME FIN discarded the readable RPC tail";
    test.reactor->remove_target(me.token);
}

TEST(MeAudit, MeFinLargeTailIsReadAcrossEvents) {
    AuditReactor test("fin-tail");
    auto ready = make_ready();
    mtdd::Runtime::Impl::MeConn me;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, &me});
    int sockets[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    me.fd.reset(sockets[0]);
    mtdd::io::UniqueFd witness(::dup(me.fd.get()));
    mtdd::io::UniqueFd peer(sockets[1]);
    // The AF_UNIX default buffer is too small for an 80 KiB tail in one write.
    const int socket_buffer = 512 * 1024;
    ASSERT_EQ(::setsockopt(me.fd.get(), SOL_SOCKET, SO_RCVBUF, &socket_buffer,
                           sizeof(socket_buffer)), 0);
    ASSERT_EQ(::setsockopt(peer.get(), SOL_SOCKET, SO_SNDBUF, &socket_buffer,
                           sizeof(socket_buffer)), 0);

    // 5 * 16 KiB: me_plain_frame(len 16380) + one 4-byte pad block = 16384 wire
    // bytes, so the tail spans three read batches (2 * kReadBatch + 16 KiB).
    constexpr std::size_t kPayloadBytes = 16368;
    constexpr int kFrameCount = 5;
    const Bytes type = le32(0x11223344u); // unknown RPC: counted and ignored
    Bytes wire;
    for (int i = 0; i < kFrameCount; ++i) {
        Bytes payload(kPayloadBytes, 0x5a);
        std::copy(type.begin(), type.end(), payload.begin());
        const auto frame = me_encrypted_frame(*ready.read_enc, i, payload);
        ASSERT_EQ(frame.size(), 16384u);
        wire.insert(wire.end(), frame.begin(), frame.end());
    }
    std::size_t sent = 0;
    while (sent < wire.size()) {
        const ssize_t n = ::send(peer.get(), wire.data() + sent, wire.size() - sent, MSG_NOSIGNAL);
        ASSERT_GT(n, 0);
        sent += static_cast<std::size_t>(n);
    }
    ASSERT_EQ(sent, wire.size());
    ASSERT_EQ(::shutdown(peer.get(), SHUT_WR), 0);

    test.reactor->update_me_interest(me);
    // EPOLLIN | EPOLLRDHUP without EPOLLHUP: the drain must be resumed by
    // further level-triggered events instead of failing on the first batch.
    for (int i = 0; i < 16 && me.state == mtdd::Runtime::Impl::MeConn::State::ready; ++i) {
        test.reactor->handle_me(me, EPOLLIN | EPOLLRDHUP, mtdd::Runtime::Impl::Clock::now());
    }

    std::array<std::uint8_t, 65536> unread{};
    EXPECT_LE(::recv(witness.get(), unread.data(), unread.size(), MSG_DONTWAIT), 0)
        << "ME FIN discarded the tail beyond one read batch";
    EXPECT_EQ(me.rx_bytes, static_cast<std::uint64_t>(wire.size()))
        << "rx_bytes must reflect every byte actually read from the socket";
    EXPECT_EQ(me.state, mtdd::Runtime::Impl::MeConn::State::backoff)
        << "the drained FIN must still fail the session afterwards";
    test.reactor->remove_target(me.token);
}

TEST(MeAudit, PartialStagingMustNotRetainUnboundedConsumedPrefix) {
    AuditReactor test("stage");
    mtdd::Runtime::Impl::Client client;
    client.out.emplace(4096);
    client.s2c_wire.assign(8000, 0x11);
    client.s2c_offset = 7000;
    const Bytes next(7000, 0x22);
    ASSERT_TRUE(test.reactor->push_client_wire(client, next, false));
    EXPECT_LE(client.s2c_wire.size(), test.config.max_frame_bytes + 4096)
        << "logical pending fits the cap but the consumed prefix keeps growing";
}

TEST(MeAudit, FutureSubmillisecondDeadlineMustNotBusyPoll) {
    AuditReactor test("poll");
    const auto now = mtdd::Runtime::Impl::Clock::now();
    test.reactor->next_poll_ = now + std::chrono::seconds(1);
    test.reactor->next_gauge_ = now + std::chrono::seconds(1);
    test.reactor->deadlines_.set(12345, now + std::chrono::microseconds(500));
    EXPECT_GE(test.reactor->wait_timeout_ms(now), 1)
        << "positive delay became epoll_wait(..., 0)";
}

TEST(MeAudit, IncompleteMeFrameMustRespectGlobalBufferBudget) {
    AuditReactor test("budget");
    auto ready = make_ready();
    mtdd::Runtime::Impl::MeConn me;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, &me});
    int sockets[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    me.fd.reset(sockets[0]);
    mtdd::io::UniqueFd peer(sockets[1]);
    const Bytes body(128 * 1024, 0x11);
    const auto wire = me_encrypted_frame(*ready.read_enc, 0, body);
    ASSERT_EQ(::send(peer.get(), wire.data(), 32768, MSG_NOSIGNAL), 32768);
    // Other live queues leave only 16 KiB of the envelope free.
    test.reactor->budget_used_ = test.config.global_buffer_bytes - 16384;
    test.reactor->read_me(me, mtdd::Runtime::Impl::Clock::now());
    EXPECT_LE(test.reactor->budget_used_, test.config.global_buffer_bytes)
        << "ME reassembly grew past the hard relay-buffer envelope";
    test.reactor->remove_target(me.token);
}

TEST(MeAudit, MeBudgetPauseAndResumeAreVisiblePerWorker) {
    AuditReactor test("me-budget-diag");
    auto ready = make_ready();
    auto owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
    auto& me = *owned;
    me.dc = 2;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, &me});
    int sockets[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    me.fd.reset(sockets[0]);
    mtdd::io::UniqueFd peer(sockets[1]);
    me.clients = 3;
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = 1;
    pool.serving_generation = 1;
    pool.scale_target = 1;
    pool.conns.push_back(std::move(owned));

    const auto paused_at = mtdd::Runtime::Impl::Clock::now();
    // The local partition is exhausted: read_me must pause instead of failing
    // the shared session, and the transition is counted once.
    test.reactor->budget_used_ = test.config.global_buffer_bytes;
    test.reactor->read_me(me, paused_at);
    EXPECT_TRUE(me.budget_paused);
    EXPECT_EQ(me.budget_pauses, 1u);
    EXPECT_EQ(me.armed & EPOLLIN, 0u)
        << "a paused ME read must leave the epoll read mask";
    test.reactor->publish_me_worker_diagnostics(2, paused_at + std::chrono::milliseconds{250});
    auto snapshot = test.stats.snapshot();
    ASSERT_EQ(snapshot.workers.size(), 1u);
    const auto& paused = snapshot.workers[0].me_dcs.at("2");
    EXPECT_EQ(paused.budget_paused_connections, 1u);
    EXPECT_EQ(paused.bound_clients_on_paused, 3u)
        << "the blast radius is every client multiplexed on the paused ME";
    EXPECT_EQ(paused.read_armed_connections, 0u);
    EXPECT_EQ(paused.current_pause_age_ms, 250u);
    EXPECT_GE(paused.max_pause_age_ms, 250u);
    EXPECT_EQ(paused.budget_pauses_total, 1u);
    EXPECT_EQ(paused.budget_resumes_total, 0u);

    // Slack returns: the same housekeeping path resumes and re-arms the read,
    // and the completed pause duration is retained.
    test.reactor->budget_used_ = 0;
    test.reactor->unpause_clients_if_possible(paused_at + std::chrono::milliseconds{250});
    EXPECT_FALSE(me.budget_paused);
    EXPECT_EQ(me.budget_resumes, 1u);
    EXPECT_GE(me.budget_pause_max_ms, 250u);
    EXPECT_NE(me.armed & EPOLLIN, 0u) << "resume did not re-arm the read";
    test.reactor->publish_me_worker_diagnostics(2, paused_at + std::chrono::milliseconds{300});
    snapshot = test.stats.snapshot();
    const auto& resumed = snapshot.workers[0].me_dcs.at("2");
    EXPECT_EQ(resumed.budget_paused_connections, 0u);
    EXPECT_EQ(resumed.bound_clients_on_paused, 0u);
    EXPECT_EQ(resumed.read_armed_connections, 1u);
    EXPECT_EQ(resumed.current_pause_age_ms, 0u);
    EXPECT_GE(resumed.max_pause_age_ms, 250u);
    EXPECT_EQ(resumed.budget_pauses_total, 1u);
    EXPECT_EQ(resumed.budget_resumes_total, 1u);

    test.reactor->remove_target(me.token);
    test.reactor->me_pool_.clear();
}

// ---------------------------------------------------------------------------
// Keepalive liveness is traffic-based, not PONG-based.
// ---------------------------------------------------------------------------

namespace {

struct MePair {
    MePair() {
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) != 0) {
            throw std::runtime_error("socketpair");
        }
    }
    ~MePair() {
        if (fds[0] >= 0) ::close(fds[0]);
        if (fds[1] >= 0) ::close(fds[1]);
    }
    int fds[2]{-1, -1};
};

// Unknown RPC constructors are counted and ignored by the session, so they model
// "inbound progress that grants no liveness credit" (no PONG, no answer).
void push_inbound_noise(MePair& pair, crypto::AesCbc& cipher, std::int32_t& seq) {
    const Bytes frame =
        me_encrypted_frame(cipher, seq++, cat({le32(0x5eed5eedu), Bytes(8, 0x31)}));
    if (::send(pair.fds[1], frame.data(), frame.size(), MSG_NOSIGNAL) !=
        static_cast<ssize_t>(frame.size())) {
        throw std::runtime_error("send ME noise");
    }
}

} // namespace

TEST(MeAudit, PingWindowWithInboundTrafficKeepsConnectionAlive) {
    AuditReactor test("ping-live");
    auto ready = make_ready();
    mtdd::Runtime::Impl::MeConn me;
    me.dc = 2;
    me.generation = 1;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.out.emplace(test.config.connection_queue_bytes);
    me.token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, &me});
    me.ping_token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me_ping, &me});
    MePair pair;
    me.fd.reset(pair.fds[0]);
    pair.fds[0] = -1;
    test.reactor->update_me_interest(me);

    auto client = std::make_unique<mtdd::Runtime::Impl::Client>();
    client->token = 918273;
    client->me = &me;
    me.clients = 1;
    test.reactor->clients_.emplace(client->token, std::move(client));

    const auto now = mtdd::Runtime::Impl::Clock::now();
    const std::int32_t sent = me.session->write_seq();
    std::int32_t inbound_seq = 0;
    for (int round = 1; round <= 3; ++round) {
        push_inbound_noise(pair, *ready.read_enc, inbound_seq);
        const auto at = now + std::chrono::milliseconds(round);
        test.reactor->handle_me(me, EPOLLIN, at);
        ASSERT_EQ(me.state, mtdd::Runtime::Impl::MeConn::State::ready);
        test.reactor->on_me_ping_deadline(me, at);
    }
    ASSERT_GT(me.rx_bytes, 0U);
    ASSERT_EQ(me.session->write_seq(), sent + 3) << "three pings were encoded";
    ASSERT_EQ(me.unanswered_pings, 3U);

    // Fourth deadline: K=3 reached, but inbound bytes arrived since the window
    // started, so the peer is alive and the clients must survive.
    test.reactor->on_me_ping_deadline(me, now + std::chrono::milliseconds(4));
    EXPECT_EQ(me.state, mtdd::Runtime::Impl::MeConn::State::ready)
        << "a connection that keeps receiving traffic was declared dead";
    EXPECT_EQ(me.unanswered_pings, 0U) << "the liveness window was not reset";
    EXPECT_TRUE(me.pending_pings.empty());
    EXPECT_EQ(test.reactor->clients_.size(), 1U)
        << "the clients of a live connection were closed";
    const auto snapshot = test.reactor->stats_.snapshot();
    EXPECT_EQ(snapshot.me_dcs.at("2").ping_timeouts_total, 0U);
    EXPECT_EQ(snapshot.me_dcs.at("2").ping_stalls_total, 1U)
        << "a stalled but live keepalive window was not reported";

    // Tear the synthetic client down while `me` is still alive: the reactor owns
    // the client and would otherwise reach a dead stack MeConn in finalize().
    test.reactor->close_client(918273);
    test.reactor->remove_target(me.token);
    test.reactor->remove_target(me.ping_token);
    me.ping_token = 0;
}

TEST(MeAudit, PingWindowWithoutAnyInboundTrafficFailsTheConnection) {
    AuditReactor test("ping-dead");
    auto ready = make_ready();
    mtdd::Runtime::Impl::MeConn me;
    me.dc = 2;
    me.generation = 1;
    me.state = mtdd::Runtime::Impl::MeConn::State::ready;
    me.session = std::move(ready.session);
    me.out.emplace(test.config.connection_queue_bytes);
    me.token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, &me});
    me.ping_token = test.reactor->add_target({mtdd::Runtime::Impl::Kind::me_ping, &me});
    MePair pair;
    me.fd.reset(pair.fds[0]);
    pair.fds[0] = -1;
    test.reactor->update_me_interest(me);

    auto client = std::make_unique<mtdd::Runtime::Impl::Client>();
    client->token = 564738;
    client->me = &me;
    me.clients = 1;
    test.reactor->clients_.emplace(client->token, std::move(client));

    const auto now = mtdd::Runtime::Impl::Clock::now();
    for (int round = 1; round <= 3; ++round) {
        test.reactor->on_me_ping_deadline(me, now + std::chrono::milliseconds(round));
        ASSERT_EQ(me.state, mtdd::Runtime::Impl::MeConn::State::ready);
    }
    ASSERT_EQ(me.rx_bytes, 0U);
    test.reactor->on_me_ping_deadline(me, now + std::chrono::milliseconds(4));
    EXPECT_EQ(me.state, mtdd::Runtime::Impl::MeConn::State::backoff)
        << "a connection with no PONG and no inbound byte must be replaced";
    EXPECT_TRUE(test.reactor->clients_.empty());
    const auto snapshot = test.reactor->stats_.snapshot();
    EXPECT_EQ(snapshot.me_dcs.at("2").ping_timeouts_total, 1U);
    EXPECT_EQ(snapshot.me_dcs.at("2").ping_stalls_total, 0U);

    test.reactor->remove_target(me.token);
    test.reactor->remove_target(me.ping_token);
    me.ping_token = 0;
}

// ---------------------------------------------------------------------------
// Successor-first metadata replacement (generations).
// ---------------------------------------------------------------------------

namespace {

std::shared_ptr<mtdd::MeMetadata> me_metadata(std::uint16_t port) {
    auto snapshot = std::make_shared<mtdd::MeMetadata>();
    mtdd::MeEndpoint endpoint;
    endpoint.dc = 2;
    endpoint.host = "127.0.0.1";
    endpoint.port = port;
    snapshot->endpoints.push_back(endpoint);
    snapshot->secret.assign(128, 7);
    return snapshot;
}

bool pool_has_generation(const mtdd::Runtime::Impl::DcPool& pool, std::uint64_t generation) {
    return std::any_of(pool.conns.begin(), pool.conns.end(),
                       [generation](const std::unique_ptr<mtdd::Runtime::Impl::MeConn>& c) {
                           return c && c->generation == generation;
                       });
}

} // namespace

TEST(MeAudit, DynamicPoolScalesAndDrainsWithoutClosingClients) {
    AuditReactor test("elastic-pool");
    using Impl = mtdd::Runtime::Impl;
    const auto now = Impl::Clock::now();
    test.reactor->config_.me_connections_per_dc = 2;
    test.reactor->config_.me_clients_per_writer = 10;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = pool.serving_generation = 1;
    auto owned = std::make_unique<Impl::MeConn>();
    auto* first = owned.get();
    first->dc = 2;
    first->generation = 1;
    first->state = Impl::MeConn::State::ready;
    first->clients = 11;
    first->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(owned));
    test.reactor->scale_me_pool(2, now);
    ASSERT_EQ(pool.conns.size(), 2U);
    EXPECT_FALSE(first->draining);
    auto* second = pool.conns.back().get();
    second->clients = 1;
    second->state = Impl::MeConn::State::ready;
    first->clients = 5;
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(10));
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(311));
    ASSERT_TRUE(second->draining);
    test.reactor->reap_me_pool(now + std::chrono::hours(1));
    EXPECT_EQ(pool.conns.size(), 2U);
    first->clients = 11;
    test.reactor->budget_used_ = test.reactor->config_.global_buffer_bytes;
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(321));
    EXPECT_FALSE(second->draining);
    EXPECT_EQ(pool.conns.size(), 2U);
    test.reactor->budget_used_ = 0;
    first->clients = 0;
    second->clients = 0;
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(331));
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(641));
    ASSERT_TRUE(first->scale_draining);
    const std::array<std::uint8_t, 1> pending{1};
    ASSERT_EQ(first->out->append(pending), mtdd::io::AppendStatus::ok);
    test.reactor->reap_me_pool(now + std::chrono::seconds(642));
    EXPECT_EQ(pool.conns.size(), 2U);
    first->out->clear();
    test.reactor->reap_me_pool(now + std::chrono::seconds(643));
    EXPECT_EQ(pool.conns.size(), 1U);
    EXPECT_EQ(test.reactor->stats_.snapshot().me_dcs.at("2").scale_down_total, 2U);
}

TEST(MeAudit, DynamicPoolRequiresSustainedQueuePressure) {
    AuditReactor test("elastic-pressure");
    using Impl = mtdd::Runtime::Impl;
    const auto now = Impl::Clock::now();
    test.reactor->config_.me_connections_per_dc = 2;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = pool.serving_generation = 1;
    auto owned = std::make_unique<Impl::MeConn>();
    owned->dc = 2;
    owned->generation = 1;
    owned->state = Impl::MeConn::State::ready;
    owned->out.emplace(test.config.connection_queue_bytes);
    owned->queued_clients = 1;
    owned->frame_bytes = test.config.connection_queue_bytes;
    pool.conns.push_back(std::move(owned));
    test.reactor->scale_me_pool(2, now);
    EXPECT_EQ(pool.conns.size(), 1U);
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(9));
    EXPECT_EQ(pool.conns.size(), 1U);
    test.reactor->scale_me_pool(2, now + std::chrono::seconds(10));
    EXPECT_EQ(pool.conns.size(), 2U);
    const auto dc = test.reactor->stats_.snapshot().me_dcs.at("2");
    EXPECT_EQ(dc.pool_target, 2U);
    EXPECT_EQ(dc.scale_up_total, 1U);
}

TEST(MeAudit, DemandRaisesPoolTargetInOneScalingDecision) {
    AuditReactor test("ramp-target");
    using Impl = mtdd::Runtime::Impl;
    const auto now = Impl::Clock::now();
    test.reactor->config_.me_connections_per_dc = 24;
    test.reactor->config_.me_clients_per_writer = 10;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = pool.serving_generation = 1;
    auto owned = std::make_unique<Impl::MeConn>();
    auto* first = owned.get();
    first->dc = 2;
    first->generation = 1;
    first->state = Impl::MeConn::State::ready;
    first->clients = 31;
    first->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(owned));

    // ceil(31 / 10) = 4 writers. The target must jump on the first decision (a
    // restart used to add one writer per 10 s decision, which starved the pool
    // for minutes at load), while the sockets still follow the batch bounds.
    test.reactor->scale_me_pool(2, now);
    EXPECT_EQ(pool.scale_target, 4U);
    EXPECT_EQ(test.reactor->stats_.snapshot().me_dcs.at("2").pool_target, 4U);
    EXPECT_EQ(test.reactor->stats_.snapshot().me_dcs.at("2").scale_up_total, 3U);
    EXPECT_EQ(pool.conns.size(), 4U);
    EXPECT_FALSE(first->draining);
}

TEST(MeAudit, DemandRampCapsAtConfiguredWritersAndOpensInBatches) {
    AuditReactor test("ramp-batch");
    using Impl = mtdd::Runtime::Impl;
    const auto now = Impl::Clock::now();
    test.reactor->config_.me_connections_per_dc = 24;
    test.reactor->config_.me_clients_per_writer = 10;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = pool.serving_generation = 1;
    auto owned = std::make_unique<Impl::MeConn>();
    owned->dc = 2;
    owned->generation = 1;
    owned->state = Impl::MeConn::State::ready;
    owned->clients = 1000000;
    owned->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(owned));

    test.reactor->scale_me_pool(2, now);
    EXPECT_EQ(pool.scale_target, 24U) << "demand must not raise the cap";
    ASSERT_EQ(pool.conns.size(), 1U + mtdd::detail::kMeDialBatch)
        << "one decision must not open every missing socket at once";
    // The new sockets are dialling, so the concurrent batch is full and another
    // tick must not add sockets on top of it.
    test.reactor->scale_me_pool(2, now);
    EXPECT_EQ(pool.conns.size(), 1U + mtdd::detail::kMeDialBatch);
    // A batch that fails to connect releases its slots; the fill path runs
    // before the 10 s decision gate, so the same decision interval continues the
    // ramp instead of waiting one decision per writer.
    for (auto& member : pool.conns) member->state = Impl::MeConn::State::backoff;
    test.reactor->scale_me_pool(2, now);
    EXPECT_EQ(pool.conns.size(), 1U + 2U * mtdd::detail::kMeDialBatch);
    EXPECT_EQ(test.reactor->stats_.snapshot().me_dcs.at("2").pool_target, 24U);
    EXPECT_EQ(test.reactor->stats_.snapshot().me_dcs.at("2").scale_up_total, 23U);
}

TEST(MeAudit, PendingHandshakeBatchBoundsNewDials) {
    AuditReactor test("pending-batch");
    using Impl = mtdd::Runtime::Impl;
    const auto now = Impl::Clock::now();
    test.reactor->config_.me_connections_per_dc = 24;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = pool.serving_generation = 1;
    pool.scale_target = 8;
    for (std::size_t i = 0; i < mtdd::detail::kMePendingBatch; ++i) {
        auto member = std::make_unique<Impl::MeConn>();
        member->dc = 2;
        member->generation = 1;
        member->state = i % 2 == 0 ? Impl::MeConn::State::connecting
                                   : Impl::MeConn::State::handshaking;
        member->out.emplace(test.config.connection_queue_bytes);
        pool.conns.push_back(std::move(member));
    }
    test.reactor->ensure_me(2, now);
    EXPECT_EQ(pool.conns.size(), mtdd::detail::kMePendingBatch)
        << "a full dial/handshake batch must not open another socket";
}

TEST(MeAudit, WriterCapReservesCapacityForMetadataReplacement) {
    AuditReactor test("elastic-cap");
    using Impl = mtdd::Runtime::Impl;
    const auto now = Impl::Clock::now();
    test.reactor->metadata_snapshot_ = me_metadata(1);
    auto& others = test.reactor->me_pool_[4];
    for (unsigned i = 0; i < 62; ++i) {
        others.conns.push_back(std::make_unique<Impl::MeConn>());
    }
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = pool.serving_generation = 1;
    auto old = std::make_unique<Impl::MeConn>();
    old->dc = 2;
    old->generation = 1;
    old->state = Impl::MeConn::State::ready;
    pool.conns.push_back(std::move(old));
    pool.scale_target = 2;
    test.reactor->ensure_me(2, now);
    EXPECT_EQ(pool.conns.size(), 1U);
    pool.desired_generation = 2;
    test.reactor->ensure_me(2, now);
    EXPECT_EQ(pool.conns.size(), 2U);
}

TEST(MeAudit, ReplacementKeepsReadinessUntilSuccessorIsReady) {
    AuditReactor test("generation-ready");
    test.reactor->config_.me_connections_per_dc = 1;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    test.reactor->enabled_users_ = 1;
    test.reactor->next_me_generation_ = 1;
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = 1;
    pool.serving_generation = 1;

    // The working generation: ready and NOT draining.
    auto old_owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
    auto* old_me = old_owned.get();
    old_me->dc = 2;
    old_me->generation = 1;
    old_me->state = mtdd::Runtime::Impl::MeConn::State::ready;
    old_me->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(old_owned));
    test.reactor->recompute_ready();
    ASSERT_TRUE(test.reactor->stats_.ready());

    // Between "successor created" and "successor ready" the old generation keeps
    // counting: a metadata replacement must not take the node out of rotation.
    test.reactor->advance_me_generation(2, mtdd::Runtime::Impl::Clock::now());
    ASSERT_EQ(pool.conns.size(), 2U) << "the successor socket was not created";
    EXPECT_FALSE(old_me->draining)
        << "the working generation started draining before the successor was ready";
    EXPECT_TRUE(test.reactor->stats_.ready());

    // The successor becomes ready -> the old generation starts draining, and the
    // node stays ready because the successor is.
    mtdd::Runtime::Impl::MeConn* successor = nullptr;
    for (auto& connection : pool.conns) {
        if (connection->generation == pool.desired_generation) successor = connection.get();
    }
    ASSERT_NE(successor, nullptr);
    auto ready = make_ready();
    successor->state = mtdd::Runtime::Impl::MeConn::State::handshaking;
    successor->session = std::move(ready.session);
    test.reactor->on_me_ready(*successor, mtdd::Runtime::Impl::Clock::now());

    EXPECT_TRUE(old_me->draining) << "the older generation did not start draining";
    EXPECT_GT(old_me->draining_deadline, mtdd::Runtime::Impl::Clock::now());
    EXPECT_TRUE(test.reactor->stats_.ready())
        << "readiness dropped when the successor took over";
    const auto snapshot = test.reactor->stats_.snapshot();
    EXPECT_EQ(snapshot.me_dcs.at("2").connections, 2U);
    EXPECT_EQ(snapshot.me_dcs.at("2").ready_connections, 1U)
        << "a draining connection must not count as ready";
}

TEST(MeAudit, RapidMetadataChangesKeepOnlyTheWorkingAndOneNewGeneration) {
    AuditReactor test("generation-bound");
    test.reactor->config_.me_connections_per_dc = 1;
    const auto now = mtdd::Runtime::Impl::Clock::now();
    test.reactor->metadata_snapshot_ = me_metadata(1);

    // Generation 1 is serving; generation 2 is an attempt to reach an endpoint
    // that never became ready (the DC address changed twice in quick succession).
    auto& pool = test.reactor->me_pool_[2];
    test.reactor->next_me_generation_ = 2;
    pool.desired_generation = 2;
    pool.serving_generation = 1;
    auto add = [&](std::uint64_t generation, mtdd::Runtime::Impl::MeConn::State state) {
        auto owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
        auto* connection = owned.get();
        connection->dc = 2;
        connection->generation = generation;
        connection->state = state;
        connection->attempt = 1000; // keep retry backoff out of this unit test
        connection->out.emplace(test.config.connection_queue_bytes);
        connection->token =
            test.reactor->add_target({mtdd::Runtime::Impl::Kind::me, connection});
        connection->ping_token =
            test.reactor->add_target({mtdd::Runtime::Impl::Kind::me_ping, connection});
        test.reactor->me_by_token_[connection->token] = connection;
        pool.conns.push_back(std::move(owned));
        return connection;
    };
    auto* working = add(1, mtdd::Runtime::Impl::MeConn::State::ready);
    const std::uint64_t intermediate_token = add(2, mtdd::Runtime::Impl::MeConn::State::connecting)->token;

    test.reactor->advance_me_generation(2, now);
    EXPECT_EQ(pool.conns.size(), 2U) << "an intermediate generation accumulated in the pool";
    EXPECT_EQ(test.reactor->me_by_token_.count(intermediate_token), 0U)
        << "the never-ready intermediate generation was not retired";
    EXPECT_EQ(working->generation, 1U);
    EXPECT_TRUE(pool_has_generation(pool, 1))
        << "the working generation was dropped while its successor was not ready";
    EXPECT_EQ(std::count_if(pool.conns.begin(), pool.conns.end(),
                            [&](const std::unique_ptr<mtdd::Runtime::Impl::MeConn>& c) {
                                return c->generation == pool.desired_generation;
                            }),
              1) << "the newest generation was not created exactly once";
    EXPECT_FALSE(working->draining);
    EXPECT_EQ(pool.desired_generation, 3U);
}

TEST(MeAudit, DisappearedDcDrainsWithoutSuccessorAndResetsGenerations) {
    AuditReactor test("dc-gone");
    const auto now = mtdd::Runtime::Impl::Clock::now();
    auto snapshot = std::make_shared<mtdd::MeMetadata>();
    mtdd::MeEndpoint other;
    other.dc = 4;
    other.host = "127.0.0.1";
    other.port = 1;
    snapshot->endpoints.push_back(other);
    snapshot->secret.assign(128, 7);
    test.reactor->metadata_snapshot_ = snapshot;

    auto& pool = test.reactor->me_pool_[2];
    test.reactor->next_me_generation_ = 1;
    pool.desired_generation = 1;
    pool.serving_generation = 1;
    pool.scale_target = 2;
    auto owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
    auto* me = owned.get();
    me->dc = 2;
    me->generation = 1;
    me->state = mtdd::Runtime::Impl::MeConn::State::ready;
    me->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(owned));

    test.reactor->advance_me_generation(2, now);
    EXPECT_TRUE(me->draining) << "a route that disappeared must drain";
    EXPECT_GT(me->draining_deadline, mtdd::Runtime::Impl::Clock::now());
    EXPECT_EQ(pool.conns.size(), 1U) << "no successor can exist for a dropped DC";
    EXPECT_EQ(pool.desired_generation, 0U);
    EXPECT_EQ(pool.scale_target, 1U);
}

TEST(MeAudit, PerDcMetricsAggregateAndStayMonotoneAcrossReplacements) {
    AuditReactor test("pool-metrics");
    const auto now = mtdd::Runtime::Impl::Clock::now();
    auto& pool = test.reactor->me_pool_[2];
    auto add = [&](double rtt_us) {
        auto owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
        auto* connection = owned.get();
        connection->dc = 2;
        connection->generation = 1;
        connection->state = mtdd::Runtime::Impl::MeConn::State::ready;
        connection->out.emplace(test.config.connection_queue_bytes);
        if (rtt_us > 0.0) {
            connection->rtt_valid = true;
            connection->rtt_ema_us = rtt_us;
        }
        pool.conns.push_back(std::move(owned));
        return connection;
    };
    auto* fast = add(5'000.0);
    auto* slow = add(25'000.0);
    fast->control_close_conn = 2;
    fast->control_unknown = 1;
    slow->control_close_conn = 3;

    test.reactor->publish_me_pool(2);
    auto snapshot = test.reactor->stats_.snapshot();
    EXPECT_EQ(snapshot.me_dcs.at("2").ping_rtt_us, 15'000U)
        << "the per-DC RTT gauge is not the aggregate of the ready members";
    EXPECT_EQ(snapshot.me_dcs.at("2").control_close_conn, 5U);
    EXPECT_EQ(snapshot.me_dcs.at("2").control_unknown, 1U);

    // Replacing the fast connection must not move the counters backwards: its
    // counters are folded into the DC base by retire_me().
    fast->draining = true;
    fast->draining_deadline = now;
    test.reactor->reap_me_pool(now + std::chrono::seconds(1));
    EXPECT_EQ(pool.conns.size(), 1U);
    snapshot = test.reactor->stats_.snapshot();
    EXPECT_EQ(snapshot.me_dcs.at("2").control_close_conn, 5U)
        << "inbound control counters fell back after a pool member was replaced";
    EXPECT_EQ(snapshot.me_dcs.at("2").control_unknown, 1U);
    EXPECT_EQ(snapshot.me_dcs.at("2").ping_rtt_us, 25'000U)
        << "the RTT gauge did not fall back to the remaining member";

    // A DC without any connection keeps its accumulated counters (the
    // connected=false transition must not clear them).
    slow->draining = true;
    slow->draining_deadline = now;
    test.reactor->reap_me_pool(now + std::chrono::seconds(1));
    EXPECT_TRUE(pool.conns.empty());
    snapshot = test.reactor->stats_.snapshot();
    EXPECT_FALSE(snapshot.me_dcs.at("2").connected);
    EXPECT_EQ(snapshot.me_dcs.at("2").control_close_conn, 5U);
    EXPECT_EQ(snapshot.me_dcs.at("2").control_unknown, 1U);
}

TEST(MeAudit, PerDcSocketBytesStayMonotoneAcrossTwoPoolReplacements) {
    AuditReactor test("pool-bytes");
    const auto now = mtdd::Runtime::Impl::Clock::now();
    auto& pool = test.reactor->me_pool_[2];
    auto add = [&](std::uint64_t rx, std::uint64_t tx) {
        auto owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
        auto* connection = owned.get();
        connection->dc = 2;
        connection->generation = 1;
        connection->state = mtdd::Runtime::Impl::MeConn::State::ready;
        connection->out.emplace(test.config.connection_queue_bytes);
        connection->rx_bytes = rx;
        connection->tx_bytes = tx;
        pool.conns.push_back(std::move(owned));
        return connection;
    };

    std::uint64_t rx_high_water = 0;
    std::uint64_t tx_high_water = 0;
    auto publish = [&](const char* what) {
        test.reactor->publish_me_io(2);
        const auto snapshot = test.reactor->stats_.snapshot();
        const auto& dc = snapshot.me_dcs.at("2");
        EXPECT_GE(dc.rx_bytes_total, rx_high_water)
            << "mtdd_me_rx_bytes_total moved backwards at " << what;
        EXPECT_GE(dc.tx_bytes_total, tx_high_water)
            << "mtdd_me_tx_bytes_total moved backwards at " << what;
        rx_high_water = dc.rx_bytes_total;
        tx_high_water = dc.tx_bytes_total;
        return std::pair{rx_high_water, tx_high_water};
    };

    auto* first = add(1'000, 2'000);
    (void)add(500, 700);
    EXPECT_EQ(publish("the initial pool"),
              (std::pair<std::uint64_t, std::uint64_t>{1'500, 2'700}));
    const auto before_replacements = std::pair{rx_high_water, tx_high_water};

    // First replacement: the retired member's bytes are folded into the DC
    // base, so the aggregate is unchanged instead of dropping to the survivor.
    first->draining = true;
    first->draining_deadline = now;
    test.reactor->reap_me_pool(now + std::chrono::seconds(1));
    EXPECT_EQ(pool.conns.size(), 1U);
    EXPECT_EQ(publish("the first replacement"), before_replacements);

    // A successor joins with fresh traffic; totals only grow.
    (void)add(300, 400);
    EXPECT_EQ(publish("a successor joining"),
              (std::pair<std::uint64_t, std::uint64_t>{1'800, 3'100}));

    // Second replacement, then the whole pool empties: the folded base keeps the
    // series monotone and non-zero even with no live connection left.
    for (auto& connection : pool.conns) {
        if (!connection || connection->draining) continue;
        connection->draining = true;
        connection->draining_deadline = now;
    }
    test.reactor->reap_me_pool(now + std::chrono::seconds(1));
    EXPECT_TRUE(pool.conns.empty());
    const auto after_two_replacements = publish("the emptied pool");
    EXPECT_GE(after_two_replacements.first, before_replacements.first);
    EXPECT_GE(after_two_replacements.second, before_replacements.second);
    EXPECT_EQ(after_two_replacements,
              (std::pair<std::uint64_t, std::uint64_t>{1'800, 3'100}));

    // A brand-new generation of the same DC starts from the accumulated base.
    (void)add(50, 60);
    EXPECT_EQ(publish("a rebuilt generation"),
              (std::pair<std::uint64_t, std::uint64_t>{1'850, 3'160}));
}

TEST(MeAudit, FailedSuccessorRollsBackToTheDrainingGeneration) {
    AuditReactor test("generation-rollback");
    test.reactor->enabled_users_ = 1;
    test.reactor->metadata_snapshot_ = me_metadata(1);
    test.reactor->next_me_generation_ = 2;
    auto& pool = test.reactor->me_pool_[2];
    pool.desired_generation = 2;
    pool.serving_generation = 2;

    // Generation 1 is draining but still ready with a live client; generation 2
    // took over and then failed, so no non-draining ready connection is left.
    auto old_owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
    auto* old_me = old_owned.get();
    old_me->dc = 2;
    old_me->generation = 1;
    old_me->state = mtdd::Runtime::Impl::MeConn::State::ready;
    old_me->clients = 1;
    old_me->draining = true;
    old_me->draining_deadline = mtdd::Runtime::Impl::Clock::now() + std::chrono::seconds(5);
    old_me->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(old_owned));

    auto successor_owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
    successor_owned->dc = 2;
    successor_owned->generation = 2;
    successor_owned->state = mtdd::Runtime::Impl::MeConn::State::backoff;
    successor_owned->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(successor_owned));

    // A second, idle member of the working generation must be promoted as well:
    // the rollback restores the whole generation, not just the connections that
    // happen to have clients.
    auto idle_owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
    auto* idle_me = idle_owned.get();
    idle_me->dc = 2;
    idle_me->generation = 1;
    idle_me->state = mtdd::Runtime::Impl::MeConn::State::ready;
    idle_me->draining = true;
    idle_me->draining_deadline = mtdd::Runtime::Impl::Clock::now() + std::chrono::seconds(5);
    idle_me->out.emplace(test.config.connection_queue_bytes);
    pool.conns.push_back(std::move(idle_owned));

    test.reactor->recompute_ready();
    EXPECT_TRUE(test.reactor->stats_.ready())
        << "the node reported not-ready while the previous generation still relayed";
    EXPECT_FALSE(old_me->draining) << "the working generation was not promoted back";
    EXPECT_FALSE(idle_me->draining) << "the idle member of the working generation stayed draining";
    EXPECT_EQ(pool.serving_generation, 1U);
    EXPECT_TRUE(test.reactor->stats_.snapshot().me_dcs.at("2").connected);

    // A DC that disappeared from the metadata must NOT be resurrected: its
    // draining connections expire on the hard deadline instead.
    auto snapshot = std::make_shared<mtdd::MeMetadata>();
    mtdd::MeEndpoint other;
    other.dc = 4;
    other.host = "127.0.0.1";
    other.port = 1;
    snapshot->endpoints.push_back(other);
    snapshot->secret.assign(128, 7);
    test.reactor->metadata_snapshot_ = snapshot;
    pool.serving_generation = 2;
    // What drain_me_pool() does when the route disappears: every non-draining
    // member starts draining, and none of them may be promoted back.
    old_me->draining = true;
    old_me->draining_deadline = mtdd::Runtime::Impl::Clock::now() + std::chrono::seconds(5);
    idle_me->draining = true;
    idle_me->draining_deadline = mtdd::Runtime::Impl::Clock::now() + std::chrono::seconds(5);
    test.reactor->recompute_ready();
    EXPECT_TRUE(old_me->draining) << "a dropped DC was resurrected from its draining pool";
    EXPECT_TRUE(idle_me->draining);
    EXPECT_FALSE(test.reactor->stats_.ready());
}

}  // namespace

TEST(MeAudit, ReloadedPoolTunablesReachTheReactorAndClampTargets) {
    AuditReactor test("live-tunables");
    auto& reactor = *test.reactor;
    reactor.config_.me_clients_per_writer = 400;
    reactor.config_.me_connections_per_dc = 16;
    auto& pool = reactor.me_pool_[2];
    pool.scale_target = 12;
    pool.desired_generation = pool.serving_generation = 1;
    std::vector<mtdd::Runtime::Impl::MeConn*> writers;
    for (std::size_t clients : {5U, 1U, 9U, 3U}) {
        auto owned = std::make_unique<mtdd::Runtime::Impl::MeConn>();
        owned->dc = 2;
        owned->generation = 1;
        owned->state = mtdd::Runtime::Impl::MeConn::State::ready;
        owned->clients = clients;
        writers.push_back(owned.get());
        pool.conns.push_back(std::move(owned));
    }
    // No new generation: nothing changes (direct config edits stay intact).
    reactor.apply_shared_tunables();
    EXPECT_EQ(reactor.config_.me_clients_per_writer, 400U);
    // A reload publishes new values and bumps the generation.
    reactor.shared_->me_clients_per_writer.store(1500);
    reactor.shared_->me_connections_per_dc.store(2);
    reactor.shared_->tunables_generation.fetch_add(1);
    reactor.apply_shared_tunables();
    EXPECT_EQ(reactor.config_.me_clients_per_writer, 1500U);
    EXPECT_EQ(reactor.config_.me_connections_per_dc, 2U);
    EXPECT_EQ(pool.scale_target, 2U) << "target above the new cap is clamped";
    // The two least-loaded writers are scale-drained; none is closed.
    EXPECT_TRUE(writers[1]->draining && writers[1]->scale_draining);
    EXPECT_TRUE(writers[3]->draining && writers[3]->scale_draining);
    EXPECT_FALSE(writers[0]->draining);
    EXPECT_FALSE(writers[2]->draining);
    EXPECT_EQ(pool.conns.size(), 4U);
    // Applied once per generation.
    reactor.config_.me_clients_per_writer = 7;
    reactor.apply_shared_tunables();
    EXPECT_EQ(reactor.config_.me_clients_per_writer, 7U);
}

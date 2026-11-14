#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// FakeTLS ClientHello split over several TLS handshake records (ByeDPI
// --tlsrec, zapret). The proxy authenticates the reassembled record; anything
// that is not a valid hello reaches masking exactly as the client sent it.
// ---------------------------------------------------------------------------

namespace {

using mtdd::control::SuspectSignal;

struct SplitDirectScope {
    explicit SplitDirectScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~SplitDirectScope() { mtdd::detail::set_direct_endpoint_override(std::nullopt); }
    SplitDirectScope(const SplitDirectScope&) = delete;
    SplitDirectScope& operator=(const SplitDirectScope&) = delete;
};

struct SplitMaskingScope {
    explicit SplitMaskingScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~SplitMaskingScope() { mtdd::detail::set_masking_endpoint_override(std::nullopt); }
    SplitMaskingScope(const SplitMaskingScope&) = delete;
    SplitMaskingScope& operator=(const SplitMaskingScope&) = delete;
};

void enable_split_direct(mtdd::Config& config) {
    config.direct_fallback_enabled = true;
    config.direct_fallback_dcs = {2};
    config.max_connections = 8;
    config.max_handshakes = 8;
}

// Re-frames the body of one ClientHello record as consecutive handshake
// records whose bodies have `sizes` bytes; the last record takes the rest.
Bytes split_hello(const Bytes& record, std::initializer_list<std::size_t> sizes) {
    const auto body = std::span<const std::uint8_t>(record).subspan(5);
    Bytes out;
    std::size_t pos = 0;
    auto emit = [&](std::size_t size) {
        out.insert(out.end(), {0x16, record[1], record[2]});
        put16(out, static_cast<std::uint16_t>(size));
        append(out, body.subspan(pos, size));
        pos += size;
    };
    for (const std::size_t size : sizes) emit(size);
    if (pos < body.size()) emit(body.size() - pos);
    return out;
}

Bytes split_even(const Bytes& record, std::size_t count) {
    const std::size_t body = record.size() - 5;
    std::vector<std::size_t> sizes;
    for (std::size_t i = 0; i + 1 < count; ++i) sizes.push_back(body / count);
    Bytes out;
    std::size_t pos = 0;
    for (const std::size_t size : sizes) {
        out.insert(out.end(), {0x16, record[1], record[2]});
        put16(out, static_cast<std::uint16_t>(size));
        append(out, std::span<const std::uint8_t>(record).subspan(5 + pos, size));
        pos += size;
    }
    out.insert(out.end(), {0x16, record[1], record[2]});
    put16(out, static_cast<std::uint16_t>(body - pos));
    append(out, std::span<const std::uint8_t>(record).subspan(5 + pos));
    return out;
}

// Reads ServerHello + CCS + the fake certificate record.
bool read_server_flight(int fd) {
    for (int record = 0; record < 4; ++record) {
        std::uint8_t header[5]{};
        if (!recv_exact(fd, header, sizeof(header), 3000)) return false;
        const std::size_t length = (static_cast<std::size_t>(header[3]) << 8) | header[4];
        Bytes body(length);
        if (length > 0 && !recv_exact(fd, body.data(), length, 3000)) return false;
        if (header[0] == 0x17) return true;
    }
    return false;
}

// One FakeTLS session whose ClientHello is `hello`. The hello, CCS, the
// obfuscation header and one message go out in a single write, so any byte
// the proxy swallowed into the hello buffer would break the session.
bool split_session(std::uint16_t port, const Bytes& hello, const Bytes& payload, Bytes& echoed) {
    const int fd = connect_loopback(port);
    if (fd < 0) return false;
    const auto obfuscation = make_obfuscation(secret_bytes(), 2);
    mtdd::protocol::crypto::AesCtr c2s(obfuscation.decrypt_key, obfuscation.decrypt_iv);
    c2s.skip(64);
    Bytes frame;
    put32(frame, static_cast<std::uint32_t>(payload.size()));
    append(frame, payload);
    c2s.apply(frame);
    Bytes wire = hello;
    append(wire, Bytes{0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    append(wire, tls_record(0x17, obfuscation.wire));
    append(wire, tls_record(0x17, frame));
    bool ok = send_all(fd, wire) && read_server_flight(fd);
    mtdd::protocol::crypto::AesCtr s2c(obfuscation.encrypt_key, obfuscation.encrypt_iv);
    Bytes plain;
    while (ok && (plain.size() < 4 || plain.size() < 4 + rd32(plain, 0))) {
        std::uint8_t header[5]{};
        ok = recv_exact(fd, header, sizeof(header), 3000);
        if (!ok) break;
        const std::size_t length = (static_cast<std::size_t>(header[3]) << 8) | header[4];
        Bytes body(length);
        ok = header[0] == 0x17 && length > 0 && recv_exact(fd, body.data(), length, 3000);
        if (!ok) break;
        s2c.apply(body);
        append(plain, body);
    }
    ::close(fd);
    if (!ok) return false;
    echoed.assign(plain.begin() + 4, plain.begin() + 4 + rd32(plain, 0));
    return true;
}

Bytes wrong_secret_hello(std::uint8_t variant) {
    A16 wrong{};
    wrong.fill(0xaa);
    return make_client_hello(wrong, current_timestamp(), kDomain, variant);
}

std::uint32_t suspect_count(Daemon& daemon, SuspectSignal signal) {
    for (const auto& row : daemon.services.stats.suspects()) {
        if (row.ip == "127.0.0.1") return row.hits[static_cast<std::size_t>(signal)];
    }
    return 0;
}

// Sends `wire` and expects the masking echo backend to return it unchanged.
void expect_masked_verbatim(Daemon& daemon, const Bytes& wire) {
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, wire));
    Bytes echoed(wire.size());
    EXPECT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
    EXPECT_EQ(echoed, wire);
    ::close(fd);
}

} // namespace

TEST(HelloSplit, SplitHelloAuthenticatesAndRelaysLikeTheUnsplitOne) {
    mtdd::test::FakeDirectDc dc(2);
    SplitDirectScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_split_direct(config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    const auto secret = secret_bytes();
    const Bytes payload(64, 0x5c);
    std::uint8_t variant = 0;
    const auto hello = [&] { return make_client_hello(secret, current_timestamp(), kDomain, ++variant); };
    std::vector<std::pair<std::string, Bytes>> cases;
    cases.emplace_back("unsplit", hello());
    cases.emplace_back("first=1", split_hello(hello(), {1}));
    cases.emplace_back("first=3", split_hello(hello(), {3}));
    cases.emplace_back("first=4", split_hello(hello(), {4}));
    cases.emplace_back("first=5", split_hello(hello(), {5}));
    cases.emplace_back("2 records", split_even(hello(), 2));
    cases.emplace_back("16 records", split_even(hello(), 16));
    for (const auto& [name, wire] : cases) {
        SCOPED_TRACE(name);
        Bytes echoed;
        ASSERT_TRUE(split_session(daemon.port(), wire, payload, echoed));
        EXPECT_EQ(echoed, payload);
    }
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "success") >= cases.size(); },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 0U);
}

TEST(HelloSplit, SplitHelloReplayIsStillRejected) {
    mtdd::test::FakeDirectDc dc(2);
    SplitDirectScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_split_direct(config); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    const Bytes hello = make_client_hello(secret_bytes(), current_timestamp(), kDomain, 9);
    Bytes echoed;
    ASSERT_TRUE(split_session(daemon.port(), hello, Bytes(16, 0x01), echoed));
    // The same signed hello, now split: the canonical HMAC is the replay key.
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, split_hello(hello, {2})));
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "replay"), 1U);
}

TEST(HelloSplit, WrongSecretSplitHelloIsMaskedVerbatim) {
    EchoBackend echo;
    SplitMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = true;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    // Every fragment header intact, plus a tail the client sent after the
    // hello in the same write.
    Bytes wire = split_hello(wrong_secret_hello(1), {1, 2, 40});
    for (int i = 0; i < 777; ++i) wire.push_back(0x5a);
    expect_masked_verbatim(daemon, wire);
    EXPECT_GE(echo.accepted(), 1U);
    // The reassembled hello carries our SNI: someone who knows the domain but
    // not a secret. The 1-byte first record alone is not junk.
    EXPECT_TRUE(wait_for([&] { return suspect_count(daemon, SuspectSignal::wrong_secret) >= 1U; },
                         3000ms));
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 0U);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
}

TEST(HelloSplit, InvalidFragmentIsMaskedVerbatim) {
    EchoBackend echo;
    SplitMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = true;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    Bytes wire = split_hello(make_client_hello(secret_bytes(), current_timestamp(), kDomain, 2),
                             {3, 50});
    wire[8] = 0x17;  // the second record is not a handshake record
    expect_masked_verbatim(daemon, wire);
    EXPECT_TRUE(wait_for([&] { return suspect_count(daemon, SuspectSignal::junk) >= 1U; }, 3000ms));
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
}

TEST(HelloSplit, WrongSecretSplitHelloIsClosedWithoutMasking) {
    Daemon daemon(1, false, [](mtdd::Config& config) { config.masking = false; });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, split_hello(wrong_secret_hello(3), {3})));
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
    EXPECT_GE(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 1U);
}

TEST(HelloSplit, ShortFirstRecordThatNeverCompletesEndsByHandshakeTimeout) {
    EchoBackend echo;
    SplitMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = true;
        config.suspects = true;
        config.handshake_timeout = std::chrono::seconds{1};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const Bytes wire = split_hello(make_client_hello(secret_bytes(), current_timestamp(), kDomain, 4),
                                   {3});
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, std::span<const std::uint8_t>(wire).first(8)));  // first record only
    EXPECT_TRUE(wait_closed(fd, 4000));
    ::close(fd);
    EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "timeout"), 1U);
    EXPECT_EQ(echo.accepted(), 0U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 0U);
}

TEST(HelloSplit, LargestSixteenRecordHelloIsMaskedWithTheSmallestQueue) {
    EchoBackend echo;
    SplitMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = true;
        config.connection_queue_bytes = 4096;  // the configured minimum
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    // Pad a wrong-secret hello to the largest accepted body (4096 bytes) with
    // a padding extension, then split it into 16 records: 4176 wire bytes.
    Bytes hello = wrong_secret_hello(5);
    const std::size_t pad = mtdd::protocol::kFakeTlsMaxClientHello - (hello.size() - 5) - 4;
    hello.insert(hello.end(), {0x00, 0x15});
    put16(hello, static_cast<std::uint16_t>(pad));
    hello.insert(hello.end(), pad, 0x00);
    const auto patch16 = [&](std::size_t offset, std::size_t value) {
        hello[offset] = static_cast<std::uint8_t>(value >> 8);
        hello[offset + 1] = static_cast<std::uint8_t>(value);
    };
    const std::size_t body = hello.size() - 5;
    ASSERT_EQ(body, mtdd::protocol::kFakeTlsMaxClientHello);
    patch16(3, body);                // record length
    patch16(7, body - 4);            // handshake length (low 16 bits)
    patch16(84, hello.size() - 86);  // extensions length
    const Bytes wire = split_even(hello, mtdd::protocol::kFakeTlsMaxHelloRecords);
    ASSERT_EQ(wire.size(), mtdd::protocol::kFakeTlsMaxClientHello +
                               5 * mtdd::protocol::kFakeTlsMaxHelloRecords);
    ASSERT_EQ(mtdd::protocol::scan_client_hello(wire).status, mtdd::protocol::HelloStatus::Ok);
    expect_masked_verbatim(daemon, wire);
    EXPECT_GE(echo.accepted(), 1U);
}

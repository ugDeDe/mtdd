#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// PROXY protocol on the proxy listener (Config::proxy_protocol): the header's
// source address stands for the client; the front itself is never scored.
// ---------------------------------------------------------------------------

namespace {

struct PpDirectScope {
    explicit PpDirectScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~PpDirectScope() { mtdd::detail::set_direct_endpoint_override(std::nullopt); }
    PpDirectScope(const PpDirectScope&) = delete;
    PpDirectScope& operator=(const PpDirectScope&) = delete;
};

struct PpMaskingScope {
    explicit PpMaskingScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~PpMaskingScope() { mtdd::detail::set_masking_endpoint_override(std::nullopt); }
    PpMaskingScope(const PpMaskingScope&) = delete;
    PpMaskingScope& operator=(const PpMaskingScope&) = delete;
};

void enable_proxy_protocol(mtdd::Config& config) {
    config.proxy_protocol = true;
    config.proxy_protocol_allow = {"127.0.0.0/8"};
}

Bytes text_bytes(std::string_view text) { return Bytes(text.begin(), text.end()); }

Bytes v2_header_v4(std::array<std::uint8_t, 4> source, std::uint16_t source_port) {
    Bytes out{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
              0x21, 0x11, 0x00, 0x0C};
    out.insert(out.end(), source.begin(), source.end());
    out.insert(out.end(), {127, 0, 0, 1});
    out.push_back(static_cast<std::uint8_t>(source_port >> 8));
    out.push_back(static_cast<std::uint8_t>(source_port));
    out.insert(out.end(), {0x01, 0xbb});
    return out;
}

Bytes v2_local() {
    return Bytes{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
                 0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00};
}

bool read_flight(int fd) {
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

// One Direct-route FakeTLS session: PROXY header, hello, CCS, obfuscation
// header and one message in a single write, so a byte of the stream lost to
// (or swallowed by) the header parser breaks it.
bool proxied_session(std::uint16_t port, const Bytes& header, const Bytes& payload,
                     Bytes& echoed) {
    const int fd = connect_loopback(port);
    if (fd < 0) return false;
    const auto obfuscation = make_obfuscation(secret_bytes(), 2);
    mtdd::protocol::crypto::AesCtr c2s(obfuscation.decrypt_key, obfuscation.decrypt_iv);
    c2s.skip(64);
    Bytes frame;
    put32(frame, static_cast<std::uint32_t>(payload.size()));
    append(frame, payload);
    c2s.apply(frame);
    Bytes wire = header;
    append(wire, make_client_hello(secret_bytes(), current_timestamp(), kDomain,
                                   static_cast<std::uint8_t>(header.size())));
    append(wire, Bytes{0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    append(wire, tls_record(0x17, obfuscation.wire));
    append(wire, tls_record(0x17, frame));
    bool ok = send_all(fd, wire) && read_flight(fd);
    mtdd::protocol::crypto::AesCtr s2c(obfuscation.encrypt_key, obfuscation.encrypt_iv);
    Bytes plain;
    while (ok && (plain.size() < 4 || plain.size() < 4 + rd32(plain, 0))) {
        std::uint8_t record[5]{};
        ok = recv_exact(fd, record, sizeof(record), 3000);
        if (!ok) break;
        const std::size_t length = (static_cast<std::size_t>(record[3]) << 8) | record[4];
        Bytes body(length);
        ok = record[0] == 0x17 && length > 0 && recv_exact(fd, body.data(), length, 3000);
        if (!ok) break;
        s2c.apply(body);
        append(plain, body);
    }
    ::close(fd);
    if (!ok) return false;
    echoed.assign(plain.begin() + 4, plain.begin() + 4 + rd32(plain, 0));
    return true;
}

bool has_suspect_ip(Daemon& daemon, std::string_view ip) {
    for (const auto& row : daemon.services.stats.suspects()) {
        if (row.ip == ip) return true;
    }
    return false;
}

Bytes wrong_secret_hello() {
    A16 wrong{};
    wrong.fill(0xaa);
    return make_client_hello(wrong, current_timestamp(), kDomain, 1);
}

}  // namespace

TEST(ProxyProtocol, HeaderAndSessionInOneWriteRelayForEveryHeaderForm) {
    mtdd::test::FakeDirectDc dc(2);
    PpDirectScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_proxy_protocol(config);
        config.direct_fallback_enabled = true;
        config.direct_fallback_dcs = {2};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    std::vector<std::pair<std::string, Bytes>> cases;
    cases.emplace_back("v1 tcp4", text_bytes("PROXY TCP4 203.0.113.7 127.0.0.1 40000 443\r\n"));
    cases.emplace_back("v1 tcp6", text_bytes("PROXY TCP6 2001:db8::7 ::1 40001 443\r\n"));
    cases.emplace_back("v1 unknown", text_bytes("PROXY UNKNOWN\r\n"));
    cases.emplace_back("v1 longest",
                       text_bytes("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff "
                                  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"));
    cases.emplace_back("v2 tcp4", v2_header_v4({198, 51, 100, 9}, 40002));
    cases.emplace_back("v2 local", v2_local());
    const Bytes payload(48, 0x3c);
    for (const auto& [name, header] : cases) {
        SCOPED_TRACE(name);
        Bytes echoed;
        ASSERT_TRUE(proxied_session(daemon.port(), header, payload, echoed));
        EXPECT_EQ(echoed, payload);
    }
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "success") >= cases.size(); },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 0U);
}

TEST(ProxyProtocol, HeaderSourceIsTheClientAddressReportedToTelegram) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, enable_proxy_protocol);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    // The header arrives on its own, byte by byte.
    for (const std::uint8_t byte : v2_header_v4({203, 0, 113, 50}, 51515)) {
        ASSERT_TRUE(send_all(fd, Bytes{byte}));
    }
    TestClient client(TestClient::Adopt{}, fd, secret_bytes());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    ASSERT_EQ(me.future().wait_for(5s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    EXPECT_EQ(observation.client_addr,
              mtdd::protocol::Endpoint::v4({203, 0, 113, 50}, 51515).wire20());
    EXPECT_EQ(observation.ad_tag, daemon.services.config.ad_tag);
}

TEST(ProxyProtocol, MissingOrMalformedHeaderIsClosedNotMasked) {
    EchoBackend echo;
    PpMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        enable_proxy_protocol(config);
        config.masking = true;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const std::vector<Bytes> wires = {
        make_client_hello(secret_bytes(), current_timestamp(), kDomain, 3),  // no header
        text_bytes("PROXY TCP4 1.2.3.4 5.6.7.8 0 443\r\n"),                  // source port 0
        text_bytes("PROXY TCP4 1.2.3.4\r\n"),
        text_bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        Bytes(200, 'P'),  // no CRLF within 107 bytes
    };
    for (const auto& wire : wires) {
        const int fd = connect_loopback(daemon.port());
        ASSERT_GE(fd, 0);
        ASSERT_TRUE(send_all(fd, wire));
        EXPECT_TRUE(wait_closed(fd, 3000));
        ::close(fd);
    }
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "rejected", "invalid_request") >= wires.size(); },
        3000ms));
    EXPECT_EQ(echo.accepted(), 0U);
    // The front itself is never a suspect.
    EXPECT_FALSE(has_suspect_ip(daemon, "127.0.0.1"));
}

TEST(ProxyProtocol, PeerOutsideTheAllowlistIsRefused) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.proxy_protocol = true;
        config.proxy_protocol_allow = {"10.0.0.0/8"};
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    (void)send_all(fd, text_bytes("PROXY TCP4 203.0.113.7 127.0.0.1 40000 443\r\n"));
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "rejected", "invalid_request") >= 1U; },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 0U);
}

TEST(ProxyProtocol, ProbeIsMaskedWithoutTheHeaderAndScoredUnderTheClientAddress) {
    EchoBackend echo;
    PpMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        enable_proxy_protocol(config);
        config.masking = true;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const Bytes hello = wrong_secret_hello();
    Bytes wire = text_bytes("PROXY TCP4 192.0.2.44 127.0.0.1 41000 443\r\n");
    append(wire, hello);
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, wire));
    Bytes echoed(hello.size());
    EXPECT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
    EXPECT_EQ(echoed, hello);  // the masking site never sees the header
    ::close(fd);
    EXPECT_TRUE(wait_for([&] { return has_suspect_ip(daemon, "192.0.2.44"); }, 3000ms));
    EXPECT_FALSE(has_suspect_ip(daemon, "127.0.0.1"));
}

TEST(ProxyProtocol, LocalHeaderIsNeverScoredAsSuspect) {
    EchoBackend echo;
    PpMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        enable_proxy_protocol(config);
        config.masking = true;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    Bytes wire = v2_local();
    append(wire, wrong_secret_hello());
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, wire));
    Bytes echoed(wire.size() - 16);
    EXPECT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
    ::close(fd);
    // A front health check (connect, close) is not a port check either.
    const int check = connect_loopback(daemon.port());
    ASSERT_GE(check, 0);
    ASSERT_TRUE(send_all(check, v2_local()));
    ::close(check);
    std::this_thread::sleep_for(300ms);
    EXPECT_TRUE(daemon.services.stats.suspects().empty());
}

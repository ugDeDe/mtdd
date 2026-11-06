#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {

// ----------------------------- Middle-End -----------------------------

namespace {

const A32 kMeSecret = [] {
  A32 s{};
  for (int i = 0; i < 32; ++i) s[i] = static_cast<std::uint8_t>(i);
  return s;
}();
const Endpoint kMeServer = Endpoint::v4({149, 154, 175, 50}, 8888);
// Outbound ME socket endpoint: the ephemeral port 54321 is KDF material only.
const Endpoint kMeLocal = Endpoint::v4({203, 0, 113, 9}, 54321);
// Proxy listener endpoint clients connect to; this is what RPC_PROXY_REQ must
// advertise as our_addr. Same IP, different port, so port semantics are tested
// independently of the address bytes.
const Endpoint kMeAdvertised = Endpoint::v4({203, 0, 113, 9}, 443);
const Endpoint kMeAdvertisedOtherIp = Endpoint::v4({192, 0, 2, 77}, 8443);
const Endpoint kPeer = Endpoint::v4({198, 51, 100, 7}, 40000);
constexpr std::uint16_t kMeProcessId = 0x1f3a;
constexpr std::uint32_t kMeProcessTime = 1600000000u;  // == kNow
// ME-side process_id used in the handshake answer fixture (server identity).
// IPv4 octets are reversed because Telegram process_id carries a host-order
// u32 (reference implementation reverses the octets; MTProxy memcpy()s a host-order u32).
const std::array<std::uint8_t, 12> kMeServerPid{50, 175, 154, 149, 0xb8, 0x22,
                                                0x34, 0x12, 0x00, 0x00, 0x00, 0x60};
// sender_pid bytes mtdd must emit. Reference layout (reference implementation handshake.rs
// `srv.reverse(); clt.reverse()` + codec.rs LE writes; MTProxy host-order
// memcpy): IPv4 reversed, outbound KDF socket port 54321, pid16, utime32.
const std::array<std::uint8_t, 12> kExpectedSenderPid{9, 113, 0, 203, 0x31, 0xd4,
                                                      0x3a, 0x1f, 0x00, 0x10, 0x5e, 0x5f};
// The previous placeholder identity must never be sent again.
const std::array<std::uint8_t, 12> kPlaceholderPid{'I', 'P', 'I', 'P', 'P',
                                                   'R', 'P', 'D', 'T', 'I', 'M', 'E'};
const std::array<std::uint8_t, 8> kConnId{1, 2, 3, 4, 5, 6, 7, 8};
const std::array<std::uint8_t, 16> kAdTag{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

Bytes me_plain_frame(std::int32_t seq, std::span<const std::uint8_t> payload) {
  EXPECT_EQ(payload.size() % 4, 0u);
  Bytes f = cat({le32(static_cast<std::uint32_t>(payload.size() + 12)), le32(static_cast<std::uint32_t>(seq))});
  f.insert(f.end(), payload.begin(), payload.end());
  f = cat({f, le32(crypto::crc32(f))});
  return f;
}

Bytes me_encrypted_frame(crypto::AesCbc& cbc, std::int32_t seq, std::span<const std::uint8_t> payload) {
  Bytes f = me_plain_frame(seq, payload);
  while (f.size() % 16 != 0) f = cat({f, le32(4)});
  cbc.encrypt(f);
  return f;
}

// Independent bitwise CRC-32C for test frames: a frame the implementation
// accepts must be checksummed with Castagnoli, without trusting crypto::crc32c.
std::uint32_t me_test_crc32c(std::span<const std::uint8_t> data) {
  std::uint32_t crc = 0xffffffffu;
  for (const auto byte : data) {
    crc ^= byte;
    for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1u) ? 0x82f63b78u : 0u);
  }
  return crc ^ 0xffffffffu;
}

Bytes me_encrypted_frame_crc32c(crypto::AesCbc& cbc, std::int32_t seq,
                                std::span<const std::uint8_t> payload) {
  EXPECT_EQ(payload.size() % 4, 0u);
  Bytes f = cat({le32(static_cast<std::uint32_t>(payload.size() + 12)),
                 le32(static_cast<std::uint32_t>(seq))});
  f.insert(f.end(), payload.begin(), payload.end());
  f = cat({f, le32(me_test_crc32c(f))});
  while (f.size() % 16 != 0) f = cat({f, le32(4)});
  cbc.encrypt(f);
  return f;
}

struct ThrowingSink : MiddleEndSession::Sink {
  void on_proxy_payload(const MiddleEndSession::ConnId&, std::span<const std::uint8_t>) override {
    throw std::runtime_error("sink boom");
  }
};

struct TestSink : MiddleEndSession::Sink {
  struct Data {
    std::array<std::uint8_t, 8> conn{};
    Bytes payload;
  };
  std::vector<Data> data;
  std::vector<std::pair<std::array<std::uint8_t, 8>, std::array<std::uint8_t, 4>>> acks;
  std::vector<std::array<std::uint8_t, 8>> closes;
  std::vector<std::int64_t> pongs;
  void on_proxy_payload(const std::array<std::uint8_t, 8>& conn, std::span<const std::uint8_t> p) override {
    data.push_back({conn, Bytes(p.begin(), p.end())});
  }
  void on_quick_ack(const std::array<std::uint8_t, 8>& conn, std::array<std::uint8_t, 4> c) override {
    acks.emplace_back(conn, c);
  }
  void on_remote_close(const std::array<std::uint8_t, 8>& conn) override { closes.push_back(conn); }
  void on_pong(std::int64_t ping_id) override { pongs.push_back(ping_id); }
};

MiddleEndConfig me_config(std::size_t max_frame = 1u << 20) {
  MiddleEndConfig cfg;
  cfg.secret.assign(kMeSecret.begin(), kMeSecret.end());
  cfg.server = kMeServer;
  cfg.local = kMeLocal;
  cfg.advertised = kMeAdvertised;
  cfg.ad_tag.bytes = kAdTag;
  cfg.max_frame = max_frame;
  // Pinned process identity so the handshake known-answer vectors are exact.
  cfg.process_id = kMeProcessId;
  cfg.process_time = kMeProcessTime;
  cfg.random = [](std::span<std::uint8_t> out) {
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(i);
  };
  cfg.clock = [] { return kNow; };
  return cfg;
}

// Nonce response used by the handshake tests: server nonce a0..af, same timestamp.
Bytes nonce_answer() {
  Bytes n(16);
  for (int i = 0; i < 16; ++i) n[i] = static_cast<std::uint8_t>(0xa0 + i);
  return me_plain_frame(-2, cat({from_hex("aa87cb7a"), Bytes(kMeSecret.begin(), kMeSecret.begin() + 4),
                                 le32(1), le32(1600000000), n}));
}

// Independent ME fixtures generated by a Python hashlib/cryptography script for
// this exact KDF input (nonce_server a0..af, nonce_client 00..0f, ts 1600000000,
// ME secret 00..1f, server 149.154.175.50:8888, local 203.0.113.9:54321).
// The handshake request/answer are already AES-CBC encrypted; this is the
// reference behavior after RPC_NONCE (rpc_start_crypto precedes RPC_HANDSHAKE).
constexpr std::string_view kMeWriteKey = "3c570bb28a07c6d2e625251af0fdb92a394409e252cc1ca1f434e3e20eb7958c";
constexpr std::string_view kMeWriteIv  = "0a3897c0664be4972963954ba2284efe";
constexpr std::string_view kMeReadKey  = "1a0873e6e697bb4dee5d998b9aeb5852950c9238687cbfde5dd34a03f9590e2d";
constexpr std::string_view kMeReadIv   = "dc756fa62f214e6b097c1a60223621d3";
// Regenerated independently (Python cryptography AES-256-CBC + zlib.crc32,
// tools/regen_handshake_vectors.py) after the request started advertising
// RPC_HANDSHAKE flag USE_CRC32C (0x800). KDF inputs are unchanged, so the keys
// above still apply. kHandshakeAnswerEnc stays on flags=0 (IEEE CRC-32 stream);
// kHandshakeAnswerCrc32cEnc is the same answer with flags=0x800 (CRC-32C after
// the handshake).
constexpr std::string_view kHandshakeRequestEnc =
    "31b5fbbdccde7099a3b4dbf0b5d4dbf953c10bea1dbde9cfee28bfadc472ebae"
    "783f829d71af0e50ba989f30c043a5fa";
constexpr std::string_view kHandshakeAnswerEnc =
    "ca56a51dead27a7ec16e658762b13591dfd6e87a9bcae4d3896b8f8fae573601"
    "f339b98bfa546aff74a6a4ad662d08d6";
constexpr std::string_view kHandshakeAnswerCrc32cEnc =
    "1323823d292aab7797c9030c87181db70ddc4aabcf56c44126290742fa760c46"
    "47cd2591b492c2477d139730fe9f1966";

Bytes handshake_request_plain() {
  return me_plain_frame(-1, cat({from_hex("f5ee8276"), le32(0x800),
                                 Bytes(kExpectedSenderPid.begin(), kExpectedSenderPid.end()),
                                 Bytes({50, 175, 154, 149, 0xb8, 0x22, 0, 0, 0, 0, 0, 0})}));
}

Bytes handshake_answer_payload(std::uint32_t flags = 0) {
  return cat({from_hex("f5ee8276"), le32(flags),
              Bytes(kMeServerPid.begin(), kMeServerPid.end()),
              Bytes(kExpectedSenderPid.begin(), kExpectedSenderPid.end())});
}

Bytes handshake_answer_plain() {
  return me_plain_frame(-1, handshake_answer_payload());
}

struct ReadyMe {
  std::unique_ptr<MiddleEndSession> session;
  Bytes handshake_request_enc;
  Bytes handshake_answer_enc;
  std::unique_ptr<crypto::AesCbc> read_enc;   // peer -> proxy, after handshake answer
  std::unique_ptr<crypto::AesCbc> write_dec;  // proxy -> peer, after handshake request
};

A16 last_block(std::span<const std::uint8_t> b) {
  A16 out{};
  std::copy(b.end() - 16, b.end(), out.begin());
  return out;
}

MiddleProxyKeys keys();

// `echo_sent_pid` builds an answer that echoes whatever sender_pid the session
// under test actually produced (like a real ME), instead of the fixed golden
// fixture. Needed whenever the configuration changes the process identity.
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

ReadyMe make_ready_config(MiddleEndConfig cfg, bool echo_sent_pid = false,
                          std::uint32_t answer_flags = 0) {
  auto k = keys_for(cfg);
  auto session = std::make_unique<MiddleEndSession>(std::move(cfg),
                                                   std::make_unique<TestSink>());
  ReadyMe out;
  out.session = std::move(session);
  EXPECT_EQ(out.session->start().size(), 44u);

  std::vector<std::uint8_t> to_me;
  EXPECT_EQ(out.session->feed(nonce_answer(), to_me), Status::Ok);
  out.handshake_request_enc = to_me;
  EXPECT_EQ(out.handshake_request_enc.size(), 48u);

  if (echo_sent_pid) {
    crypto::AesCbc request_dec(k.write_key, k.write_iv);
    Bytes request = out.handshake_request_enc;
    request_dec.decrypt(request);
    Bytes payload = cat({from_hex("f5ee8276"), le32(answer_flags),
                         Bytes(kMeServerPid.begin(), kMeServerPid.end()),
                         Bytes(request.begin() + 16, request.begin() + 28)});
    crypto::AesCbc answer_enc(k.read_key, k.read_iv);
    out.handshake_answer_enc = me_encrypted_frame(answer_enc, -1, payload);
  } else {
    out.handshake_answer_enc = from_hex(kHandshakeAnswerEnc);
  }
  to_me.clear();
  EXPECT_EQ(out.session->feed(out.handshake_answer_enc, to_me), Status::Ok);
  EXPECT_TRUE(out.session->ready());

  out.read_enc = std::make_unique<crypto::AesCbc>(k.read_key, last_block(out.handshake_answer_enc));
  out.write_dec = std::make_unique<crypto::AesCbc>(k.write_key, last_block(out.handshake_request_enc));
  return out;
}

ReadyMe make_ready(std::size_t max_frame = 1u << 20) {
  return make_ready_config(me_config(max_frame));
}

MiddleProxyKeys keys() { return keys_for(me_config()); }

}  // namespace

TEST(MiddleEnd, NonceRequestGolden) {
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  auto start = s.start();
  ASSERT_EQ(start.size(), 44u);
  EXPECT_EQ(rd32(start, 0), 44u);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(start, 4)), -2);
  auto payload = std::span<const std::uint8_t>(start).subspan(8, 32);
  EXPECT_EQ(rd32(payload, 0), 0x7acb87aau);
  expect_bytes(std::span<const std::uint8_t>(payload).subspan(4, 4),
               std::span<const std::uint8_t>(kMeSecret).first(4));
  EXPECT_EQ(rd32(payload, 8), 1u);
  EXPECT_EQ(rd32(payload, 12), 1600000000u);
  std::array<std::uint8_t, 16> nonce{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  expect_bytes(std::span<const std::uint8_t>(payload).subspan(16, 16), nonce);
  EXPECT_EQ(rd32(start, 40), crypto::crc32(std::span<const std::uint8_t>(start).first(40)));
  EXPECT_EQ(s.state(), MiddleEndSession::State::Nonce);
}

TEST(MiddleEnd, HandshakeEncryptedKnownAnswerAndSplits) {
  auto k = keys();
  EXPECT_EQ(k.write_key, arr<32>(from_hex(kMeWriteKey)));
  EXPECT_EQ(k.write_iv, arr<16>(from_hex(kMeWriteIv)));
  EXPECT_EQ(k.read_key, arr<32>(from_hex(kMeReadKey)));
  EXPECT_EQ(k.read_iv, arr<16>(from_hex(kMeReadIv)));

  auto hreq = from_hex(kHandshakeRequestEnc);
  auto hans = from_hex(kHandshakeAnswerEnc);
  {
    crypto::AesCbc dec(k.write_key, k.write_iv);
    Bytes p = hreq;
    dec.decrypt(p);
    EXPECT_EQ(p, cat({handshake_request_plain(), from_hex("04000000")}));
  }
  {
    crypto::AesCbc dec(k.read_key, k.read_iv);
    Bytes p = hans;
    dec.decrypt(p);
    EXPECT_EQ(p, cat({handshake_answer_plain(), from_hex("04000000")}));
  }

  auto nonce = nonce_answer();
  for (std::size_t split = 1; split < nonce.size(); ++split) {
    MiddleEndSession s(me_config(), std::make_unique<TestSink>());
    s.start();
    std::vector<std::uint8_t> to_me;
    EXPECT_EQ(s.feed(std::span<const std::uint8_t>(nonce).first(split), to_me), Status::NeedMoreData);
    EXPECT_EQ(s.feed(std::span<const std::uint8_t>(nonce).subspan(split), to_me), Status::Ok);
    EXPECT_EQ(s.state(), MiddleEndSession::State::Handshake);
    // The handshake request must be the exact independently generated ciphertext.
    EXPECT_EQ(to_me, hreq) << "split=" << split;
  }

  for (std::size_t split = 1; split < hans.size(); ++split) {
    MiddleEndSession s(me_config(), std::make_unique<TestSink>());
    s.start();
    std::vector<std::uint8_t> to_me;
    ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
    auto st = s.feed(std::span<const std::uint8_t>(hans).first(split), to_me);
    EXPECT_TRUE(st == Status::NeedMoreData || st == Status::Ok) << "split=" << split;
    st = s.feed(std::span<const std::uint8_t>(hans).subspan(split), to_me);
    EXPECT_EQ(st, Status::Ok) << "split=" << split;
    EXPECT_TRUE(s.ready()) << "split=" << split;
  }

  // Byte-at-a-time handshake answer.
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  for (std::size_t i = 0; i < hans.size(); ++i) {
    auto st = s.feed(std::span<const std::uint8_t>(hans).subspan(i, 1), to_me);
    EXPECT_NE(st, Status::ProtocolError);
  }
  EXPECT_TRUE(s.ready());
}

// The handshake must identify this process with real process_id fields:
// reversed IPv4 octets and the outbound KDF socket port (reference implementation handshake.rs
// uses client_addr_for_kdf for sender_pid; our_addr is a separate field), plus
// pid16/utime32. peer_pid is the ME endpoint with wildcard pid/time. The old
// value was twelve ASCII 'IPIPPRPDTIME' bytes twice.
TEST(MiddleEnd, HandshakeProcessIdFieldsAreSourceReal) {
  auto r = make_ready();
  auto k = keys();
  crypto::AesCbc dec(k.write_key, k.write_iv);
  Bytes p = r.handshake_request_enc;
  dec.decrypt(p);
  ASSERT_EQ(p.size(), 48u);
  EXPECT_EQ(rd32(p, 0), 44u);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(p, 4)), -1);
  auto payload = std::span<const std::uint8_t>(p).subspan(8, 32);
  EXPECT_EQ(rd32(payload, 0), 0x7682eef5u);  // RPC_HANDSHAKE
  EXPECT_EQ(rd32(payload, 4), 0x800u);       // USE_CRC32C advertised

  Bytes sender(payload.begin() + 8, payload.begin() + 20);
  Bytes peer(payload.begin() + 20, payload.begin() + 32);
  expect_bytes(sender, kExpectedSenderPid);
  EXPECT_EQ(rd32(payload, 12) & 0xffffu, kMeLocal.port);   // outbound KDF port
  EXPECT_EQ(rd32(payload, 12) >> 16, kMeProcessId);        // real pid16
  EXPECT_EQ(rd32(payload, 16), kMeProcessTime);            // utime32
  EXPECT_NE(rd32(payload, 12) & 0xffffu, kMeAdvertised.port); // not the listener
  EXPECT_EQ(peer[0], 50);                                  // ME server IPv4, reversed
  EXPECT_EQ(peer[1], 175);
  EXPECT_EQ(peer[2], 154);
  EXPECT_EQ(peer[3], 149);
  EXPECT_EQ(rd32(payload, 24) & 0xffffu, 8888u);           // ME port
  EXPECT_EQ(rd32(payload, 24) >> 16, 0u);                  // wildcard pid
  EXPECT_EQ(rd32(payload, 28), 0u);                        // wildcard utime

  const Bytes placeholder(kPlaceholderPid.begin(), kPlaceholderPid.end());
  EXPECT_NE(sender, placeholder);
  EXPECT_NE(peer, placeholder);
}

// A second hand-written reference vector: 192.0.2.77 -> [77,2,0,192] and
// 198.51.100.7 -> [7,100,51,198]. Expected bytes come from the documented
// reference rule, not from make_process_id().
TEST(MiddleEnd, ProcessIdIPv4OctetsFollowReferenceOrder) {
  auto cfg = me_config();
  cfg.server = Endpoint::v4({198, 51, 100, 7}, 443);
  cfg.local = Endpoint::v4({192, 0, 2, 77}, 12345);
  cfg.advertised = Endpoint::v4({203, 0, 113, 9}, 443);
  auto r = make_ready_config(std::move(cfg), /*echo_sent_pid=*/true);
  // Decrypt with the keys for this config (nonce/time fixed).
  MiddleProxyKdfInput in;
  in.nonce_server = arr<16>([&] {
    Bytes n(16);
    for (int i = 0; i < 16; ++i) n[i] = static_cast<std::uint8_t>(0xa0 + i);
    return n;
  }());
  in.nonce_client = arr<16>(Bytes{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
  in.client_timestamp = 1600000000;
  in.server = Endpoint::v4({198, 51, 100, 7}, 443);
  in.local = Endpoint::v4({192, 0, 2, 77}, 12345);
  in.secret = kMeSecret;
  auto keys = derive_middle_proxy_keys(in);
  crypto::AesCbc dec(keys.write_key, keys.write_iv);
  Bytes p = r.handshake_request_enc;
  dec.decrypt(p);
  ASSERT_EQ(p.size(), 48u);
  auto payload = std::span<const std::uint8_t>(p).subspan(8, 32);
  const std::array<std::uint8_t, 12> sender{77, 2, 0, 192, 0x39, 0x30,
                                            0x3a, 0x1f, 0x00, 0x10, 0x5e, 0x5f};
  const std::array<std::uint8_t, 12> peer{7, 100, 51, 198, 0xbb, 0x01,
                                          0, 0, 0, 0, 0, 0};
  expect_bytes(std::span<const std::uint8_t>(payload).subspan(8, 12), sender);
  expect_bytes(std::span<const std::uint8_t>(payload).subspan(20, 12), peer);
}

// The ME echoes sender_pid as peer_pid (that is why the placeholder "worked").
// Validation must compare against the bytes actually sent, not a constant.
TEST(MiddleEnd, HandshakePeerPidEchoIsValidated) {
  auto k = keys();
  auto run_answer = [&](const std::array<std::uint8_t, 12>& echo) {
    MiddleEndSession s(me_config(), std::make_unique<TestSink>());
    s.start();
    std::vector<std::uint8_t> to_me;
    EXPECT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
    crypto::AesCbc enc(k.read_key, k.read_iv);
    Bytes payload = cat({from_hex("f5ee8276"), le32(0),
                         Bytes(kMeServerPid.begin(), kMeServerPid.end()),
                         Bytes(echo.begin(), echo.end())});
    const Status status = s.feed(me_encrypted_frame(enc, -1, payload), to_me);
    return std::pair<Status, std::string>{status, std::string(s.error())};
  };

  auto [ok_status, ok_error] = run_answer(kExpectedSenderPid);
  EXPECT_EQ(ok_status, Status::Ok);
  EXPECT_TRUE(ok_error.empty());

  auto [placeholder_status, placeholder_error] = run_answer(kPlaceholderPid);
  EXPECT_EQ(placeholder_status, Status::ProtocolError);
  EXPECT_NE(placeholder_error.find("peer pid echo mismatch"), std::string::npos);

  auto corrupted = kExpectedSenderPid;
  corrupted[9] ^= 0x01;
  auto [bad_status, bad_error] = run_answer(corrupted);
  EXPECT_EQ(bad_status, Status::ProtocolError);
  EXPECT_NE(bad_error.find("peer pid echo mismatch"), std::string::npos);
}

// RPC_HANDSHAKE flag USE_CRC32C (0x800) selects the checksum for every frame
// after the handshake answer. The handshake frames themselves stay on IEEE
// CRC-32 (reference implementation handshake.rs), which is why the golden answer below is a valid
// answer to a CRC32C-advertising request.
TEST(MiddleEnd, HandshakeNegotiatesCrc32cWhenPeerEchoesFlag) {
  const auto k = keys();
  const auto answer = from_hex(kHandshakeAnswerCrc32cEnc);
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  ASSERT_EQ(to_me, from_hex(kHandshakeRequestEnc));
  ASSERT_EQ(s.feed(answer, to_me), Status::Ok);
  ASSERT_TRUE(s.ready());
  ASSERT_EQ(to_me.size(), 48u);  // the answer produced no outbound frame

  const Bytes ans_payload =
      cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
           from_hex("a1a2a3a4")});

  // Same answer over IEEE CRC-32 must be rejected once CRC32C is negotiated.
  {
    MiddleEndSession wrong(me_config(), std::make_unique<TestSink>());
    wrong.start();
    std::vector<std::uint8_t> out;
    ASSERT_EQ(wrong.feed(nonce_answer(), out), Status::Ok);
    ASSERT_EQ(wrong.feed(answer, out), Status::Ok);
    crypto::AesCbc enc(k.read_key, last_block(answer));
    EXPECT_EQ(wrong.feed(me_encrypted_frame(enc, 0, ans_payload), out), Status::ProtocolError);
    EXPECT_NE(std::string(wrong.error()).find("CRC mismatch"), std::string::npos);
  }

  // A Castagnoli frame is accepted; an IEEE frame is rejected.
  {
    MiddleEndSession good(me_config(), std::make_unique<TestSink>());
    good.start();
    std::vector<std::uint8_t> out;
    ASSERT_EQ(good.feed(nonce_answer(), out), Status::Ok);
    ASSERT_EQ(good.feed(answer, out), Status::Ok);
    crypto::AesCbc enc(k.read_key, last_block(answer));
    ASSERT_EQ(good.feed(me_encrypted_frame_crc32c(enc, 0, ans_payload), out), Status::Ok);
    auto* sink = dynamic_cast<TestSink*>(good.sink());
    ASSERT_EQ(sink->data.size(), 1u);
    EXPECT_EQ(sink->data[0].payload, from_hex("a1a2a3a4"));
  }

  // Outbound frames of the negotiating session use CRC32C too.
  Bytes outbound;
  ASSERT_EQ(s.encode_client_message(from_hex("0102030405060708"), kPeer, ProtoTag::Secure,
                                   false, outbound),
            Status::Ok);
  crypto::AesCbc write_dec(k.write_key, last_block(from_hex(kHandshakeRequestEnc)));
  write_dec.decrypt(outbound);
  const std::uint32_t len = rd32(outbound);
  ASSERT_LE(static_cast<std::size_t>(len) + 4, outbound.size());
  EXPECT_EQ(rd32(outbound, len - 4),
            me_test_crc32c(std::span<const std::uint8_t>(outbound).first(len - 4)));
  EXPECT_NE(rd32(outbound, len - 4),
            crypto::crc32(std::span<const std::uint8_t>(outbound).first(len - 4)));
}

// A flags=0 answer keeps the default IEEE CRC-32 stream: the old golden answer
// is used by make_ready(), and a Castagnoli frame must be rejected there.
TEST(MiddleEnd, HandshakeWithoutFlagKeepsIeeeCrc32) {
  const auto k = keys();
  auto r = make_ready();
  const Bytes ans_payload =
      cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
           from_hex("b1b2b3b4")});
  auto check = [&](std::span<const std::uint8_t> frame) {
    std::vector<std::uint8_t> out;
    return r.session->feed(frame, out);
  };
  EXPECT_EQ(check(me_encrypted_frame_crc32c(*r.read_enc, 0, ans_payload)), Status::ProtocolError);
  EXPECT_NE(std::string(r.session->error()).find("CRC mismatch"), std::string::npos);
}

// Only the low byte of the RPC_HANDSHAKE answer flags is semantically ours
// (reference implementation: `if hs_flags & 0xff != 0 { fail }`); a nonzero low byte is rejected.
TEST(MiddleEnd, HandshakeRejectsUnknownLowByteFlags) {
  const auto k = keys();
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  crypto::AesCbc enc(k.read_key, k.read_iv);
  const Bytes payload =
      cat({from_hex("f5ee8276"), le32(0x01),
           Bytes(kMeServerPid.begin(), kMeServerPid.end()),
           Bytes(kExpectedSenderPid.begin(), kExpectedSenderPid.end())});
  EXPECT_EQ(s.feed(me_encrypted_frame(enc, -1, payload), to_me), Status::ProtocolError);
  EXPECT_NE(std::string(s.error()).find("flags unsupported"), std::string::npos);
  EXPECT_EQ(s.handshake_flags(), 0x01u);
  EXPECT_EQ(s.state(), MiddleEndSession::State::Failed);
}

// Unknown HIGH flag bits are ignored (reference implementation-compatible) instead of tearing down
// the shared ME transport, and are observable through handshake_flags() and the
// control counter. 0x1000 alone does not select CRC32C: the stream stays IEEE.
TEST(MiddleEnd, HandshakeIgnoresUnknownHighFlagAndKeepsIeeeCrc32) {
  auto r = make_ready_config(me_config(), /*echo_sent_pid=*/true, /*answer_flags=*/0x1000);
  ASSERT_TRUE(r.session->ready());
  EXPECT_EQ(r.session->handshake_flags(), 0x1000u);
  EXPECT_EQ(r.session->control_counters().handshake_unknown_flags, 1u);

  const Bytes ans_payload =
      cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
           from_hex("c1c2c3c4")});
  std::vector<std::uint8_t> out;
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 0, ans_payload), out), Status::Ok);
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_EQ(sink->data.size(), 1u);
  EXPECT_EQ(sink->data[0].payload, from_hex("c1c2c3c4"));

  // A Castagnoli frame must still be rejected: no CRC32C was negotiated.
  auto wrong = make_ready_config(me_config(), /*echo_sent_pid=*/true, /*answer_flags=*/0x1000);
  ASSERT_TRUE(wrong.session->ready());
  std::vector<std::uint8_t> wrong_out;
  EXPECT_EQ(wrong.session->feed(me_encrypted_frame_crc32c(*wrong.read_enc, 0, ans_payload),
                                wrong_out),
            Status::ProtocolError);
  EXPECT_NE(std::string(wrong.session->error()).find("CRC mismatch"), std::string::npos);
}

// 0x800 | 0x1000: the known bit still selects CRC32C, the unknown high bit is
// only counted.
TEST(MiddleEnd, HandshakeUnknownHighFlagWithCrc32cSelectsCrc32c) {
  auto r = make_ready_config(me_config(), /*echo_sent_pid=*/true, /*answer_flags=*/0x1800);
  ASSERT_TRUE(r.session->ready());
  EXPECT_EQ(r.session->handshake_flags(), 0x1800u);
  EXPECT_EQ(r.session->control_counters().handshake_unknown_flags, 1u);

  const Bytes ans_payload =
      cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
           from_hex("d1d2d3d4")});
  std::vector<std::uint8_t> out;
  ASSERT_EQ(r.session->feed(me_encrypted_frame_crc32c(*r.read_enc, 0, ans_payload), out),
            Status::Ok);
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_EQ(sink->data.size(), 1u);
  EXPECT_EQ(sink->data[0].payload, from_hex("d1d2d3d4"));

  auto wrong = make_ready_config(me_config(), /*echo_sent_pid=*/true, /*answer_flags=*/0x1800);
  ASSERT_TRUE(wrong.session->ready());
  std::vector<std::uint8_t> wrong_out;
  EXPECT_EQ(wrong.session->feed(me_encrypted_frame(*wrong.read_enc, 0, ans_payload), wrong_out),
            Status::ProtocolError);
  EXPECT_NE(std::string(wrong.session->error()).find("CRC mismatch"), std::string::npos);
}

TEST(MiddleEnd, HandshakeRejectionCodeIsSurfaced) {
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  auto k = keys();
  crypto::AesCbc enc(k.read_key, k.read_iv);
  Bytes payload = cat({from_hex("dabe276a"), le32(static_cast<std::uint32_t>(-6))});
  EXPECT_EQ(s.feed(me_encrypted_frame(enc, -1, payload), to_me), Status::ProtocolError);
  EXPECT_NE(std::string(s.error()).find("code -6"), std::string::npos);
  EXPECT_EQ(s.state(), MiddleEndSession::State::Failed);
}

// Unset process fields derive from the real process and the injected clock.
TEST(MiddleEnd, HandshakeProcessIdDefaultsToRealProcess) {
  auto cfg = me_config();
  cfg.process_id = 0;
  cfg.process_time = 0;
  MiddleEndSession s(std::move(cfg), std::make_unique<TestSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  ASSERT_EQ(s.state(), MiddleEndSession::State::Handshake);
  auto k = keys();
  crypto::AesCbc dec(k.write_key, k.write_iv);
  dec.decrypt(to_me);
  ASSERT_EQ(to_me.size(), 48u);
  auto payload = std::span<const std::uint8_t>(to_me).subspan(8, 32);
  EXPECT_EQ(rd32(payload, 12) & 0xffffu, 54321u);
  EXPECT_EQ(rd32(payload, 12) >> 16,
            static_cast<std::uint16_t>(::getpid() & 0xffff));
  EXPECT_EQ(rd32(payload, 16), static_cast<std::uint32_t>(kNow));
}

TEST(MiddleEnd, AdTagExactLayoutAndQuickAckFlag) {
  auto r = make_ready();
  auto k = keys();

  Bytes payload = from_hex("0102030405060708090a0b0c");
  Bytes out;
  ASSERT_EQ(r.session->encode_client_message(payload, kPeer, ProtoTag::Secure, false, out), Status::Ok);
  ASSERT_EQ(out.size() % 16, 0u);

  r.write_dec->decrypt(out);
  std::uint32_t len = rd32(out);
  EXPECT_EQ(len, 12u + 84u + payload.size());
  EXPECT_EQ(static_cast<std::int32_t>(rd32(out, 4)), 0);
  auto p = std::span<const std::uint8_t>(out).subspan(8, len - 12);
  EXPECT_EQ(rd32(p, 0), 0x36cef1eeu);                 // RPC_PROXY_REQ
  EXPECT_EQ(rd32(p, 4), 0x28021008u);                 // MAGIC|EXTMODE2|ADTAG|INTERMEDIATE|PAD
  expect_bytes(std::span<const std::uint8_t>(p).subspan(8, 8), r.session->conn_id());
  auto peer20 = kPeer.wire20();
  auto advertised20 = kMeAdvertised.wire20();
  expect_bytes(std::span<const std::uint8_t>(p).subspan(16, 20), peer20);
  expect_bytes(std::span<const std::uint8_t>(p).subspan(36, 20), advertised20);
  EXPECT_EQ(rd32(p, 56), 24u);
  EXPECT_EQ(rd32(p, 60), 0xdb1e26aeu);               // TL_PROXY_TAG
  EXPECT_EQ(p[64], 16);                               // TL string length
  expect_bytes(std::span<const std::uint8_t>(p).subspan(65, 16), kAdTag);
  expect_bytes(std::span<const std::uint8_t>(p).subspan(56, 28),
               cat({from_hex("18000000ae261edb10"), kAdTag, from_hex("000000")}));
  expect_bytes(std::span<const std::uint8_t>(p).subspan(84), payload);
  for (std::size_t i = len; i < out.size(); i += 4) EXPECT_EQ(rd32(out, i), 4u);
  EXPECT_EQ(rd32(out, len - 4), crypto::crc32(std::span<const std::uint8_t>(out).first(len - 4)));

  // The next frame increments seq and carries the QUICKACK flag when requested.
  Bytes out2;
  ASSERT_EQ(r.session->encode_client_message(payload, kPeer, ProtoTag::Secure, true, out2), Status::Ok);
  r.write_dec->decrypt(out2);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(out2, 4)), 1);
  EXPECT_EQ(rd32(std::span<const std::uint8_t>(out2).subspan(8), 4), 0xa8021008u);
}

TEST(MiddleEnd, LiveAdTagOverrideAppliesToNextRequest) {
  auto r = make_ready();
  const std::array<std::uint8_t, 16> other{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                                           0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0};
  AdTag tag;
  tag.bytes = other;
  r.session->set_ad_tag(tag);
  Bytes payload = from_hex("0102030405060708090a0b0c");
  Bytes out;
  ASSERT_EQ(r.session->encode_client_message(payload, kPeer, ProtoTag::Secure, false, out), Status::Ok);
  r.write_dec->decrypt(out);
  auto p = std::span<const std::uint8_t>(out).subspan(8, rd32(out) - 12);
  expect_bytes(p.subspan(65, 16), other);

  AdTag zero;
  EXPECT_THROW(r.session->set_ad_tag(zero), std::invalid_argument);
  Bytes again;
  ASSERT_EQ(r.session->encode_client_message(payload, kPeer, ProtoTag::Secure, false, again), Status::Ok);
  r.write_dec->decrypt(again);
  expect_bytes(std::span<const std::uint8_t>(again).subspan(8, rd32(again) - 12).subspan(65, 16), other);
}

// RPC_PROXY_REQ carries two distinct 20-byte endpoints: the client's address
// and this proxy's own listener address. The listener port must be the one
// clients connect to; the ME socket's ephemeral source port belongs ONLY to the
// KDF input (`cfg.local`) and must never be advertised.
TEST(MiddleEnd, ProxyReqAdvertisesListenerPortNotKdfSourcePort) {
  auto r = make_ready();
  ASSERT_NE(kMeLocal.port, kMeAdvertised.port);
  Bytes out;
  ASSERT_EQ(r.session->encode_client_message(from_hex("0102030405060708"), kPeer,
                                             ProtoTag::Secure, false, out),
            Status::Ok);
  r.write_dec->decrypt(out);
  const std::uint32_t len = rd32(out);
  auto p = std::span<const std::uint8_t>(out).subspan(8, len - 12);
  expect_bytes(p.subspan(36, 20), kMeAdvertised.wire20());
  EXPECT_EQ(rd32(p, 52), 443u);   // listener port, host byte order
  EXPECT_NE(rd32(p, 52), 54321u); // never the outbound socket's ephemeral port
  // The KDF golden vector above still derives from kMeLocal, proving the
  // advertised endpoint is not part of key derivation.
  EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready);
}

TEST(MiddleEnd, ProxyReqAdvertisedEndpointAddressVariants) {
  struct Case {
    Endpoint advertised;
    const char* name;
  };
  const std::array<Case, 2> cases{{
      {kMeAdvertisedOtherIp, "different IPv4 address"},
      {Endpoint::v6(arr<16>(from_hex("20010db8000000000000000000000042")), 443),
       "native IPv6 listener"},
  }};
  for (const auto& c : cases) {
    auto cfg = me_config();
    cfg.advertised = c.advertised;
    auto r = make_ready_config(std::move(cfg), /*echo_sent_pid=*/true);
    Bytes out;
    ASSERT_EQ(r.session->encode_client_message(from_hex("0102030405060708"), kPeer,
                                               ProtoTag::Secure, false, out),
              Status::Ok)
        << c.name;
    r.write_dec->decrypt(out);
    const std::uint32_t len = rd32(out);
    auto p = std::span<const std::uint8_t>(out).subspan(8, len - 12);
    expect_bytes(p.subspan(36, 20), c.advertised.wire20());
    EXPECT_EQ(rd32(p, 52), c.advertised.port) << c.name;
    EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready) << c.name;
  }
}

TEST(MiddleEnd, RejectsUnalignedAndOversizedOutbound) {
  auto r = make_ready(128);
  Bytes out;
  EXPECT_EQ(r.session->encode_client_message(from_hex("010203"), kPeer, ProtoTag::Secure, false, out),
            Status::ProtocolError);
  EXPECT_EQ(r.session->encode_client_message(Bytes{}, kPeer, ProtoTag::Secure, false, out),
            Status::ProtocolError);
  EXPECT_EQ(r.session->encode_client_message(Bytes(64, 0x42), kPeer, ProtoTag::Secure, false, out),
            Status::ProtocolError);
  EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready);
}

// F1: a payload span pointing INTO to_me must be detached before reserve() can
// reallocate the vector and free that storage (heap-use-after-free otherwise).
// The aliased encode must produce exactly the same bytes as an encode whose
// payload lives in a separate buffer, with the same pre-existing output prefix.
TEST(MiddleEnd, EncodeClientMessageAliasedPayloadMatchesCopy) {
  auto aliased = make_ready();
  auto copied = make_ready();
  const Bytes payload(1024, 0x5a);

  // `to_me` owns the bytes the span will point into. Its capacity equals its
  // size, so reserve(start + padded) is guaranteed to reallocate and invalidate
  // the span unless it was detached first.
  std::vector<std::uint8_t> to_me = payload;
  std::vector<std::uint8_t> reference = payload;
  ASSERT_EQ(to_me.capacity(), payload.size());

  ASSERT_EQ(aliased.session->encode_client_message(
                std::span<const std::uint8_t>(to_me.data(), to_me.size()), kPeer,
                ProtoTag::Secure, false, to_me),
            Status::Ok);
  ASSERT_EQ(copied.session->encode_client_message(payload, kPeer, ProtoTag::Secure, false,
                                                  reference),
            Status::Ok);
  EXPECT_EQ(to_me, reference);
  EXPECT_GT(to_me.size(), payload.size());
}

TEST(MiddleEnd, DemuxProxyAnswerQuickAckCloseKeepsTransport) {
  auto r = make_ready();
  std::array<std::uint8_t, 8> other{9, 9, 9, 9, 9, 9, 9, 9};

  Bytes close_payload = cat({from_hex("a234b65e"), Bytes(kConnId.begin(), kConnId.end())});
  Bytes data_payload = cat({from_hex("0dda0344"), le32(0), Bytes(other.begin(), other.end()),
                            from_hex("deadbeef00112233")});
  Bytes batch = cat({me_encrypted_frame(*r.read_enc, 0, close_payload),
                     me_encrypted_frame(*r.read_enc, 1, data_payload)});
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(r.session->feed(batch, to_me), Status::Ok);
  EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready);
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_NE(sink, nullptr);
  ASSERT_EQ(sink->closes.size(), 1u);
  EXPECT_EQ(sink->closes[0], kConnId);
  ASSERT_EQ(sink->data.size(), 1u);
  EXPECT_EQ(sink->data[0].conn, other);
  EXPECT_EQ(sink->data[0].payload, from_hex("deadbeef00112233"));

  // Later frames still parse on the same shared transport.
  Bytes later = cat({from_hex("0dda0344"), le32(0), Bytes(other.begin(), other.end()),
                     from_hex("55667788")});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 2, later), to_me), Status::Ok);
  ASSERT_EQ(sink->data.size(), 2u);
  EXPECT_EQ(sink->data[1].payload, from_hex("55667788"));
}

// Telegram may close a logical connection with RPC_CLOSE_CONN as well as
// RPC_CLOSE_EXT. Both close exactly one logical connection and are counted;
// a malformed CLOSE_CONN is ignored (counted) instead of killing the transport.
TEST(MiddleEnd, EncodedCloseFrameIsAtomicAndFixedSize) {
  auto r = make_ready();
  const std::int32_t before = r.session->write_seq();
  Bytes out;
  ASSERT_EQ(r.session->encode_close(kConnId, out), Status::Ok);
  // 4 len + 4 seq + 12 payload + 4 CRC = 24, padded to 32.
  EXPECT_EQ(out.size(), 32u);
  EXPECT_EQ(r.session->write_seq(), before + 1);
  r.write_dec->decrypt(out);
  EXPECT_EQ(rd32(out), 24u);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(out, 4)), before);
  EXPECT_EQ(rd32(out, 8), 0x1fcf425du);
}

// reference implementation accepts body.len() >= 8 (payload >= 12) for the close constructors and
// ignores trailing bytes; only shorter payloads are malformed/fatal.
TEST(MiddleEnd, InboundCloseAcceptsTrailingBytesLikeReference) {
  auto r = make_ready();
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_NE(sink, nullptr);
  std::vector<std::uint8_t> to_me;

  Bytes close_conn = cat({from_hex("5d42cf1f"), Bytes(kConnId.begin(), kConnId.end()),
                          from_hex("aabbccdd")});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 0, close_conn), to_me), Status::Ok);
  EXPECT_TRUE(r.session->ready());
  ASSERT_EQ(sink->closes.size(), 1u);
  EXPECT_EQ(sink->closes[0], kConnId);
  EXPECT_EQ(r.session->control_counters().close_conn, 1u);
  EXPECT_EQ(r.session->control_counters().malformed, 0u);

  std::array<std::uint8_t, 8> other{9, 8, 7, 6, 5, 4, 3, 2};
  Bytes close_ext = cat({from_hex("a234b65e"), Bytes(other.begin(), other.end()),
                         from_hex("0102030405060708")});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 1, close_ext), to_me), Status::Ok);
  EXPECT_TRUE(r.session->ready());
  ASSERT_EQ(sink->closes.size(), 2u);
  EXPECT_EQ(sink->closes[1], other);
  EXPECT_EQ(r.session->control_counters().close_ext, 1u);
  EXPECT_EQ(r.session->control_counters().malformed, 0u);
}

TEST(MiddleEnd, InboundCloseConstructorsAreHandledAndCounted) {
  auto r = make_ready();
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_NE(sink, nullptr);
  std::vector<std::uint8_t> to_me;

  const auto counters = [&] { return r.session->control_counters(); };
  EXPECT_EQ(counters().close_conn, 0u);
  EXPECT_EQ(counters().close_ext, 0u);
  EXPECT_EQ(counters().unknown, 0u);

  // RPC_CLOSE_CONN inbound: logical close only.
  Bytes close_conn = cat({from_hex("5d42cf1f"), Bytes(kConnId.begin(), kConnId.end())});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 0, close_conn), to_me), Status::Ok);
  EXPECT_TRUE(r.session->ready());
  ASSERT_EQ(sink->closes.size(), 1u);
  EXPECT_EQ(sink->closes[0], kConnId);
  EXPECT_EQ(counters().close_conn, 1u);
  EXPECT_EQ(counters().malformed, 0u);

  // Malformed CLOSE_CONN (8-byte body): counted, ignored, transport survives.
  Bytes short_close = cat({from_hex("5d42cf1f"), from_hex("01020304")});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 1, short_close), to_me), Status::Ok);
  EXPECT_TRUE(r.session->ready());
  EXPECT_EQ(sink->closes.size(), 1u);
  EXPECT_EQ(counters().malformed, 1u);
  EXPECT_EQ(counters().close_conn, 1u);

  // Unknown constructor: counted, ignored, transport survives.
  Bytes unknown_ctor = cat({from_hex("78563412"), from_hex("01020304")});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 2, unknown_ctor), to_me), Status::Ok);
  EXPECT_TRUE(r.session->ready());
  EXPECT_EQ(counters().unknown, 1u);

  // RPC_CLOSE_EXT keeps its previous behaviour and is counted separately.
  std::array<std::uint8_t, 8> other{7, 7, 7, 7, 7, 7, 7, 7};
  Bytes close_ext = cat({from_hex("a234b65e"), Bytes(other.begin(), other.end())});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 3, close_ext), to_me), Status::Ok);
  EXPECT_TRUE(r.session->ready());
  ASSERT_EQ(sink->closes.size(), 2u);
  EXPECT_EQ(sink->closes[1], other);
  EXPECT_EQ(counters().close_ext, 1u);

  // A ping/pong exchange must not perturb control counters.
  Bytes ping = cat({le32(0x5730a2df), from_hex("8877665544332211")});
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 4, ping), to_me), Status::Ok);
  EXPECT_EQ(counters().close_conn, 1u);
  EXPECT_EQ(counters().close_ext, 1u);
  EXPECT_EQ(counters().unknown, 1u);
  EXPECT_EQ(counters().malformed, 1u);
  EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready);
}

TEST(MiddleEnd, ClosePingAndPongFrames) {
  auto r = make_ready();
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_NE(sink, nullptr);

  Bytes out;
  ASSERT_EQ(r.session->encode_close(kConnId, out), Status::Ok);
  r.write_dec->decrypt(out);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(out, 4)), 0);
  auto close_payload = std::span<const std::uint8_t>(out).subspan(8, rd32(out) - 12);
  EXPECT_EQ(rd32(close_payload, 0), 0x1fcf425du);  // RPC_CLOSE_CONN, not CLOSE_EXT
  expect_bytes(close_payload.subspan(4, 8), kConnId);

  out.clear();
  ASSERT_EQ(r.session->encode_ping(0x1122334455667788, out), Status::Ok);
  r.write_dec->decrypt(out);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(out, 4)), 1);
  auto ping_payload = std::span<const std::uint8_t>(out).subspan(8, rd32(out) - 12);
  EXPECT_EQ(rd32(ping_payload, 0), 0x5730a2dfu);
  std::uint64_t id = 0;
  for (int i = 0; i < 8; ++i) id |= static_cast<std::uint64_t>(ping_payload[4 + i]) << (8 * i);
  EXPECT_EQ(id, 0x1122334455667788ull);

  // Peer RPC_PING gets an automatic encrypted PONG with the same id.
  Bytes ping = cat({le32(0x5730a2df), from_hex("8877665544332211")});
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 0, ping), to_me), Status::Ok);
  ASSERT_FALSE(to_me.empty());
  r.write_dec->decrypt(to_me);
  EXPECT_EQ(static_cast<std::int32_t>(rd32(to_me, 4)), 2);
  auto pong = std::span<const std::uint8_t>(to_me).subspan(8, rd32(to_me) - 12);
  EXPECT_EQ(rd32(pong, 0), 0x8430eaa7u);
  expect_bytes(pong.subspan(4, 8), from_hex("8877665544332211"));
  EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready);
  EXPECT_TRUE(sink->closes.empty());
}

// Intersection of the CRC32C negotiation (proto) and the active keepalive
// (melife): once the peer echoed USE_CRC32C, both the outbound RPC_PING and the
// inbound RPC_PONG must use Castagnoli, the ping frame must stay 32 wire bytes
// (12-byte payload + 12-byte header/CRC, padded to 16), and the echoed id must
// reach Sink::on_pong.
TEST(MiddleEnd, PingAndPongUseNegotiatedCrc32c) {
  auto r = make_ready_config(me_config(), /*echo_sent_pid=*/true, 0x800);
  ASSERT_TRUE(r.session->ready());
  EXPECT_EQ(r.session->handshake_flags(), 0x800u);
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_NE(sink, nullptr);

  Bytes out;
  ASSERT_EQ(r.session->encode_ping(0x0102030405060708, out), Status::Ok);
  // Wire size is the declared frame length (payload + 12) padded to the CBC
  // block size: 24 -> 32. kEncodedPingFrameBytes must keep matching this.
  EXPECT_EQ(out.size(), 32u);
  r.write_dec->decrypt(out);
  EXPECT_EQ(rd32(out, 0), 24u);
  EXPECT_EQ(rd32(out, 20), me_test_crc32c(std::span<const std::uint8_t>(out).first(20)));
  // The IEEE CRC-32 of the same bytes must NOT be what was sent.
  EXPECT_NE(rd32(out, 20), crypto::crc32(std::span<const std::uint8_t>(out).first(20)));
  const auto ping_payload = std::span<const std::uint8_t>(out).subspan(8, 12);
  EXPECT_EQ(rd32(ping_payload, 0), 0x5730a2dfu);

  Bytes pong = cat({le32(0x8430eaa7), from_hex("8877665544332211")});
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(r.session->feed(me_encrypted_frame_crc32c(*r.read_enc, 0, pong), to_me),
            Status::Ok);
  ASSERT_EQ(sink->pongs.size(), 1u);
  EXPECT_EQ(sink->pongs[0], static_cast<std::int64_t>(0x1122334455667788ull));
  EXPECT_TRUE(r.session->ready());

  // An IEEE-checksummed PONG is rejected in the negotiated mode, proving the
  // parser really switched and did not silently accept both.
  auto rel = make_ready_config(me_config(), /*echo_sent_pid=*/true, 0x800);
  std::vector<std::uint8_t> ignored;
  EXPECT_EQ(rel.session->feed(me_encrypted_frame(*rel.read_enc, 0, pong), ignored),
            Status::ProtocolError);
}

TEST(MiddleEnd, DemuxFragmentedEverySplitPoint) {
  auto ans_payload = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
                          from_hex("0102030405060708")});

  for (std::size_t split = 1; split < 48; ++split) {
    auto rr = make_ready();
    Bytes w = me_encrypted_frame(*rr.read_enc, 0, ans_payload);
    ASSERT_EQ(w.size(), 48u);
    std::vector<std::uint8_t> to_me;
    auto st = rr.session->feed(std::span<const std::uint8_t>(w).first(split), to_me);
    EXPECT_TRUE(st == Status::NeedMoreData || st == Status::Ok) << "split=" << split;
    st = rr.session->feed(std::span<const std::uint8_t>(w).subspan(split), to_me);
    EXPECT_EQ(st, Status::Ok) << "split=" << split;
    auto* snk = dynamic_cast<TestSink*>(rr.session->sink());
    ASSERT_EQ(snk->data.size(), 1u) << "split=" << split;
    EXPECT_EQ(snk->data[0].payload, from_hex("0102030405060708")) << "split=" << split;
  }
}

TEST(MiddleEnd, BadCrcBadSeqBadLengthFailClosed) {
  {
    auto r = make_ready();
    Bytes payload = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()), from_hex("01020304")});
    Bytes wire = me_encrypted_frame(*r.read_enc, 0, payload);
    wire[12] ^= 0x01;
    std::vector<std::uint8_t> to_me;
    EXPECT_EQ(r.session->feed(wire, to_me), Status::ProtocolError);
    EXPECT_EQ(r.session->state(), MiddleEndSession::State::Failed);
  }
  {
    auto r = make_ready();
    Bytes payload = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()), from_hex("01020304")});
    Bytes wire = me_encrypted_frame(*r.read_enc, 7, payload);
    std::vector<std::uint8_t> to_me;
    EXPECT_EQ(r.session->feed(wire, to_me), Status::ProtocolError);
    EXPECT_EQ(r.session->state(), MiddleEndSession::State::Failed);
  }
  {
    auto r = make_ready(64);
    Bytes payload(64, 0x42);
    Bytes wire = me_encrypted_frame(*r.read_enc, 0, payload);
    std::vector<std::uint8_t> to_me;
    EXPECT_EQ(r.session->feed(wire, to_me), Status::ProtocolError);
  }
  {
    MiddleEndSession s(me_config(), std::make_unique<TestSink>());
    s.start();
    Bytes bad = nonce_answer();
    bad[8] = 0x00;  // wrong RPC type, CRC still valid
    std::vector<std::uint8_t> to_me;
    EXPECT_EQ(s.feed(bad, to_me), Status::ProtocolError);
    EXPECT_EQ(s.state(), MiddleEndSession::State::Failed);
  }
}

TEST(MiddleEnd, NonceAndHandshakeAnswerPipelined) {
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  s.start();
  auto k = keys();
  crypto::AesCbc enc(k.read_key, k.read_iv);
  Bytes hans = me_encrypted_frame(enc, -1, handshake_answer_payload());
  Bytes combined = cat({nonce_answer(), hans});
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(combined, to_me), Status::Ok);
  EXPECT_EQ(s.state(), MiddleEndSession::State::Ready);
  EXPECT_EQ(to_me, from_hex(kHandshakeRequestEnc));
}

TEST(MiddleEnd, PipelinedHandshakeAnswerAndEncryptedFrame) {
  MiddleEndSession s(me_config(), std::make_unique<TestSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  ASSERT_EQ(s.state(), MiddleEndSession::State::Handshake);
  auto k = keys();
  crypto::AesCbc enc(k.read_key, k.read_iv);
  Bytes hans_payload = handshake_answer_payload();
  Bytes ans_payload = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
                           from_hex("11223344")});
  Bytes combined = cat({me_encrypted_frame(enc, -1, hans_payload),
                        me_encrypted_frame(enc, 0, ans_payload)});
  ASSERT_EQ(s.feed(combined, to_me), Status::Ok);
  ASSERT_EQ(s.state(), MiddleEndSession::State::Ready);
  auto* sink = dynamic_cast<TestSink*>(s.sink());
  ASSERT_EQ(sink->data.size(), 1u);
  EXPECT_EQ(sink->data[0].payload, from_hex("11223344"));
}

TEST(MiddleEnd, RetainedBytesReleaseAfterDrain) {
  auto r = make_ready(300000);
  Bytes data(100000, 0x5a);
  Bytes ans = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()), data});
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(r.session->feed(me_encrypted_frame(*r.read_enc, 0, ans), to_me), Status::Ok);
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_EQ(sink->data.size(), 1u);
  EXPECT_EQ(sink->data[0].payload.size(), data.size());
  EXPECT_LT(r.session->retained_bytes(), 70u * 1024u);

  TransportDecoder dec({ProtoTag::Secure, 200000});
  Bytes big(100000, 0x42);
  std::vector<TransportDecoder::Message> msgs;
  ASSERT_EQ(dec.feed(cat({le32(static_cast<std::uint32_t>(big.size())), big}), msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_LT(dec.retained_bytes(), 70u * 1024u);
}

TEST(MiddleEnd, NearMaxFrameTailPlusNextFrameBatch) {
  auto r = make_ready(4096);
  Bytes big(4068, 0x11);  // RPC_PROXY_ANS payload 16 + 4068 = 4084; frame = 4096
  Bytes batch = me_encrypted_frame(*r.read_enc, 0,
                                   cat({from_hex("0dda0344"), le32(0),
                                        Bytes(kConnId.begin(), kConnId.end()), big}));
  for (int i = 0; i < 6; ++i) {
    Bytes small = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
                       from_hex("01020304")});
    batch = cat({batch, me_encrypted_frame(*r.read_enc, 1 + i, small)});
  }
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(r.session->feed(batch, to_me), Status::Ok);
  EXPECT_EQ(r.session->state(), MiddleEndSession::State::Ready);
  auto* sink = dynamic_cast<TestSink*>(r.session->sink());
  ASSERT_EQ(sink->data.size(), 7u);
  EXPECT_EQ(sink->data[0].payload.size(), 4068u);
}

TEST(MiddleEnd, SinkExceptionFailsTerminal) {
  MiddleEndSession s(me_config(), std::make_unique<ThrowingSink>());
  s.start();
  std::vector<std::uint8_t> to_me;
  ASSERT_EQ(s.feed(nonce_answer(), to_me), Status::Ok);
  ASSERT_EQ(s.feed(from_hex(kHandshakeAnswerEnc), to_me), Status::Ok);
  ASSERT_TRUE(s.ready());
  auto k = keys();
  crypto::AesCbc enc(k.read_key, last_block(from_hex(kHandshakeAnswerEnc)));
  Bytes ans = cat({from_hex("0dda0344"), le32(0), Bytes(kConnId.begin(), kConnId.end()),
                   from_hex("01020304")});
  EXPECT_EQ(s.feed(me_encrypted_frame(enc, 0, ans), to_me), Status::ProtocolError);
  EXPECT_EQ(s.state(), MiddleEndSession::State::Failed);
  EXPECT_NE(std::string(s.error()).find("sink threw"), std::string::npos);
  EXPECT_EQ(s.feed(Bytes{}, to_me), Status::ProtocolError);
}

TEST(MiddleEnd, ConfigValidation) {
  auto cfg = me_config();
  cfg.secret.clear();
  EXPECT_THROW(MiddleEndSession(cfg, std::make_unique<TestSink>()), std::invalid_argument);
  cfg = me_config();
  cfg.random = nullptr;
  EXPECT_THROW(MiddleEndSession(cfg, std::make_unique<TestSink>()), std::invalid_argument);
  cfg = me_config();
  cfg.server = Endpoint::v6(std::array<std::uint8_t, 16>{}, 8888);
  EXPECT_THROW(MiddleEndSession(cfg, std::make_unique<TestSink>()), std::invalid_argument);
  cfg = me_config();
  cfg.ad_tag.bytes.fill(0);
  EXPECT_THROW(MiddleEndSession(cfg, std::make_unique<TestSink>()), std::invalid_argument);
  // The advertised listener endpoint is mandatory and must carry a real port;
  // silently falling back to the KDF socket port would reintroduce the defect.
  cfg = me_config();
  cfg.advertised.port = 0;
  EXPECT_THROW(MiddleEndSession(cfg, std::make_unique<TestSink>()), std::invalid_argument);
}

}  // namespace mtdd::protocol

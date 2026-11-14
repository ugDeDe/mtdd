// Shape of the FakeTLS ServerHello flight: the ApplicationData record after
// ServerHello + CCS takes the length measured from the real tls_domain (or a
// random fallback length, never one constant), and the X25519 key share is a
// real X25519 public key. The official client must keep accepting it.
#include "../support/protocol_fixture.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <set>

namespace mtdd::protocol {

namespace {

constexpr std::size_t kOldConstant = 2878;

Bytes classical_hello() { return make_client_hello(kSecret, static_cast<std::uint32_t>(kNow)); }
Bytes pq_hello() {
  return make_client_hello(kSecret, static_cast<std::uint32_t>(kNow), 0x11ec, kPqClientKeyShare);
}

// The response as the official client consumes it (tdlib
// TlsInit::wait_hello_response): one handshake record of any length, then the
// fixed bytes 14 03 03 00 01 01 17 03 03 and one ApplicationData record; the
// HMAC over client_random || response (server random zeroed) must equal the
// server random. Returns the ApplicationData body length, or nullopt when the
// client would reject the response or leave bytes unconsumed.
std::optional<std::size_t> client_accepts(const Bytes& hello, const Bytes& response) {
  std::size_t pos = 0;
  if (response.size() < 5 || response[0] != 0x16 || response[1] != 0x03 || response[2] != 0x03) {
    return std::nullopt;
  }
  pos = 5 + rd16be(response, 3);
  static constexpr std::uint8_t kPrefix[9] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03};
  if (response.size() < pos + 11 || !std::equal(kPrefix, kPrefix + 9, response.begin() + static_cast<std::ptrdiff_t>(pos))) {
    return std::nullopt;
  }
  const std::size_t body = rd16be(response, pos + 9);
  pos += 11 + body;
  if (pos != response.size()) return std::nullopt;
  Bytes zeroed = response;
  std::fill(zeroed.begin() + 11, zeroed.begin() + 43, 0);
  const auto expect = crypto::hmac_sha256(
      kSecret, cat({std::span<const std::uint8_t>(hello).subspan(11, 32), std::span<const std::uint8_t>(zeroed)}));
  if (!std::equal(expect.begin(), expect.end(), response.begin() + 11)) return std::nullopt;
  return body;
}

Bytes hello_response(const Bytes& hello, const RandomFn& random, const ServerHelloOptions& options = {}) {
  ClientHelloInfo info;
  EXPECT_EQ(validate_client_hello(hello, kSecret, kNow, 120, info), HelloStatus::Ok);
  return build_server_hello(info, random, options);
}

// The X25519 share: the whole classical share, the last 32 bytes of the PQ one.
A32 x25519_share(const Bytes& response) {
  const bool pq = rd16be(response, 91) == 0x11ec;
  const std::size_t offset = pq ? 95 + kPqServerKeyShare - 32 : 95;
  A32 out{};
  std::copy_n(response.begin() + static_cast<std::ptrdiff_t>(offset), 32, out.begin());
  return out;
}

// What an observer can check without any secret: an honest X25519 public key
// is the u-coordinate of a point on Curve25519 itself (u^3 + 486662 u^2 + u is
// a square mod 2^255 - 19), never of a point on the twist, and its unused top
// bit is clear. About half of all random strings fail one of the two.
bool on_curve25519(const A32& share) {
  if (share[31] & 0x80) return false;
  A32 be{};
  std::reverse_copy(share.begin(), share.end(), be.begin());
  std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), &BN_CTX_free);
  BIGNUM* p = nullptr;
  BN_hex2bn(&p, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
  std::unique_ptr<BIGNUM, decltype(&BN_free)> p_owner(p, &BN_free);
  std::unique_ptr<BIGNUM, decltype(&BN_free)> u(BN_bin2bn(be.data(), 32, nullptr), &BN_free);
  std::unique_ptr<BIGNUM, decltype(&BN_free)> t(BN_new(), &BN_free);
  std::unique_ptr<BIGNUM, decltype(&BN_free)> y2(BN_new(), &BN_free);
  // y2 = ((u + A) * u + 1) * u
  BN_set_word(t.get(), 486662);
  BN_mod_add(t.get(), u.get(), t.get(), p, ctx.get());
  BN_mod_mul(t.get(), t.get(), u.get(), p, ctx.get());
  BN_add_word(t.get(), 1);
  BN_mod_mul(y2.get(), t.get(), u.get(), p, ctx.get());
  if (BN_is_zero(y2.get())) return false;  // low-order points: not a public key
  return BN_kronecker(y2.get(), p, ctx.get()) == 1;
}

// A fresh peer derives a shared secret with the share through OpenSSL.
bool derives_with_fresh_peer(const A32& share) {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> server(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, share.data(), share.size()),
      &EVP_PKEY_free);
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> gen(
      EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), &EVP_PKEY_CTX_free);
  EVP_PKEY* raw_peer = nullptr;
  if (!server || !gen || EVP_PKEY_keygen_init(gen.get()) != 1 ||
      EVP_PKEY_keygen(gen.get(), &raw_peer) != 1) {
    return false;
  }
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer(raw_peer, &EVP_PKEY_free);
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> derive(
      EVP_PKEY_CTX_new(peer.get(), nullptr), &EVP_PKEY_CTX_free);
  std::array<std::uint8_t, 32> secret{};
  std::size_t length = secret.size();
  return derive && EVP_PKEY_derive_init(derive.get()) == 1 &&
         EVP_PKEY_derive_set_peer(derive.get(), server.get()) == 1 &&
         EVP_PKEY_derive(derive.get(), secret.data(), &length) == 1 && length == 32;
}

}  // namespace

TEST(ServerHelloShape, ConfiguredLengthIsUsedAndTheClientAcceptsIt) {
  const auto random = system_random();
  for (const bool pq : {false, true}) {
    const Bytes hello = pq ? pq_hello() : classical_hello();
    for (const std::size_t length :
         {kServerFlightMin, std::size_t{1000}, std::size_t{4321}, std::size_t{9000}, kServerFlightMax}) {
      SCOPED_TRACE(testing::Message() << "pq=" << pq << " length=" << length);
      ServerHelloOptions options;
      options.app_data_min = length;
      options.app_data_max = length;
      const Bytes response = hello_response(hello, random, options);
      const auto body = client_accepts(hello, response);
      ASSERT_TRUE(body.has_value()) << "the official client would reject this response";
      EXPECT_EQ(*body, length);
      EXPECT_EQ(response.size(), (pq ? 95 + kPqServerKeyShare : 127) + 6 + 5 + length);
    }
  }
}

TEST(ServerHelloShape, MeasuredRangeIsHonouredAndNeverTheOldConstant) {
  const auto random = system_random();
  ServerHelloOptions options;
  options.app_data_min = 4100;
  options.app_data_max = 4103;
  std::set<std::size_t> seen;
  for (int i = 0; i < 200; ++i) {
    const Bytes hello = (i % 2) ? pq_hello() : classical_hello();
    const auto body = client_accepts(hello, hello_response(hello, random, options));
    ASSERT_TRUE(body.has_value());
    EXPECT_GE(*body, options.app_data_min);
    EXPECT_LE(*body, options.app_data_max);
    seen.insert(*body);
  }
  EXPECT_EQ(seen.size(), 4U) << "every length of the measured range is used";
  EXPECT_EQ(seen.count(kOldConstant), 0U);
}

TEST(ServerHelloShape, OutOfRangeLengthsAreClampedToOneLegalRecord) {
  const auto random = system_random();
  const Bytes hello = classical_hello();
  ServerHelloOptions tiny;
  tiny.app_data_min = 1;
  tiny.app_data_max = 1;
  EXPECT_EQ(client_accepts(hello, hello_response(hello, random, tiny)), kServerFlightMin);
  ServerHelloOptions huge;
  huge.app_data_min = 60000;
  huge.app_data_max = 70000;
  EXPECT_EQ(client_accepts(hello, hello_response(hello, random, huge)), kServerFlightMax);
}

TEST(ServerHelloShape, UnmeasuredFallbackIsADistributionNotAConstant) {
  const auto random = system_random();
  std::set<std::size_t> seen;
  for (int i = 0; i < 200; ++i) {
    const Bytes hello = (i % 2) ? pq_hello() : classical_hello();
    const auto body = client_accepts(hello, hello_response(hello, random));
    ASSERT_TRUE(body.has_value());
    EXPECT_GE(*body, kServerFlightFallbackMin);
    EXPECT_LE(*body, kServerFlightFallbackMax);
    seen.insert(*body);
  }
  EXPECT_GT(seen.size(), 100U) << "200 draws from ~1120 lengths";
}

TEST(ServerHelloShape, X25519ShareIsARealPublicKeyAndNeverRepeats) {
  const auto random = system_random();
  std::set<A32> shares;
  for (int i = 0; i < 64; ++i) {
    const bool pq = (i % 2) != 0;
    SCOPED_TRACE(testing::Message() << "i=" << i << " pq=" << pq);
    const Bytes hello = pq ? pq_hello() : classical_hello();
    const Bytes response = hello_response(hello, random);
    ASSERT_TRUE(client_accepts(hello, response).has_value());
    const A32 share = x25519_share(response);
    EXPECT_TRUE(on_curve25519(share));
    EXPECT_TRUE(derives_with_fresh_peer(share));
    EXPECT_TRUE(shares.insert(share).second) << "key share repeated";
  }
}

TEST(ServerHelloShape, DeterministicSourceDerivesTheShareFromItsPrivateKey) {
  // Without a pre-generated key the private key is the next 32 random bytes.
  CountingRng rng;
  const Bytes response = hello_response(classical_hello(), rng.fn());
  CountingRng same;
  A32 priv{};
  same.fn()(priv);
  EXPECT_EQ(x25519_share(response), crypto::x25519_public_key(priv));
  EXPECT_TRUE(on_curve25519(x25519_share(response)));
}

TEST(ServerHelloShape, PreGeneratedShareIsUsedVerbatimInBothShapes) {
  const auto random = system_random();
  A32 priv{};
  random(priv);
  const A32 pub = crypto::x25519_public_key(priv);
  ServerHelloOptions options;
  options.x25519_public = pub;
  for (const bool pq : {false, true}) {
    const Bytes hello = pq ? pq_hello() : classical_hello();
    const Bytes response = hello_response(hello, random, options);
    ASSERT_TRUE(client_accepts(hello, response).has_value());
    EXPECT_EQ(x25519_share(response), pub) << "pq=" << pq;
    if (pq) {
      EXPECT_EQ(rd16be(response, 93), kPqServerKeyShare);
    } else {
      EXPECT_EQ(rd16be(response, 93), 32);
    }
  }
}

TEST(ServerHelloShape, ConnectionConfigReachesTheResponse) {
  const Bytes hello = classical_hello();
  FakeTlsConnection::Config cfg;
  cfg.secret = kSecret;
  cfg.random = system_random();
  cfg.clock = [] { return kNow; };
  cfg.server_hello.app_data_min = 5000;
  cfg.server_hello.app_data_max = 5000;
  FakeTlsConnection conn(cfg);
  Bytes to_client, plain;
  ASSERT_EQ(conn.feed(hello, to_client, plain), Status::Ok);
  EXPECT_EQ(client_accepts(hello, to_client), std::optional<std::size_t>(5000));
}

// ---------------------------------------------------------------------------
// Mirroring the real server's ServerHello: suite, extension order, group.
// ---------------------------------------------------------------------------

namespace {

// A ClientHello with the given key shares (group, key length) in order and
// the given cipher-suite list, sealed with kSecret at kNow.
Bytes hello_with(std::initializer_list<std::pair<std::uint16_t, std::size_t>> shares,
                 const Bytes& ciphers) {
  Bytes entries;
  for (const auto& [group, length] : shares) {
    entries = cat({entries, be16(group), be16(static_cast<std::uint16_t>(length)), Bytes(length, 0x80)});
  }
  const Bytes key_share = cat({be16(static_cast<std::uint16_t>(entries.size())), entries});
  const Bytes exts = cat({Bytes{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}, Bytes{0x00, 0x33},
                          be16(static_cast<std::uint16_t>(key_share.size())), key_share});
  const Bytes body = cat({Bytes{0x03, 0x03}, Bytes(32, 0x21), Bytes{0x20}, Bytes(32, 0x41),
                          be16(static_cast<std::uint16_t>(ciphers.size())), ciphers, Bytes{0x01, 0x00},
                          be16(static_cast<std::uint16_t>(exts.size())), exts});
  const Bytes hs = cat({Bytes{0x01, static_cast<std::uint8_t>(body.size() >> 16),
                              static_cast<std::uint8_t>(body.size() >> 8),
                              static_cast<std::uint8_t>(body.size())},
                        body});
  Bytes rec = cat({Bytes{0x16, 0x03, 0x01}, be16(static_cast<std::uint16_t>(hs.size())), hs});
  reseal_client_hello(rec, kSecret, static_cast<std::uint32_t>(kNow));
  return rec;
}

// The Telegram/Chrome shape: GREASE, then X25519MLKEM768 and X25519 shares;
// GREASE, 1301, 1302, 1303 suites.
const Bytes kChromeSuites{0x7a, 0x7a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b};
Bytes both_shares_hello(const Bytes& ciphers = kChromeSuites) {
  return hello_with({{0x2a2a, 1}, {0x11ec, kPqClientKeyShare}, {0x001d, 32}}, ciphers);
}

struct Answer {
  std::uint16_t cipher{0};
  std::vector<std::uint16_t> extensions;
  std::uint16_t group{0};
  std::size_t key_length{0};
  A32 x25519{};  // the last 32 bytes of the key share
};

// The ServerHello record of a response, parsed from its own length fields.
std::optional<Answer> parse_answer(const Bytes& response) {
  if (response.size() < 81 || response[0] != 0x16 || response[5] != 0x02) return std::nullopt;
  const std::size_t record_end = 5 + rd16be(response, 3);
  const std::size_t hs_length = (static_cast<std::size_t>(response[6]) << 16) |
                                (static_cast<std::size_t>(response[7]) << 8) | response[8];
  if (hs_length + 9 != record_end || response.size() < record_end) return std::nullopt;
  Answer answer;
  answer.cipher = rd16be(response, 76);
  std::size_t pos = 81;
  const std::size_t end = pos + rd16be(response, 79);
  if (end != record_end) return std::nullopt;
  while (pos + 4 <= end) {
    const std::uint16_t type = rd16be(response, pos);
    const std::size_t length = rd16be(response, pos + 2);
    if (pos + 4 + length > end) return std::nullopt;
    answer.extensions.push_back(type);
    if (type == 0x0033) {
      if (length < 4 + 32) return std::nullopt;
      answer.group = rd16be(response, pos + 4);
      answer.key_length = rd16be(response, pos + 6);
      if (answer.key_length + 4 != length) return std::nullopt;
      std::copy_n(response.begin() + static_cast<std::ptrdiff_t>(pos + 4 + length - 32), 32,
                  answer.x25519.begin());
    } else if (type == 0x002b) {
      if (length != 2 || rd16be(response, pos + 4) != 0x0304) return std::nullopt;
    }
    pos += 4 + length;
  }
  if (pos != end) return std::nullopt;
  return answer;
}

const std::vector<std::uint16_t> kVersionsFirst{0x002b, 0x0033};
const std::vector<std::uint16_t> kKeyShareFirst{0x0033, 0x002b};

}  // namespace

TEST(ServerHelloShape, ClientHelloRecordsOfferedSuitesAndX25519Share) {
  ClientHelloInfo info;
  ASSERT_EQ(validate_client_hello(both_shares_hello(), kSecret, kNow, 120, info), HelloStatus::Ok);
  EXPECT_EQ(info.cipher, 0x1301);
  EXPECT_EQ(info.tls13_suites, 0x07);  // 1301, 1302, 1303; GREASE and c02b ignored
  EXPECT_TRUE(info.offers_pq);
  EXPECT_TRUE(info.offers_x25519);

  ClientHelloInfo pq_only;
  ASSERT_EQ(validate_client_hello(pq_hello(), kSecret, kNow, 120, pq_only), HelloStatus::Ok);
  EXPECT_TRUE(pq_only.offers_pq);
  EXPECT_FALSE(pq_only.offers_x25519);
  EXPECT_EQ(pq_only.tls13_suites, 0x05);  // the fixture offers 1301, 1303

  ClientHelloInfo classical;
  ASSERT_EQ(validate_client_hello(classical_hello(), kSecret, kNow, 120, classical), HelloStatus::Ok);
  EXPECT_FALSE(classical.offers_pq);
  EXPECT_TRUE(classical.offers_x25519);
  // A share of the wrong length is not an X25519 offer.
  ClientHelloInfo short_share;
  ASSERT_EQ(validate_client_hello(hello_with({{0x001d, 31}}, kChromeSuites), kSecret, kNow, 120,
                                  short_share),
            HelloStatus::Ok);
  EXPECT_FALSE(short_share.offers_x25519);
}

TEST(ServerHelloShape, UnmeasuredOptionsKeepTheEchoingAnswer) {
  const auto random = system_random();
  const Bytes hello = both_shares_hello(Bytes{0x13, 0x03, 0x13, 0x01});
  const Bytes response = hello_response(hello, random);
  ASSERT_TRUE(client_accepts(hello, response).has_value());
  const auto answer = parse_answer(response);
  ASSERT_TRUE(answer.has_value());
  EXPECT_EQ(answer->cipher, 0x1303) << "the client's first suite";
  EXPECT_EQ(answer->extensions, kVersionsFirst);
  EXPECT_EQ(answer->group, 0x11ec) << "PQ offered, PQ answered";
  EXPECT_EQ(answer->key_length, kPqServerKeyShare);
}

TEST(ServerHelloShape, KeyShareFirstOrderIsWrittenInBothShapes) {
  const auto random = system_random();
  ServerHelloOptions options;
  options.key_share_first = true;
  for (const bool pq : {false, true}) {
    SCOPED_TRACE(testing::Message() << "pq=" << pq);
    const Bytes hello = pq ? both_shares_hello() : classical_hello();
    const Bytes response = hello_response(hello, random, options);
    const auto body = client_accepts(hello, response);
    ASSERT_TRUE(body.has_value()) << "lengths and HMAC still verify";
    const auto answer = parse_answer(response);
    ASSERT_TRUE(answer.has_value());
    EXPECT_EQ(answer->extensions, kKeyShareFirst);
    EXPECT_EQ(answer->group, pq ? 0x11ec : 0x001d);
    EXPECT_EQ(answer->key_length, pq ? kPqServerKeyShare : 32U);
    EXPECT_TRUE(on_curve25519(answer->x25519));
    // Same total size as the default order: only the order changes.
    EXPECT_EQ(response.size(), (pq ? 95 + kPqServerKeyShare : 127) + 6 + 5 + *body);
  }
}

TEST(ServerHelloShape, MeasuredCipherIsAnsweredOnlyWhenTheClientOfferedIt) {
  const auto random = system_random();
  const Bytes chrome = both_shares_hello();
  const Bytes fixture = classical_hello();  // offers 1301, 1303 only
  const auto cipher_of = [&](const Bytes& hello, std::uint16_t measured) {
    ServerHelloOptions options;
    options.cipher = measured;
    const Bytes response = hello_response(hello, random, options);
    EXPECT_TRUE(client_accepts(hello, response).has_value());
    const auto answer = parse_answer(response);
    return answer ? answer->cipher : std::uint16_t{0};
  };
  EXPECT_EQ(cipher_of(chrome, 0x1302), 0x1302) << "server-side preference for AES-256";
  EXPECT_EQ(cipher_of(chrome, 0x1303), 0x1303);
  EXPECT_EQ(cipher_of(chrome, 0x1301), 0x1301);
  EXPECT_EQ(cipher_of(fixture, 0x1303), 0x1303);
  EXPECT_EQ(cipher_of(fixture, 0x1302), 0x1301) << "not offered: the client's own first suite";
  EXPECT_EQ(cipher_of(fixture, 0x0000), 0x1301) << "unmeasured";
  EXPECT_EQ(cipher_of(fixture, 0xc02f), 0x1301) << "never a non-TLS-1.3 suite";
}

TEST(ServerHelloShape, DeclinedPqAnswersX25519WhenTheClientOffersBoth) {
  const auto random = system_random();
  ServerHelloOptions options;
  options.decline_pq = true;
  const Bytes hello = both_shares_hello();
  const Bytes response = hello_response(hello, random, options);
  ASSERT_TRUE(client_accepts(hello, response).has_value());
  EXPECT_EQ(rd16be(response, 3) + 5U, 127U) << "the classical template";
  const auto answer = parse_answer(response);
  ASSERT_TRUE(answer.has_value());
  EXPECT_EQ(answer->group, 0x001d);
  EXPECT_EQ(answer->key_length, 32U);
  EXPECT_TRUE(on_curve25519(answer->x25519));
  EXPECT_TRUE(derives_with_fresh_peer(answer->x25519));
}

TEST(ServerHelloShape, PqOnlyClientKeepsThePqAnswerEvenWhenDeclined) {
  const auto random = system_random();
  ServerHelloOptions options;
  options.decline_pq = true;
  const Bytes hello = pq_hello();  // X25519MLKEM768 share only
  const Bytes response = hello_response(hello, random, options);
  ASSERT_TRUE(client_accepts(hello, response).has_value());
  const auto answer = parse_answer(response);
  ASSERT_TRUE(answer.has_value());
  EXPECT_EQ(answer->group, 0x11ec) << "no X25519 share to answer instead";
  EXPECT_EQ(answer->key_length, kPqServerKeyShare);
}

TEST(ServerHelloShape, AllMeasuredChoicesTogetherStillVerify) {
  const auto random = system_random();
  ServerHelloOptions options;
  options.cipher = 0x1302;
  options.key_share_first = true;
  options.decline_pq = true;
  options.app_data_min = 4000;
  options.app_data_max = 4000;
  const Bytes hello = both_shares_hello();
  // Through the connection, as the runtime builds it.
  FakeTlsConnection::Config cfg;
  cfg.secret = kSecret;
  cfg.random = random;
  cfg.clock = [] { return kNow; };
  cfg.server_hello = options;
  FakeTlsConnection conn(cfg);
  Bytes to_client, plain;
  ASSERT_EQ(conn.feed(hello, to_client, plain), Status::Ok);
  EXPECT_EQ(client_accepts(hello, to_client), std::optional<std::size_t>(4000));
  const auto answer = parse_answer(to_client);
  ASSERT_TRUE(answer.has_value());
  EXPECT_EQ(answer->cipher, 0x1302);
  EXPECT_EQ(answer->extensions, kKeyShareFirst);
  EXPECT_EQ(answer->group, 0x001d);
  // A forged byte anywhere in the reordered hello breaks the HMAC.
  Bytes forged = to_client;
  forged[85] = static_cast<std::uint8_t>(forged[85] ^ 0x01);
  EXPECT_FALSE(client_accepts(hello, forged).has_value());
}

}  // namespace mtdd::protocol

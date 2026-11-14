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

}  // namespace mtdd::protocol

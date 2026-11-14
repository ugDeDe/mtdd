// JA4 TLS client fingerprint (FoxIO JA4, TCP variant) of a ClientHello.
//
// Reference vector: the FoxIO JA4 README publishes Chrome's fingerprint
// t13d1516h2_8daaf6152771_e5627efa2ab1 together with its raw (JA4_r) form
//   t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,
//   c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,
//   0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
// The Chrome hello below is built from exactly those lists (plus GREASE, SNI
// and ALPN, which JA4 drops from the hashes), so the expected value is the
// published one. The other expected hashes are sha256(...)[:12] of the raw
// strings quoted next to each, computed by hand (python3 hashlib).
#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {
namespace {

using Extension = std::pair<std::uint16_t, Bytes>;

Bytes u16_list(const std::vector<std::uint16_t>& values) {
  Bytes out;
  for (const auto value : values) out = cat({out, be16(value)});
  return out;
}

Bytes alpn_body(const std::vector<std::string>& names) {
  Bytes list;
  for (const auto& name : names) {
    list.push_back(static_cast<std::uint8_t>(name.size()));
    list.insert(list.end(), name.begin(), name.end());
  }
  return cat({be16(static_cast<std::uint16_t>(list.size())), list});
}

Bytes sni_body(std::string_view host) {
  Bytes entry = cat({Bytes{0x00}, be16(static_cast<std::uint16_t>(host.size())),
                     Bytes(host.begin(), host.end())});
  return cat({be16(static_cast<std::uint16_t>(entry.size())), entry});
}

Bytes sigalgs_body(const std::vector<std::uint16_t>& algs) {
  Bytes list = u16_list(algs);
  return cat({be16(static_cast<std::uint16_t>(list.size())), list});
}

Bytes versions_body(const std::vector<std::uint16_t>& versions) {
  Bytes list = u16_list(versions);
  return cat({Bytes{static_cast<std::uint8_t>(list.size())}, list});
}

// One TLS record with one ClientHello; no FakeTLS digest (JA4 ignores it).
Bytes build_hello(std::uint16_t legacy_version, const std::vector<std::uint16_t>& ciphers,
                  const std::vector<Extension>& extensions) {
  Bytes exts;
  for (const auto& [type, body] : extensions) {
    exts = cat({exts, be16(type), be16(static_cast<std::uint16_t>(body.size())), body});
  }
  Bytes suites = u16_list(ciphers);
  Bytes body = cat({be16(legacy_version), Bytes(32, 0x11), Bytes{0x20}, Bytes(32, 0x22),
                    be16(static_cast<std::uint16_t>(suites.size())), suites, Bytes{0x01, 0x00},
                    be16(static_cast<std::uint16_t>(exts.size())), exts});
  Bytes hs = cat({Bytes{0x01, static_cast<std::uint8_t>(body.size() >> 16),
                        static_cast<std::uint8_t>(body.size() >> 8),
                        static_cast<std::uint8_t>(body.size())},
                  body});
  return cat({Bytes{0x16, 0x03, 0x01}, be16(static_cast<std::uint16_t>(hs.size())), hs});
}

Bytes chrome_hello() {
  const std::vector<std::uint16_t> ciphers = {0x3a3a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
                                              0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
                                              0x009c, 0x009d, 0x002f, 0x0035};
  const std::vector<Extension> extensions = {
      {0x8a8a, {}},
      {0x0000, sni_body("example.com")},
      {0x0017, {}},
      {0xff01, {0x00}},
      {0x000a, cat({be16(8), u16_list({0x6a6a, 0x001d, 0x0017, 0x0018})})},
      {0x000b, {0x01, 0x00}},
      {0x0023, {}},
      {0x0010, alpn_body({"h2", "http/1.1"})},
      {0x0005, {0x01, 0x00, 0x00, 0x00, 0x00}},
      {0x000d, sigalgs_body({0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601})},
      {0x0012, {}},
      {0x0033, cat({be16(36), be16(0x001d), be16(32), Bytes(32, 0x55)})},
      {0x002d, {0x01, 0x01}},
      {0x002b, versions_body({0x7a7a, 0x0304, 0x0303})},
      {0x001b, {0x02, 0x00, 0x02}},
      {0x4469, {0x00, 0x03, 0x02, 0x68, 0x32}},
      {0xbaba, {0x00}},
      {0x0015, Bytes(40, 0x00)},
  };
  return build_hello(0x0303, ciphers, extensions);
}

TEST(Ja4, ChromeMatchesThePublishedFingerprint) {
  const auto value = client_hello_ja4(chrome_hello());
  ASSERT_TRUE(value);
  EXPECT_EQ(*value, "t13d1516h2_8daaf6152771_e5627efa2ab1");
}

TEST(Ja4, ExtensionOrderAndGreaseDoNotChangeTheFingerprint) {
  // Chrome shuffles its extensions per connection; JA4 sorts them.
  auto fields = parse_client_hello_fields(chrome_hello());
  ASSERT_TRUE(fields);
  std::reverse(fields->extensions.begin(), fields->extensions.end());
  fields->ciphers.push_back(0xfafa);
  fields->signature_algorithms.insert(fields->signature_algorithms.begin(), 0x2a2a);
  EXPECT_EQ(ja4(*fields), "t13d1516h2_8daaf6152771_e5627efa2ab1");
}

TEST(Ja4, Tls12WithoutSniOrAlpn) {
  // No supported_versions: legacy_version 0x0303 -> "12". No SNI -> "i".
  // b = sha256("c02f,c030"), c = sha256("000a,000b,000d_0401").
  const Bytes hello = build_hello(0x0303, {0xc02f, 0xc030},
                                  {{0x000a, cat({be16(2), be16(0x0017)})},
                                   {0x000b, {0x01, 0x00}},
                                   {0x000d, sigalgs_body({0x0401})}});
  EXPECT_EQ(client_hello_ja4(hello).value_or(""), "t12i020300_04659ec43a24_379eb492da94");
}

TEST(Ja4, SupportedVersionsOverridesLegacyVersion) {
  // Highest non-GREASE supported version wins over legacy 0x0303.
  // b = sha256("1301"), c = sha256("002b") (no signature_algorithms: no "_").
  const Bytes tls13 = build_hello(0x0303, {0x1301},
                                  {{0x002b, versions_body({0x0a0a, 0x0303, 0x0304})}});
  EXPECT_EQ(client_hello_ja4(tls13).value_or(""), "t13i010100_0f2cb44170f4_b9a491fefe05");
  // Only GREASE in supported_versions: fall back to the legacy version.
  const Bytes grease_only = build_hello(0x0301, {0x1301}, {{0x002b, versions_body({0x1a1a})}});
  EXPECT_EQ(client_hello_ja4(grease_only).value_or("").substr(0, 4), "t10i");
  // Unknown version -> "00".
  const Bytes odd = build_hello(0x0305, {0x1301}, {});
  EXPECT_EQ(client_hello_ja4(odd).value_or("").substr(0, 4), "t00i");
}

TEST(Ja4, EmptyListsHashToZeros) {
  // No ciphers, no extensions: both hashes are 000000000000.
  const Bytes bare = build_hello(0x0303, {}, {});
  EXPECT_EQ(client_hello_ja4(bare).value_or(""), "t12i000000_000000000000_000000000000");
  // Only SNI and ALPN: counted in ja4_a, removed from the ja4_c list.
  const Bytes sni_alpn =
      build_hello(0x0303, {0x1301}, {{0x0000, sni_body("a.example")}, {0x0010, alpn_body({"h2"})}});
  EXPECT_EQ(client_hello_ja4(sni_alpn).value_or(""), "t12d0102h2_0f2cb44170f4_000000000000");
  // Signature algorithms but no other extension: hashes "_0401" (non-empty).
  const Bytes sig_only = build_hello(0x0303, {0x1301}, {{0x000d, sigalgs_body({0x0401})}});
  const auto value = client_hello_ja4(sig_only).value_or("");
  EXPECT_EQ(value.substr(0, 11), "t12i010100_");
  EXPECT_NE(value.substr(24), "000000000000");
}

TEST(Ja4, AlpnEdgeCases) {
  const auto alpn_of = [](const Bytes& body) {
    const Bytes hello = build_hello(0x0303, {0x1301}, {{0x0010, body}});
    const auto value = client_hello_ja4(hello);
    return value ? value->substr(8, 2) : std::string("??");
  };
  EXPECT_EQ(alpn_of(alpn_body({"h2"})), "h2");
  EXPECT_EQ(alpn_of(alpn_body({"http/1.1", "h2"})), "h1");  // first value only
  EXPECT_EQ(alpn_of(alpn_body({"h"})), "hh");               // one character
  EXPECT_EQ(alpn_of(alpn_body({"\xab"})), "ab");            // non-alnum: hex rule
  EXPECT_EQ(alpn_of(alpn_body({"\xab\xcd"})), "ad");
  EXPECT_EQ(alpn_of(alpn_body({std::string("a\x01", 2)})), "61");  // last byte non-alnum
  EXPECT_EQ(alpn_of(alpn_body({""})), "00");                // empty first value
  EXPECT_EQ(alpn_of(be16(0)), "00");                        // empty list
  EXPECT_EQ(alpn_of(Bytes{}), "00");                        // empty extension body
  EXPECT_EQ(alpn_of(Bytes{0x00, 0x09, 0x08, 'h'}), "00");   // value overruns: ignored
}

TEST(Ja4, CountsAreCappedAt99) {
  std::vector<std::uint16_t> ciphers;
  for (std::uint16_t i = 0; i < 120; ++i) ciphers.push_back(static_cast<std::uint16_t>(0xc100 + i));
  std::vector<Extension> extensions;
  for (std::uint16_t i = 0; i < 105; ++i) extensions.emplace_back(static_cast<std::uint16_t>(0x5000 + i), Bytes{});
  const auto value = client_hello_ja4(build_hello(0x0303, ciphers, extensions));
  ASSERT_TRUE(value);
  EXPECT_EQ(value->substr(0, 10), "t12i999900");
  EXPECT_EQ(value->size(), 36u);
}

TEST(Ja4, FakeTlsHelloOfTheFixtureFingerprints) {
  // The suite's FakeTLS fixture hello: two suites, three extensions
  // (supported_versions, key_share, SNI). Its supported_versions body is the
  // 2-byte ServerHello form (03 04, no list length), not a valid ClientHello
  // version list, so JA4 falls back to legacy_version 0x0303 ("12").
  const Bytes hello = make_client_hello(kSecret, static_cast<std::uint32_t>(kNow), 0x001d, 32,
                                        0x1301, "example.com");
  const auto value = client_hello_ja4(hello);
  ASSERT_TRUE(value);
  EXPECT_EQ(value->substr(0, 10), "t12d020300");
  EXPECT_EQ(value->size(), 36u);
}

TEST(Ja4, MalformedHellosNeverCrash) {
  const Bytes hello = chrome_hello();
  // Every truncation: the record length no longer matches, so nullopt.
  for (std::size_t size = 0; size < hello.size(); ++size) {
    EXPECT_FALSE(client_hello_ja4(std::span<const std::uint8_t>(hello).first(size))) << size;
  }
  // Not a handshake / not a ClientHello.
  Bytes alert = hello;
  alert[0] = 0x15;
  EXPECT_FALSE(client_hello_ja4(alert));
  Bytes server_hello = hello;
  server_hello[5] = 0x02;
  EXPECT_FALSE(client_hello_ja4(server_hello));
  // An extension that claims more bytes than the block holds.
  Bytes overrun = build_hello(0x0303, {0x1301}, {{0x000d, sigalgs_body({0x0401})}});
  overrun[overrun.size() - 5] = 0x40;  // extension length low byte: 4 -> 64
  EXPECT_FALSE(client_hello_ja4(overrun));
  // Odd cipher-suite length.
  Bytes odd = build_hello(0x0303, {0x1301}, {});
  odd[5 + 4 + 2 + 32 + 1 + 32 + 1] = 0x03;
  EXPECT_FALSE(client_hello_ja4(odd));
  // Every single-byte corruption of a valid hello either parses or is
  // rejected, never reads out of bounds (ASan build).
  for (std::size_t i = 0; i < hello.size(); ++i) {
    for (const int value : {0x00, 0x7f, 0xff}) {
      Bytes mutated = hello;
      mutated[i] = static_cast<std::uint8_t>(value);
      const auto result = client_hello_ja4(mutated);
      if (result) {
        EXPECT_EQ(result->size(), 36u);
      }
    }
  }
}

}  // namespace
}  // namespace mtdd::protocol

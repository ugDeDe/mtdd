#pragma once

// Protocol core tests for mtdd.
//
// Wire-layout provenance (read-only references, not copied code):
//   * TelegramMessenger/MTProxy @ f36d8af769ffaeac36978d38c2c0f6d1104c2137:
//     net/net-tcp-rpc-client.c, net/net-tcp-rpc-server.c, net/net-tcp-rpc-common.c,
//     net/net-crypto-aes.c, common/rpc-const.h, net/net-tcp-rpc-common.h,
//     mtproto/mtproto-proxy.c (RPC_PROXY_REQ / TL_PROXY_TAG / ad-tag block).
//   * sleep3r/mtproto.zig @ a231c48b813461b5e0084aec7930922b7dd4b5ff:
//     src/protocol/tls.zig, obfuscation.zig, middleproxy.zig,
//     src/proxy/middle_proxy_frames.zig, middle_proxy_handshake.zig.
//   * alexbers/mtprotoproxy (master) as an independent Python description of the
//     same ME KDF, RPC framing, ad-tag block and obfuscation split.
//
// Hard-coded protocol vectors were produced by an independent Python script using
// hashlib/hmac only (KDF, FakeTLS ClientHello/ServerHello), plus the published
// NIST SP 800-38A AES vectors.

#include <gtest/gtest.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <limits>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "mtdd/protocol.hpp"

namespace mtdd::protocol {
namespace {

using Bytes = std::vector<std::uint8_t>;
using A16 = std::array<std::uint8_t, 16>;
using A32 = std::array<std::uint8_t, 32>;

Bytes from_hex(std::string_view hex) {
  EXPECT_EQ(hex.size() % 2, 0u);
  Bytes out;
  out.reserve(hex.size() / 2);
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    int hi = nib(hex[i]);
    int lo = nib(hex[i + 1]);
    EXPECT_GE(hi, 0);
    EXPECT_GE(lo, 0);
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> arr(const Bytes& b) {
  EXPECT_EQ(b.size(), N);
  std::array<std::uint8_t, N> out{};
  std::copy_n(b.begin(), std::min(b.size(), N), out.begin());
  return out;
}

Bytes cat(std::initializer_list<std::span<const std::uint8_t>> parts) {
  Bytes out;
  for (auto p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}

Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}

[[maybe_unused]] void expect_bytes(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  EXPECT_EQ(Bytes(a.begin(), a.end()), Bytes(b.begin(), b.end()));
}

[[maybe_unused]] Bytes le32(std::uint32_t v) {
  return {static_cast<std::uint8_t>(v), static_cast<std::uint8_t>(v >> 8),
          static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 24)};
}
Bytes be16(std::uint16_t v) {
  return {static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
}

[[maybe_unused]] std::uint32_t rd32(std::span<const std::uint8_t> b, std::size_t off = 0) {
  return static_cast<std::uint32_t>(b[off]) |
         (static_cast<std::uint32_t>(b[off + 1]) << 8) |
         (static_cast<std::uint32_t>(b[off + 2]) << 16) |
         (static_cast<std::uint32_t>(b[off + 3]) << 24);
}
std::uint16_t rd16be(std::span<const std::uint8_t> b, std::size_t off = 0) {
  return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}

// Deterministic stream used by FakeTLS server-hello tests. The golden ServerHello
// hash was generated with this exact sequence (byte i = (0x30 + i*7) & 0xff).
struct CountingRng {
  std::uint64_t total = 0;  // bytes produced before the current call
  RandomFn fn() {
    return [this](std::span<std::uint8_t> out) {
      for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(0x30 + total * 7 + i);
      }
      total += out.size();
    };
  }
};

constexpr std::int64_t kNow = 1600000000;
const A16 kSecret = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));

// Independent ClientHello builder (structure per the reference implementations).
[[maybe_unused]] Bytes make_client_hello(const A16& secret, std::uint32_t ts, std::uint16_t group = 0x001d,
                        std::size_t key_len = 32, std::uint16_t cipher = 0x1301,
                        std::string_view sni = "", bool offer_tls13 = true) {
  Bytes random;
  for (int i = 0; i < 32; ++i) random.push_back(static_cast<std::uint8_t>(0x20 + i));
  Bytes sid;
  for (int i = 0; i < 32; ++i) sid.push_back(static_cast<std::uint8_t>(0x40 + i));
  Bytes key;
  for (std::size_t i = 0; i < key_len; ++i) key.push_back(static_cast<std::uint8_t>(0x80 + i));

  Bytes entry = cat({be16(group), be16(static_cast<std::uint16_t>(key_len)), key});
  Bytes key_share = cat({be16(static_cast<std::uint16_t>(entry.size())), entry});
  Bytes exts;
  exts = cat({exts, Bytes{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}});
  exts = cat({exts, Bytes{0x00, 0x33}, be16(static_cast<std::uint16_t>(key_share.size())), key_share});
  if (!sni.empty()) {
    Bytes sn = cat({Bytes{0x00}, be16(static_cast<std::uint16_t>(sni.size())),
                    Bytes(sni.begin(), sni.end())});
    Bytes list = cat({be16(static_cast<std::uint16_t>(sn.size())), sn});
    exts = cat({exts, Bytes{0x00, 0x00}, be16(static_cast<std::uint16_t>(list.size())), list});
  }

  Bytes ciphers = offer_tls13 ? Bytes{0x13, 0x01, 0x13, 0x03} : Bytes{0xc0, 0x2f, 0xc0, 0x30};
  Bytes body;
  body = cat({body, Bytes{0x03, 0x03}, random, Bytes{0x20}, sid,
              be16(static_cast<std::uint16_t>(ciphers.size())), ciphers, Bytes{0x01, 0x00},
              be16(static_cast<std::uint16_t>(exts.size())), exts});
  Bytes hs;
  hs = cat({hs, Bytes{0x01}, Bytes{static_cast<std::uint8_t>(body.size() >> 16),
                                 static_cast<std::uint8_t>(body.size() >> 8),
                                 static_cast<std::uint8_t>(body.size())},
            body});
  Bytes rec = cat({Bytes{0x16, 0x03, 0x01}, be16(static_cast<std::uint16_t>(hs.size())), hs});
  EXPECT_GE(rec.size(), 76u);

  auto hmac = crypto::hmac_sha256(secret, cat({std::span<const std::uint8_t>(rec).first(11), A32{},
                                               std::span<const std::uint8_t>(rec).subspan(43)}));
  for (int i = 0; i < 4; ++i) {
    hmac[28 + i] = static_cast<std::uint8_t>(hmac[28 + i] ^ static_cast<std::uint8_t>(ts >> (8 * i)));
  }
  std::copy(hmac.begin(), hmac.end(), rec.begin() + 11);

  if (offer_tls13) { EXPECT_EQ(rd16be(rec, 78), cipher); }
  return rec;
}

[[maybe_unused]] void reseal_client_hello(Bytes& rec, const A16& secret, std::uint32_t ts) {
  auto hmac = crypto::hmac_sha256(secret, cat({std::span<const std::uint8_t>(rec).first(11), A32{},
                                               std::span<const std::uint8_t>(rec).subspan(43)}));
  for (int i = 0; i < 4; ++i) {
    hmac[28 + i] = static_cast<std::uint8_t>(hmac[28 + i] ^ static_cast<std::uint8_t>(ts >> (8 * i)));
  }
  std::copy(hmac.begin(), hmac.end(), rec.begin() + 11);
}

// ----------------------------- crypto KATs -----------------------------

}  // namespace
}  // namespace mtdd::protocol

// JA4 TLS client fingerprint (FoxIO JA4 spec, TCP variant):
//
//   ja4_a = "t" + version + ("d" SNI present | "i") + ciphers(2) + extensions(2) + alpn(2)
//   ja4_b = sha256("c1,c2,...")[:12]                  ciphers sorted, 4 hex each
//   ja4_c = sha256("e1,e2,..._s1,s2,...")[:12]        extensions sorted, without
//                                                      SNI (0000) and ALPN (0010);
//                                                      signature algorithms in order
//
// GREASE values are ignored everywhere, counts are capped at 99, an empty list
// (or empty string to hash) gives "000000000000", and without signature
// algorithms the ja4_c input has no trailing "_". Pure and allocation-light;
// the runtime calls it only for hellos it records, never on the admission path.
#include "mtdd/protocol.hpp"

#include <algorithm>
#include <cctype>

namespace mtdd::protocol {
namespace {

constexpr char kHex[] = "0123456789abcdef";

// RFC 8701 GREASE: 0x0a0a, 0x1a1a, ..., 0xfafa.
bool grease(std::uint16_t value) noexcept {
  return (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff);
}

std::uint16_t rd16(std::span<const std::uint8_t> b, std::size_t off) {
  return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}

void append_hex16(std::string& out, std::uint16_t value) {
  out.push_back(kHex[(value >> 12) & 15]);
  out.push_back(kHex[(value >> 8) & 15]);
  out.push_back(kHex[(value >> 4) & 15]);
  out.push_back(kHex[value & 15]);
}

std::string join(const std::vector<std::uint16_t>& values) {
  std::string out;
  out.reserve(values.size() * 5);
  for (const auto value : values) {
    if (!out.empty()) out.push_back(',');
    append_hex16(out, value);
  }
  return out;
}

std::string hash12(const std::string& text) {
  if (text.empty()) return "000000000000";
  const auto digest = crypto::sha256(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
  std::string out;
  out.reserve(12);
  for (std::size_t i = 0; i < 6; ++i) {
    out.push_back(kHex[digest[i] >> 4]);
    out.push_back(kHex[digest[i] & 15]);
  }
  return out;
}

const char* version_text(std::uint16_t version) noexcept {
  switch (version) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    case 0x0200: return "s2";
    case 0xfeff: return "d1";
    case 0xfefd: return "d2";
    case 0xfefc: return "d3";
    default: return "00";
  }
}

void append_count(std::string& out, std::size_t count) {
  count = std::min<std::size_t>(count, 99);
  out.push_back(static_cast<char>('0' + count / 10));
  out.push_back(static_cast<char>('0' + count % 10));
}

bool alnum(char c) noexcept { return std::isalnum(static_cast<unsigned char>(c)) != 0; }

}  // namespace

std::optional<ClientHelloFields> parse_client_hello_fields(std::span<const std::uint8_t> record) {
  // Record header (5) + handshake header (4) + version (2) + random (32).
  if (record.size() < 5 + 4 + 2 + 32 || record[0] != 0x16 || record[5] != 0x01) {
    return std::nullopt;
  }
  const std::size_t rec_len = rd16(record, 3);
  if (record.size() != 5 + rec_len) return std::nullopt;
  const std::size_t hs_len = (static_cast<std::size_t>(record[6]) << 16) |
                             (static_cast<std::size_t>(record[7]) << 8) | record[8];
  if (9 + hs_len > record.size()) return std::nullopt;
  const std::size_t end = 9 + hs_len;

  ClientHelloFields out;
  std::size_t pos = 9;
  out.legacy_version = rd16(record, pos);
  pos += 2 + 32;
  if (pos + 1 > end) return std::nullopt;  // session id
  pos += 1 + record[pos];
  if (pos + 2 > end) return std::nullopt;  // cipher suites
  const std::size_t cs_len = rd16(record, pos);
  pos += 2;
  if (cs_len % 2 != 0 || pos + cs_len > end) return std::nullopt;
  out.ciphers.reserve(cs_len / 2);
  for (std::size_t i = 0; i < cs_len; i += 2) out.ciphers.push_back(rd16(record, pos + i));
  pos += cs_len;
  if (pos + 1 > end) return std::nullopt;  // compression methods
  pos += 1 + record[pos];
  if (pos > end) return std::nullopt;
  if (pos == end) return out;  // no extensions block (legal before TLS 1.3)
  if (pos + 2 > end) return std::nullopt;
  const std::size_t ext_len = rd16(record, pos);
  pos += 2;
  if (pos + ext_len > end) return std::nullopt;
  const std::size_t ext_end = pos + ext_len;
  while (pos + 4 <= ext_end) {
    const std::uint16_t type = rd16(record, pos);
    const std::size_t len = rd16(record, pos + 2);
    pos += 4;
    if (pos + len > ext_end) return std::nullopt;
    out.extensions.push_back(type);
    const auto body = record.subspan(pos, len);
    if (type == 0x0010 && !out.has_alpn) {  // ALPN: u16 list, u8-prefixed names
      out.has_alpn = true;
      if (body.size() >= 3) {
        const std::size_t list = rd16(body, 0);
        const std::size_t first = body[2];
        if (list + 2 <= body.size() && first + 1 <= list) {
          out.alpn_first.assign(reinterpret_cast<const char*>(body.data() + 3), first);
        }
      }
    } else if (type == 0x000d && out.signature_algorithms.empty() && body.size() >= 2) {
      const std::size_t list = rd16(body, 0);
      if (list % 2 == 0 && list + 2 <= body.size()) {
        for (std::size_t i = 0; i < list; i += 2) {
          out.signature_algorithms.push_back(rd16(body, 2 + i));
        }
      }
    } else if (type == 0x002b && out.supported_versions.empty() && body.size() >= 1) {
      const std::size_t list = body[0];
      if (list % 2 == 0 && list + 1 <= body.size()) {
        for (std::size_t i = 0; i < list; i += 2) {
          out.supported_versions.push_back(rd16(body, 1 + i));
        }
      }
    }
    pos += len;
  }
  if (pos != ext_end) return std::nullopt;
  return out;
}

std::string ja4(const ClientHelloFields& hello) {
  std::uint16_t version = 0;
  for (const auto value : hello.supported_versions) {
    if (!grease(value)) version = std::max(version, value);
  }
  if (version == 0) version = hello.legacy_version;

  std::vector<std::uint16_t> ciphers;
  ciphers.reserve(hello.ciphers.size());
  for (const auto value : hello.ciphers) {
    if (!grease(value)) ciphers.push_back(value);
  }
  std::vector<std::uint16_t> extensions;
  extensions.reserve(hello.extensions.size());
  std::size_t extension_count = 0;
  bool sni = false;
  for (const auto value : hello.extensions) {
    if (grease(value)) continue;
    ++extension_count;
    if (value == 0x0000) sni = true;
    if (value == 0x0000 || value == 0x0010) continue;
    extensions.push_back(value);
  }
  std::vector<std::uint16_t> signatures;
  signatures.reserve(hello.signature_algorithms.size());
  for (const auto value : hello.signature_algorithms) {
    if (!grease(value)) signatures.push_back(value);
  }

  std::string out;
  out.reserve(36);
  out.push_back('t');
  out += version_text(version);
  out.push_back(sni ? 'd' : 'i');
  append_count(out, ciphers.size());
  append_count(out, extension_count);
  const std::string& alpn = hello.alpn_first;
  if (alpn.empty()) {
    out += "00";
  } else if (alnum(alpn.front()) && alnum(alpn.back())) {
    out.push_back(alpn.front());
    out.push_back(alpn.back());
  } else {
    // Non-alphanumeric first or last byte: first and last hex digit of the
    // value's hex form (spec: 0xab -> "ab", 0xab 0xcd -> "ad").
    out.push_back(kHex[static_cast<std::uint8_t>(alpn.front()) >> 4]);
    out.push_back(kHex[static_cast<std::uint8_t>(alpn.back()) & 15]);
  }

  std::sort(ciphers.begin(), ciphers.end());
  std::sort(extensions.begin(), extensions.end());
  out.push_back('_');
  out += hash12(join(ciphers));
  out.push_back('_');
  std::string c = join(extensions);
  if (!signatures.empty()) {
    c.push_back('_');
    c += join(signatures);
  }
  out += hash12(c);
  return out;
}

std::optional<std::string> client_hello_ja4(std::span<const std::uint8_t> record) {
  const auto fields = parse_client_hello_fields(record);
  if (!fields) return std::nullopt;
  return ja4(*fields);
}

}  // namespace mtdd::protocol

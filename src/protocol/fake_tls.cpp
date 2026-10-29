#include "mtdd/protocol.hpp"

#include <algorithm>
#include <cctype>
#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <utility>

namespace mtdd::protocol {
namespace {

constexpr std::size_t kFakeCertSize = 2878;
constexpr std::uint16_t kPqGroup = 0x11ec;

std::uint16_t be16(std::span<const std::uint8_t> b, std::size_t off) {
  return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}
void wr16(Bytes& b, std::size_t off, std::uint16_t v) {
  b[off] = static_cast<std::uint8_t>(v >> 8);
  b[off + 1] = static_cast<std::uint8_t>(v);
}
void wr24(Bytes& b, std::size_t off, std::uint32_t v) {
  b[off] = static_cast<std::uint8_t>(v >> 16);
  b[off + 1] = static_cast<std::uint8_t>(v >> 8);
  b[off + 2] = static_cast<std::uint8_t>(v);
}
std::uint32_t rd32(std::span<const std::uint8_t> b, std::size_t off) {
  return static_cast<std::uint32_t>(b[off]) |
         (static_cast<std::uint32_t>(b[off + 1]) << 8) |
         (static_cast<std::uint32_t>(b[off + 2]) << 16) |
         (static_cast<std::uint32_t>(b[off + 3]) << 24);
}
bool ascii_iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    auto lower = [](char c) {
      return static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
    };
    if (lower(a[i]) != lower(b[i])) return false;
  }
  return true;
}

void release_if_large(Bytes& b) {
  if (b.capacity() > 64u * 1024u && b.empty()) Bytes().swap(b);
}


std::int64_t system_now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
bool is_tls_version(std::span<const std::uint8_t> b) {
  return b.size() >= 3 && b[1] == 0x03 && (b[2] == 0x01 || b[2] == 0x03);
}
void append(Bytes& out, std::span<const std::uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); }

bool reserved_nonce(std::span<const std::uint8_t> raw) {
  static constexpr std::array<std::array<std::uint8_t, 4>, 6> kBanned{{
      {{'H', 'E', 'A', 'D'}}, {{'P', 'O', 'S', 'T'}}, {{'G', 'E', 'T', ' '}},
      {{0xee, 0xee, 0xee, 0xee}}, {{0xdd, 0xdd, 0xdd, 0xdd}}, {{0x16, 0x03, 0x01, 0x02}},
  }};
  if (raw[0] == 0xef) return true;
  std::array<std::uint8_t, 4> first{raw[0], raw[1], raw[2], raw[3]};
  for (const auto& b : kBanned) {
    if (first == b) return true;
  }
  return raw[4] == 0 && raw[5] == 0 && raw[6] == 0 && raw[7] == 0;
}

// Room left in the record that `open_record` names, or 0 when it is not the
// final, extendable ApplicationData record of `wire`.
std::size_t open_record_room(const Bytes& wire, const std::size_t* open_record,
                             std::size_t max_body) {
  if (open_record == nullptr || *open_record == FakeTlsConnection::kNoOpenRecord) return 0;
  const std::size_t header = *open_record;
  if (header > wire.size() || wire.size() - header < 5 || wire[header] != 0x17) return 0;
  const std::size_t length = (static_cast<std::size_t>(wire[header + 3]) << 8) | wire[header + 4];
  if (header + 5 + length != wire.size() || length >= max_body) return 0;
  return max_body - length;
}

void grow_open_record(Bytes& wire, std::size_t header, std::size_t added) {
  const std::size_t length =
      ((static_cast<std::size_t>(wire[header + 3]) << 8) | wire[header + 4]) + added;
  wire[header + 3] = static_cast<std::uint8_t>(length >> 8);
  wire[header + 4] = static_cast<std::uint8_t>(length);
}

}  // namespace

void ObfuscationParams::wipe() {
  crypto::secure_zero(decrypt_key);
  crypto::secure_zero(decrypt_iv);
  crypto::secure_zero(encrypt_key);
  crypto::secure_zero(encrypt_iv);
  tag = ProtoTag::Secure;
  dc_id = 0;
}

void ClientHelloInfo::wipe() {
  crypto::secure_zero(digest);
  crypto::secure_zero(canonical_hmac);
  crypto::secure_zero(session_id);
  crypto::secure_zero(secret);
  timestamp = 0;
  server_name.clear();
  server_name.shrink_to_fit();
}

namespace {

// Shared ClientHello validation. `authenticate(input, canonical, secret)`
// returns true when some key's HMAC over the canonical input matches the first
// 28 digest bytes, filling the canonical HMAC and that key's secret.
template <typename Authenticate>
HelloStatus validate_hello_core(std::span<const std::uint8_t> record, std::int64_t now_unix,
                                std::uint32_t skew_seconds, ClientHelloInfo& out,
                                Authenticate&& authenticate) {
  out.wipe();
  if (record.size() < 5) return HelloStatus::NeedMoreData;
  if (record[0] != 0x16 || !is_tls_version(record)) return HelloStatus::NotTls;

  const std::size_t rec_len = be16(record, 3);
  if (rec_len < 100) return HelloStatus::Invalid;  // reference min_tls_client_hello_size
  if (record.size() < 5 + rec_len) return HelloStatus::NeedMoreData;
  if (record.size() != 5 + rec_len) return HelloStatus::Invalid;

  if (record[5] != 0x01) return HelloStatus::Invalid;  // ClientHello
  const std::size_t hs_len = (static_cast<std::size_t>(record[6]) << 16) |
                             (static_cast<std::size_t>(record[7]) << 8) | record[8];
  if (hs_len != rec_len - 4) return HelloStatus::Invalid;
  if (record.size() < 76) return HelloStatus::Invalid;

  std::array<std::uint8_t, 32> digest{};
  std::copy_n(record.begin() + 11, 32, digest.begin());
  const std::size_t sid_len = record[43];
  if (sid_len != 32) return HelloStatus::Invalid;
  if (record.size() < 44 + sid_len) return HelloStatus::Invalid;

  Bytes hmac_input;
  hmac_input.reserve(record.size());
  append(hmac_input, record.first(11));
  hmac_input.insert(hmac_input.end(), 32, 0);
  append(hmac_input, record.subspan(43));
  std::array<std::uint8_t, 32> canonical{};
  std::array<std::uint8_t, 16> secret{};
  if (!authenticate(std::span<const std::uint8_t>(hmac_input), digest, canonical, secret)) {
    crypto::secure_zero(digest);
    crypto::secure_zero(hmac_input);
    return HelloStatus::Unauthenticated;
  }
  struct Wipe {
    std::array<std::uint8_t, 32>& canonical;
    std::array<std::uint8_t, 16>& secret;
    ~Wipe() {
      crypto::secure_zero(canonical);
      crypto::secure_zero(secret);
    }
  } wipe_keys{canonical, secret};

  const std::uint32_t mask = (static_cast<std::uint32_t>(digest[28]) ^ canonical[28]) |
                             ((static_cast<std::uint32_t>(digest[29]) ^ canonical[29]) << 8) |
                             ((static_cast<std::uint32_t>(digest[30]) ^ canonical[30]) << 16) |
                             ((static_cast<std::uint32_t>(digest[31]) ^ canonical[31]) << 24);
  const std::int64_t diff = now_unix - static_cast<std::int64_t>(mask);
  if (diff < -static_cast<std::int64_t>(skew_seconds) || diff > static_cast<std::int64_t>(skew_seconds)) {
    crypto::secure_zero(digest);
    crypto::secure_zero(hmac_input);
    return HelloStatus::ClockSkew;
  }

  // Cipher suites: echo the first non-GREASE TLS 1.3 suite.
  std::size_t pos = 44 + sid_len;
  if (pos + 2 > record.size()) return HelloStatus::Invalid;
  const std::size_t cs_len = be16(record, pos);
  pos += 2;
  if (cs_len == 0 || cs_len % 2 != 0 || pos + cs_len > record.size()) return HelloStatus::Invalid;
  std::uint16_t cipher = 0;
  for (std::size_t i = 0; i < cs_len; i += 2) {
    const std::uint16_t suite = be16(record, pos + i);
    if ((suite & 0x0f0f) == 0x0a0a) continue;  // GREASE
    if (suite == 0x1301 || suite == 0x1302 || suite == 0x1303) {
      cipher = suite;
      break;
    }
  }
  if (cipher == 0) return HelloStatus::Invalid;  // no TLS 1.3 suite offered
  pos += cs_len;

  if (pos + 1 > record.size()) return HelloStatus::Invalid;
  pos += 1 + record[pos];
  if (pos + 2 > record.size()) return HelloStatus::Invalid;
  const std::size_t ext_len = be16(record, pos);
  pos += 2;
  if (pos + ext_len > record.size()) return HelloStatus::Invalid;

  bool offers_pq = false;
  std::string server_name;
  const std::size_t ext_end = pos + ext_len;
  while (pos + 4 <= ext_end) {
    const std::uint16_t type = be16(record, pos);
    const std::size_t len = be16(record, pos + 2);
    pos += 4;
    if (pos + len > ext_end) return HelloStatus::Invalid;
    if (type == 0x0033) {
      if (len < 2) return HelloStatus::Invalid;
      const std::size_t list_len = be16(record, pos);
      if (list_len != len - 2) return HelloStatus::Invalid;
      std::size_t kp = pos + 2;
      const std::size_t ks_end = pos + len;
      while (kp + 4 <= ks_end) {
        const std::uint16_t group = be16(record, kp);
        const std::size_t key_len = be16(record, kp + 2);
        if (kp + 4 + key_len > ks_end) return HelloStatus::Invalid;
        if (group == kPqGroup && key_len == kPqClientKeyShare) offers_pq = true;
        kp += 4 + key_len;
      }
      if (kp != ks_end) return HelloStatus::Invalid;
    } else if (type == 0x0000) {  // server_name
      if (len < 2) return HelloStatus::Invalid;
      const std::size_t list_len = be16(record, pos);
      if (list_len != len - 2) return HelloStatus::Invalid;
      std::size_t np = pos + 2;
      const std::size_t names_end = pos + len;
      while (np + 3 <= names_end) {
        const std::uint8_t name_type = record[np];
        const std::size_t name_len = be16(record, np + 1);
        np += 3;
        if (np + name_len > names_end) return HelloStatus::Invalid;
        if (name_type == 0 && server_name.empty() && name_len > 0) {
          if (std::find(record.begin() + static_cast<std::ptrdiff_t>(np),
                        record.begin() + static_cast<std::ptrdiff_t>(np + name_len), 0) !=
              record.begin() + static_cast<std::ptrdiff_t>(np + name_len)) {
            return HelloStatus::Invalid;
          }
          server_name.assign(reinterpret_cast<const char*>(record.data() + np), name_len);
        }
        np += name_len;
      }
      if (np != names_end) return HelloStatus::Invalid;
    }
    pos += len;
  }
  if (pos != ext_end) return HelloStatus::Invalid;

  out.digest = digest;
  out.canonical_hmac = canonical;
  std::copy_n(record.begin() + 44, 32, out.session_id.begin());
  std::copy(secret.begin(), secret.end(), out.secret.begin());
  out.cipher = cipher;
  out.timestamp = mask;
  out.server_name = std::move(server_name);
  out.offers_pq = offers_pq;
  crypto::secure_zero(hmac_input);
  return HelloStatus::Ok;
}

bool hmac_prefix_matches(const std::array<std::uint8_t, 32>& digest,
                         const std::array<std::uint8_t, 32>& canonical) {
  std::array<std::uint8_t, 28> got28{}, want28{};
  std::copy_n(digest.begin(), 28, got28.begin());
  std::copy_n(canonical.begin(), 28, want28.begin());
  return crypto::constant_time_equal(got28, want28);
}

}  // namespace

HelloStatus validate_client_hello(std::span<const std::uint8_t> record,
                                  std::span<const std::uint8_t, 16> secret,
                                  std::int64_t now_unix, std::uint32_t skew_seconds,
                                  ClientHelloInfo& out) {
  return validate_hello_core(
      record, now_unix, skew_seconds, out,
      [&](std::span<const std::uint8_t> input, const std::array<std::uint8_t, 32>& digest,
          std::array<std::uint8_t, 32>& canonical, std::array<std::uint8_t, 16>& matched) {
        canonical = crypto::hmac_sha256(secret, input);
        if (!hmac_prefix_matches(digest, canonical)) return false;
        std::copy(secret.begin(), secret.end(), matched.begin());
        return true;
      });
}

HelloStatus validate_client_hello(std::span<const std::uint8_t> record,
                                  std::span<const crypto::HmacSha256Key* const> keys,
                                  std::int64_t now_unix, std::uint32_t skew_seconds,
                                  ClientHelloInfo& out, std::size_t& matched) {
  return validate_hello_core(
      record, now_unix, skew_seconds, out,
      [&](std::span<const std::uint8_t> input, const std::array<std::uint8_t, 32>& digest,
          std::array<std::uint8_t, 32>& canonical, std::array<std::uint8_t, 16>& secret) {
        for (std::size_t index = 0; index < keys.size(); ++index) {
          if (keys[index] == nullptr) continue;
          canonical = keys[index]->mac(input);
          if (!hmac_prefix_matches(digest, canonical)) continue;
          const auto key = keys[index]->key();
          std::copy(key.begin(), key.end(), secret.begin());
          matched = index;
          return true;
        }
        crypto::secure_zero(canonical);
        return false;
      });
}

std::optional<std::string> client_hello_sni(std::span<const std::uint8_t> record) {
  if (record.size() < 9 || record[0] != 0x16) return std::nullopt;
  if (record[5] != 0x01) return std::nullopt;  // handshake ClientHello
  const std::size_t hs_len = (static_cast<std::size_t>(record[6]) << 16) |
                             (static_cast<std::size_t>(record[7]) << 8) | record[8];
  const std::size_t end = std::min(record.size(), 9U + hs_len);
  std::size_t pos = 9;
  if (pos + 34 > end) return std::nullopt;  // legacy_version + random
  pos += 34;
  if (pos >= end) return std::nullopt;  // session id
  pos += 1 + record[pos];
  if (pos + 2 > end) return std::nullopt;  // cipher suites
  pos += 2 + be16(record, pos);
  if (pos >= end) return std::nullopt;  // compression methods
  pos += 1 + record[pos];
  if (pos + 2 > end) return std::nullopt;  // extensions length
  const std::size_t ext_end = std::min(end, pos + 2 + be16(record, pos));
  pos += 2;
  while (pos + 4 <= ext_end) {
    const std::uint16_t type = be16(record, pos);
    const std::size_t len = be16(record, pos + 2);
    pos += 4;
    if (pos + len > ext_end) return std::nullopt;
    if (type == 0x0000 && len >= 5) {  // server_name
      std::size_t np = pos + 2;        // server_name_list length
      const std::size_t names_end = pos + len;
      while (np + 3 <= names_end) {
        const std::uint8_t name_type = record[np];
        const std::size_t name_len = be16(record, np + 1);
        np += 3;
        if (np + name_len > names_end) return std::nullopt;
        if (name_type == 0 && name_len > 0) {
          if (std::find(record.begin() + static_cast<std::ptrdiff_t>(np),
                        record.begin() + static_cast<std::ptrdiff_t>(np + name_len), 0) !=
              record.begin() + static_cast<std::ptrdiff_t>(np + name_len)) {
            return std::nullopt;
          }
          std::string name(reinterpret_cast<const char*>(record.data() + np), name_len);
          for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          return name;
        }
        np += name_len;
      }
      return std::nullopt;
    }
    pos += len;
  }
  return std::nullopt;
}

std::vector<std::uint8_t> build_server_hello(const ClientHelloInfo& info, const RandomFn& random) {
  if (!random) throw std::invalid_argument("build_server_hello requires a random source");
  const bool pq = info.offers_pq;
  const std::size_t sh_record = pq ? 95 + kPqServerKeyShare : 127;
  const std::size_t out_len = sh_record + 6 + 5 + kFakeCertSize;
  Bytes out(out_len, 0);

  out[0] = 0x16;
  out[1] = 0x03;
  out[2] = 0x03;
  wr16(out, 3, static_cast<std::uint16_t>(sh_record - 5));
  out[5] = 0x02;
  wr24(out, 6, static_cast<std::uint32_t>(sh_record - 9));
  out[9] = 0x03;
  out[10] = 0x03;
  // out[11..43] is the zeroed server-random / HMAC placeholder.
  out[43] = 32;
  std::copy(info.session_id.begin(), info.session_id.end(), out.begin() + 44);
  wr16(out, 76, info.cipher);
  out[78] = 0;

  if (!pq) {
    wr16(out, 79, 46);
    const std::uint8_t supported_versions[6] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    std::copy_n(supported_versions, 6, out.begin() + 81);
    const std::uint8_t key_share[8] = {0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
    std::copy_n(key_share, 8, out.begin() + 87);
    std::span<std::uint8_t> key(out.data() + 95, 32);
    random(key);
  } else {
    wr16(out, 79, static_cast<std::uint16_t>(6 + 4 + 4 + kPqServerKeyShare));
    const std::uint8_t supported_versions[6] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    std::copy_n(supported_versions, 6, out.begin() + 81);
    out[87] = 0x00;
    out[88] = 0x33;
    wr16(out, 89, static_cast<std::uint16_t>(4 + kPqServerKeyShare));
    wr16(out, 91, kPqGroup);
    wr16(out, 93, static_cast<std::uint16_t>(kPqServerKeyShare));
    std::span<std::uint8_t> key(out.data() + 95, kPqServerKeyShare);
    random(key);
  }

  const std::size_t ccs = sh_record;
  const std::uint8_t ccs_bytes[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
  std::copy_n(ccs_bytes, 6, out.begin() + static_cast<std::ptrdiff_t>(ccs));
  const std::size_t ad = ccs + 6;
  out[ad] = 0x17;
  out[ad + 1] = 0x03;
  out[ad + 2] = 0x03;
  wr16(out, ad + 3, static_cast<std::uint16_t>(kFakeCertSize));
  std::span<std::uint8_t> cert(out.data() + ad + 5, kFakeCertSize);
  random(cert);

  Bytes hmac_input;
  hmac_input.reserve(32 + out.size());
  hmac_input.insert(hmac_input.end(), info.digest.begin(), info.digest.end());
  append(hmac_input, out);
  const auto digest = crypto::hmac_sha256(info.secret, hmac_input);
  std::copy(digest.begin(), digest.end(), out.begin() + 11);
  crypto::secure_zero(hmac_input);
  return out;
}

ObfuscationStatus parse_obfuscation_handshake(std::span<const std::uint8_t> handshake,
                                              std::span<const std::uint8_t, 16> secret,
                                              ObfuscationParams& out) {
  out.wipe();
  if (handshake.size() < kObfuscationHandshakeSize) return ObfuscationStatus::NeedMoreData;
  const auto raw = handshake.first(kObfuscationHandshakeSize);
  if (reserved_nonce(raw)) return ObfuscationStatus::ReservedNonce;

  Bytes key_input;
  key_input.reserve(32 + 16);
  append(key_input, raw.subspan(8, 32));
  append(key_input, secret);
  auto dec_key = crypto::sha256(key_input);
  std::array<std::uint8_t, 16> dec_iv{};
  std::copy_n(raw.begin() + 40, 16, dec_iv.begin());
  crypto::secure_zero(key_input);

  Bytes plain(raw.begin(), raw.end());
  {
    crypto::AesCtr ctr(dec_key, dec_iv);
    ctr.apply(plain);
  }

  const std::uint32_t tag_u32 = rd32(plain, 56);
  const auto tag = proto_tag_from_u32(tag_u32);
  const auto dc = static_cast<std::int16_t>(static_cast<std::uint16_t>(plain[60]) |
                                            (static_cast<std::uint16_t>(plain[61]) << 8));
  crypto::secure_zero(plain);

  if (!tag) {
    crypto::secure_zero(dec_key);
    return ObfuscationStatus::Invalid;
  }
  if (*tag == ProtoTag::Abridged) {
    crypto::secure_zero(dec_key);
    return ObfuscationStatus::UnsupportedTag;
  }
  if (dc == 0) {
    crypto::secure_zero(dec_key);
    return ObfuscationStatus::Invalid;
  }

  // Encrypt direction uses raw[8..56] reversed.
  Bytes reversed;
  reversed.reserve(48);
  for (int i = 55; i >= 8; --i) reversed.push_back(raw[static_cast<std::size_t>(i)]);
  Bytes enc_input;
  enc_input.reserve(48);
  append(enc_input, std::span<const std::uint8_t>(reversed).first(32));
  append(enc_input, secret);
  auto enc_key = crypto::sha256(enc_input);
  std::array<std::uint8_t, 16> enc_iv{};
  std::copy_n(reversed.begin() + 32, 16, enc_iv.begin());
  crypto::secure_zero(reversed);
  crypto::secure_zero(enc_input);

  out.decrypt_key = dec_key;
  out.decrypt_iv = dec_iv;
  out.encrypt_key = enc_key;
  out.encrypt_iv = enc_iv;
  out.tag = *tag;
  out.dc_id = dc;
  crypto::secure_zero(dec_key);
  crypto::secure_zero(enc_key);
  return ObfuscationStatus::Ok;
}

std::array<std::uint8_t, 32> obfuscation_replay_key(std::span<const std::uint8_t> handshake) {
  if (handshake.size() < 56) throw std::invalid_argument("obfuscation handshake too short");
  return crypto::sha256(handshake.subspan(8, 48));
}

constexpr std::size_t kTlsHeaderSize = 5;

struct FakeTlsConnection::Impl {
  Config cfg;
  FakeTlsConnection::State state{FakeTlsConnection::State::ClientHello};
  std::string error;
  Bytes tls_wire;
  Bytes stream;
  std::unique_ptr<crypto::AesCtr> decryptor;
  std::unique_ptr<crypto::AesCtr> encryptor;
  ObfuscationParams obf;
  ClientHelloInfo hello;
  std::array<std::uint8_t, 32> replay{};

  ~Impl() {
    crypto::secure_zero(cfg.secret);
    crypto::secure_zero(tls_wire);
    crypto::secure_zero(stream);
  }

  Status fail(std::string msg) {
    error = std::move(msg);
    state = State::Failed;
    crypto::secure_zero(cfg.secret);
    return Status::ProtocolError;
  }

  // Consume every complete TLS record currently buffered. The caller bounds the
  // *residue* after this returns, so a recv() batch can contain many records.
  Status consume_tls_records(bool& progress, std::vector<std::uint8_t>& to_client) {
    std::size_t pos = 0;
    while (tls_wire.size() - pos >= kTlsHeaderSize) {
      const std::uint8_t type = tls_wire[pos];
      if (!is_tls_version(std::span<const std::uint8_t>(tls_wire).subspan(pos, 3))) {
        return fail("bad TLS record version");
      }
      const std::size_t len = be16(tls_wire, pos + 3);
      if (len == 0 || len > cfg.max_record_body) return fail("bad TLS record length");
      if (tls_wire.size() - pos < kTlsHeaderSize + len) break;

      const auto record = std::span<const std::uint8_t>(tls_wire).subspan(pos, kTlsHeaderSize + len);
      if (state == State::ClientHello) {
        if (type != 0x16) return fail("expected TLS ClientHello");
        if (len > cfg.max_client_hello) return fail("ClientHello too large");
        const auto hs = validate_client_hello(record, cfg.secret, cfg.clock(),
                                               cfg.skew_seconds, hello);
        if (hs == HelloStatus::ClockSkew) return fail("ClientHello clock skew");
        if (hs == HelloStatus::Unauthenticated) return fail("ClientHello authentication failed");
        if (hs != HelloStatus::Ok) return fail("invalid ClientHello");
        if (cfg.expected_server_name &&
            !ascii_iequals(hello.server_name, *cfg.expected_server_name)) {
          return fail("ClientHello SNI mismatch");
        }
        auto server_hello = build_server_hello(hello, cfg.random);
        append(to_client, server_hello);
        state = State::Obfuscation;
        progress = true;
      } else if (type == 0x15) {
        pos += kTlsHeaderSize + len;
        state = State::Closed;
        if (pos) tls_wire.erase(tls_wire.begin(), tls_wire.begin() + static_cast<std::ptrdiff_t>(pos));
        release_if_large(tls_wire);
        return Status::Closed;
      } else if (type == 0x14) {
        // ChangeCipherSpec body is discarded.
      } else if (type == 0x17) {
        if (stream.size() + len > cfg.max_pending_plaintext + kObfuscationHandshakeSize) {
          return fail("TLS plaintext buffering limit exceeded");
        }
        append(stream, record.subspan(kTlsHeaderSize));
      } else {
        return fail("unexpected TLS record type");
      }
      pos += kTlsHeaderSize + len;
    }
    if (pos) tls_wire.erase(tls_wire.begin(), tls_wire.begin() + static_cast<std::ptrdiff_t>(pos));
    release_if_large(tls_wire);
    return Status::Ok;
  }
};

FakeTlsConnection::FakeTlsConnection(Config config) {
  struct ConfigCleaner {
    Config& cfg;
    ~ConfigCleaner() { crypto::secure_zero(cfg.secret); }
  } cleaner{config};
  if (!config.random) throw std::invalid_argument("FakeTlsConnection requires a random source");
  if (!config.clock) config.clock = &system_now;
  impl_ = std::make_unique<Impl>();
  impl_->cfg = std::move(config);
}

FakeTlsConnection::~FakeTlsConnection() = default;
FakeTlsConnection::FakeTlsConnection(FakeTlsConnection&&) noexcept = default;
FakeTlsConnection& FakeTlsConnection::operator=(FakeTlsConnection&&) noexcept = default;

Status FakeTlsConnection::feed(std::span<const std::uint8_t> wire,
                               std::vector<std::uint8_t>& to_client,
                               std::vector<std::uint8_t>& plaintext_out) {
  auto& s = *impl_;
  if (s.state == State::Failed) return Status::ProtocolError;
  if (s.state == State::Closed) return Status::Closed;

  // Feed arbitrarily large recv() batches in bounded internal chunks. The
  // aggregate check is on the unconsumed residue after complete records are
  // parsed, never on the caller's input span.
  constexpr std::size_t kChunk = 16 * 1024;
  const std::size_t residue_limit =
      s.cfg.max_client_hello + s.cfg.max_record_body + kTlsHeaderSize;
  bool progress = false;
  for (std::size_t off = 0; off < wire.size(); off += kChunk) {
    append(s.tls_wire, wire.subspan(off, std::min(kChunk, wire.size() - off)));
    const Status st = s.consume_tls_records(progress, to_client);
    if (st != Status::Ok) return st;
    if (s.tls_wire.size() > residue_limit) {
      return s.fail("TLS record buffering limit exceeded");
    }
    release_if_large(s.tls_wire);
  }

  if (s.state == State::Obfuscation && s.stream.size() >= kObfuscationHandshakeSize) {
    ObfuscationParams params;
    const auto st = parse_obfuscation_handshake(
        std::span<const std::uint8_t>(s.stream).first(kObfuscationHandshakeSize), s.cfg.secret, params);
    if (st == ObfuscationStatus::Ok) {
      if (params.tag != ProtoTag::Secure) {
        return s.fail("unsupported transport tag: only secure/padded-intermediate is served over FakeTLS");
      }
      s.replay = obfuscation_replay_key(
          std::span<const std::uint8_t>(s.stream).first(kObfuscationHandshakeSize));
      s.decryptor = std::make_unique<crypto::AesCtr>(params.decrypt_key, params.decrypt_iv);
      s.decryptor->skip(kObfuscationHandshakeSize);
      s.encryptor = std::make_unique<crypto::AesCtr>(params.encrypt_key, params.encrypt_iv);
      s.obf = std::move(params);
      s.stream.erase(s.stream.begin(), s.stream.begin() + static_cast<std::ptrdiff_t>(kObfuscationHandshakeSize));
      s.state = State::Ready;
      progress = true;
    } else if (st != ObfuscationStatus::NeedMoreData) {
      return s.fail(st == ObfuscationStatus::UnsupportedTag ? "unsupported transport tag"
                                                            : "invalid obfuscation handshake");
    }
  }

  if (s.state == State::Ready && !s.stream.empty()) {
    if (plaintext_out.size() + s.stream.size() > s.cfg.max_pending_plaintext) {
      return s.fail("plaintext output limit exceeded");
    }
    s.decryptor->apply(s.stream);
    append(plaintext_out, s.stream);
    s.stream.clear();
    release_if_large(s.stream);
    progress = true;
  }

  return progress ? Status::Ok : Status::NeedMoreData;
}

Status FakeTlsConnection::send(std::span<const std::uint8_t> plaintext,
                               std::vector<std::uint8_t>& to_client, std::size_t* open_record) {
  auto& s = *impl_;
  if (s.state != State::Ready) return Status::ProtocolError;
  constexpr std::size_t kMaxBody = 16384;
  const std::size_t records = plaintext.size() / kMaxBody + (plaintext.size() % kMaxBody != 0);
  const std::size_t available = to_client.max_size() - to_client.size();
  if (plaintext.size() > available || records > (available - plaintext.size()) / kTlsHeaderSize) {
    throw std::length_error("FakeTLS output too large");
  }
  // Normally the input is a separate worker frame buffer. Preserve aliased input
  // before reserve/append can invalidate it; the hot non-aliasing path allocates
  // only when the caller's output capacity actually needs to grow.
  Bytes alias_copy;
  const std::less<const std::uint8_t*> before;
  if (!plaintext.empty() && !to_client.empty() &&
      before(plaintext.data(), to_client.data() + to_client.size()) &&
      before(to_client.data(), plaintext.data() + plaintext.size())) {
    alias_copy.assign(plaintext.begin(), plaintext.end());
    plaintext = alias_copy;
  }
  to_client.reserve(to_client.size() + plaintext.size() + records * kTlsHeaderSize);
  std::size_t off = 0;
  if (const std::size_t room = open_record_room(to_client, open_record, kMaxBody);
      room != 0 && !plaintext.empty()) {
    const std::size_t n = std::min(room, plaintext.size());
    const std::size_t body_offset = to_client.size();
    append(to_client, plaintext.first(n));
    s.encryptor->apply(std::span<std::uint8_t>(to_client).subspan(body_offset, n));
    grow_open_record(to_client, *open_record, n);
    off = n;
  }
  while (off < plaintext.size()) {
    const std::size_t n = std::min(kMaxBody, plaintext.size() - off);
    if (open_record) *open_record = to_client.size();
    to_client.push_back(0x17);
    to_client.push_back(0x03);
    to_client.push_back(0x03);
    to_client.push_back(static_cast<std::uint8_t>(n >> 8));
    to_client.push_back(static_cast<std::uint8_t>(n));
    const std::size_t body_offset = to_client.size();
    append(to_client, plaintext.subspan(off, n));
    s.encryptor->apply(std::span<std::uint8_t>(to_client).subspan(body_offset, n));
    off += n;
  }
  return Status::Ok;
}

Status FakeTlsConnection::send_transport_message(ProtoTag tag,
                                                 std::span<const std::uint8_t> payload,
                                                 std::vector<std::uint8_t>& to_client,
                                                 const RandomFn& random,
                                                 std::size_t* open_record) {
  auto& s = *impl_;
  // Same validation order and messages as encode_transport_message() + send().
  if (tag == ProtoTag::Abridged) throw std::invalid_argument("abridged transport is not supported");
  if (payload.empty() || payload.size() % 4 != 0) {
    throw std::invalid_argument("transport payload must be non-empty and 4-byte aligned");
  }
  if (s.state != State::Ready) return Status::ProtocolError;

  std::size_t padding = 0;
  std::array<std::uint8_t, 3> pad{};
  if (tag == ProtoTag::Secure && random) {
    std::uint8_t r = 0;
    random(std::span<std::uint8_t>(&r, 1));
    padding = r % 4;
    if (padding) random(std::span<std::uint8_t>(pad).first(padding));
  }

  // Preserve aliased input before reserve/append can invalidate it (same guard
  // as send()); the runtime passes an unrelated ME buffer on the hot path.
  Bytes alias_copy;
  const std::less<const std::uint8_t*> before;
  if (!to_client.empty() && before(payload.data(), to_client.data() + to_client.size()) &&
      before(to_client.data(), payload.data() + payload.size())) {
    alias_copy.assign(payload.begin(), payload.end());
    payload = alias_copy;
  }

  const std::size_t frame_size = 4 + payload.size() + padding;
  constexpr std::size_t kMaxBody = 16384;
  const std::size_t records = frame_size / kMaxBody + (frame_size % kMaxBody != 0);
  const std::size_t available = to_client.max_size() - to_client.size();
  if (frame_size > available || records > (available - frame_size) / kTlsHeaderSize) {
    throw std::length_error("FakeTLS output too large");
  }
  to_client.reserve(to_client.size() + frame_size + records * kTlsHeaderSize);

  // The intermediate transport frame is [u32 len][payload][padding]; copy any
  // slice of that virtual frame into a TLS record body without materializing it.
  const std::array<std::uint8_t, 4> length_bytes{
      static_cast<std::uint8_t>(payload.size() + padding),
      static_cast<std::uint8_t>((payload.size() + padding) >> 8),
      static_cast<std::uint8_t>((payload.size() + padding) >> 16),
      static_cast<std::uint8_t>((payload.size() + padding) >> 24)};
  const auto append_frame_range = [&](std::size_t begin, std::size_t count) {
    const std::size_t len_end = length_bytes.size();
    const std::size_t payload_end = len_end + payload.size();
    const std::size_t frame_end = payload_end + padding;
    std::size_t pos = begin;
    while (count != 0 && pos < frame_end) {
      if (pos < len_end) {
        const std::size_t take = std::min(count, len_end - pos);
        to_client.insert(to_client.end(),
                         length_bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                         length_bytes.begin() + static_cast<std::ptrdiff_t>(pos + take));
        pos += take;
        count -= take;
      } else if (pos < payload_end) {
        const std::size_t payload_pos = pos - len_end;
        const std::size_t take = std::min(count, payload_end - pos);
        to_client.insert(to_client.end(),
                         payload.begin() + static_cast<std::ptrdiff_t>(payload_pos),
                         payload.begin() + static_cast<std::ptrdiff_t>(payload_pos + take));
        pos += take;
        count -= take;
      } else {
        const std::size_t pad_pos = pos - payload_end;
        to_client.insert(to_client.end(), pad.begin() + static_cast<std::ptrdiff_t>(pad_pos),
                         pad.begin() + static_cast<std::ptrdiff_t>(pad_pos + count));
        pos += count;
        count = 0;
      }
    }
  };

  std::size_t off = 0;
  if (const std::size_t room = open_record_room(to_client, open_record, kMaxBody); room != 0) {
    const std::size_t n = std::min(room, frame_size);
    const std::size_t body_offset = to_client.size();
    append_frame_range(0, n);
    s.encryptor->apply(std::span<std::uint8_t>(to_client).subspan(body_offset, n));
    grow_open_record(to_client, *open_record, n);
    off = n;
  }
  while (off < frame_size) {
    const std::size_t n = std::min(kMaxBody, frame_size - off);
    if (open_record) *open_record = to_client.size();
    to_client.push_back(0x17);
    to_client.push_back(0x03);
    to_client.push_back(0x03);
    to_client.push_back(static_cast<std::uint8_t>(n >> 8));
    to_client.push_back(static_cast<std::uint8_t>(n));
    const std::size_t body_offset = to_client.size();
    append_frame_range(off, n);
    s.encryptor->apply(std::span<std::uint8_t>(to_client).subspan(body_offset, n));
    off += n;
  }
  return Status::Ok;
}

FakeTlsConnection::State FakeTlsConnection::state() const { return impl_->state; }
ProtoTag FakeTlsConnection::proto_tag() const { return impl_->obf.tag; }
std::int16_t FakeTlsConnection::dc_id() const { return impl_->obf.dc_id; }
const ClientHelloInfo& FakeTlsConnection::client_hello() const { return impl_->hello; }
std::array<std::uint8_t, 32> FakeTlsConnection::replay_key() const { return impl_->replay; }
std::string_view FakeTlsConnection::error() const { return impl_->error; }
void FakeTlsConnection::release_idle() {
  if (!impl_) return;
  if (impl_->tls_wire.empty()) {
    impl_->tls_wire.clear();
    if (impl_->tls_wire.capacity() != 0) Bytes().swap(impl_->tls_wire);
  }
  if (impl_->stream.empty()) {
    impl_->stream.clear();
    if (impl_->stream.capacity() != 0) Bytes().swap(impl_->stream);
  }
}

std::size_t FakeTlsConnection::retained_bytes() const {
  if (!impl_) return 0;
  return impl_->tls_wire.capacity() + impl_->stream.capacity();
}

}  // namespace mtdd::protocol

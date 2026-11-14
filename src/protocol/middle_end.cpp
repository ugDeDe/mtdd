#include "mtdd/protocol.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>
#include <utility>

namespace mtdd::protocol {
namespace {

constexpr std::uint32_t kRpcNonce = 0x7acb87aa;
constexpr std::uint32_t kRpcHandshake = 0x7682eef5;
constexpr std::uint32_t kRpcHandshakeError = 0x6a27beda;
constexpr std::uint32_t kRpcPing = 0x5730a2df;
constexpr std::uint32_t kRpcPong = 0x8430eaa7;
constexpr std::uint32_t kRpcProxyReq = 0x36cef1ee;
constexpr std::uint32_t kRpcProxyAns = 0x4403da0d;
constexpr std::uint32_t kRpcSimpleAck = 0x3bac409b;
constexpr std::uint32_t kRpcCloseConn = 0x1fcf425d;
constexpr std::uint32_t kRpcCloseExt = 0x5eb634a2;
constexpr std::uint32_t kTlProxyTag = 0xdb1e26ae;

// Optional RPC_HANDSHAKE crypto flag: frames after the handshake answer use
// CRC-32C (Castagnoli) instead of IEEE CRC-32.
constexpr std::uint32_t kRpcFlagUseCrc32c = 0x00000800;
// Bits this implementation understands in an ME handshake answer. Unknown high
// bits are ignored and counted; see
// kHandshakeRejectedFlags for the bits that are still fatal.
constexpr std::uint32_t kKnownHandshakeFlags = kRpcFlagUseCrc32c;
// Reject unknown low-byte flags but allow unknown high bits, which may be
// introduced by the peer without requiring a transport shutdown.
constexpr std::uint32_t kHandshakeRejectedFlags = 0x000000ff;

constexpr std::uint32_t kFlagNotEncrypted = 0x00000002;
constexpr std::uint32_t kFlagHasAdTag = 0x00000008;
constexpr std::uint32_t kFlagMagic = 0x00001000;
constexpr std::uint32_t kFlagExtMode2 = 0x00020000;
constexpr std::uint32_t kFlagPad = 0x08000000;
constexpr std::uint32_t kFlagIntermediate = 0x20000000;
constexpr std::uint32_t kFlagQuickAck = 0x80000000;

using ProcessId = std::array<std::uint8_t, 12>;

// CRC mode negotiated by RPC_HANDSHAKE. The nonce exchange and the handshake
// frames themselves always use IEEE CRC-32; only frames after the handshake
// answer switch to the negotiated mode.
enum class ChecksumMode { Crc32, Crc32c };

std::uint32_t rpc_crc(ChecksumMode mode, std::span<const std::uint8_t> data) {
  return mode == ChecksumMode::Crc32c ? crypto::crc32c(data) : crypto::crc32(data);
}

// Telegram's struct process_id is 12 bytes: IPv4, u16 port, u16 pid, u32 utime.
// IPv4 is carried as a host-order u32, i.e. the wire octets are reversed,
// using the same convention as the KDF (`kdf_ipv4`). IPv6 endpoints carry a
// zero IPv4 field;
// the transport address stays in RPC_PROXY_REQ.
ProcessId make_process_id(const Endpoint& endpoint, std::uint16_t pid, std::uint32_t utime) {
  ProcessId out{};
  if (!endpoint.ipv6) {
    out[0] = endpoint.address[3];
    out[1] = endpoint.address[2];
    out[2] = endpoint.address[1];
    out[3] = endpoint.address[0];
  }
  out[4] = static_cast<std::uint8_t>(endpoint.port);
  out[5] = static_cast<std::uint8_t>(endpoint.port >> 8);
  out[6] = static_cast<std::uint8_t>(pid);
  out[7] = static_cast<std::uint8_t>(pid >> 8);
  out[8] = static_cast<std::uint8_t>(utime);
  out[9] = static_cast<std::uint8_t>(utime >> 8);
  out[10] = static_cast<std::uint8_t>(utime >> 16);
  out[11] = static_cast<std::uint8_t>(utime >> 24);
  return out;
}

std::uint32_t rd32(std::span<const std::uint8_t> b, std::size_t off = 0) {
  return static_cast<std::uint32_t>(b[off]) |
         (static_cast<std::uint32_t>(b[off + 1]) << 8) |
         (static_cast<std::uint32_t>(b[off + 2]) << 16) |
         (static_cast<std::uint32_t>(b[off + 3]) << 24);
}
void put32(Bytes& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 24));
}
void append(Bytes& out, std::span<const std::uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); }

// Detaches a payload that aliases the destination vector: `reserve()` and
// `insert()` may reallocate `out`, freeing the block the span points into.
// Callers must use the returned span and must not touch `out` before it. Same
// guard as FakeTlsConnection::send()/send_transport_message(); the non-aliasing
// hot path only compares pointers and allocates nothing.
std::span<const std::uint8_t> detach_aliased(std::span<const std::uint8_t> payload,
                                             const Bytes& out, Bytes& alias_copy) {
  if (payload.empty() || out.empty()) return payload;
  const std::less<const std::uint8_t*> before;
  if (before(payload.data(), out.data() + out.size()) &&
      before(out.data(), payload.data() + payload.size())) {
    alias_copy.assign(payload.begin(), payload.end());
    return alias_copy;
  }
  return payload;
}

std::int32_t next_seq(std::int32_t seq) {
  return static_cast<std::int32_t>(static_cast<std::uint32_t>(seq) + 1u);
}

std::int64_t system_now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void release_if_large(Bytes& b) {
  if (b.capacity() > 64u * 1024u && b.empty()) Bytes().swap(b);
}

std::size_t add_sat(std::size_t a, std::size_t b) {
  const std::size_t max = std::numeric_limits<std::size_t>::max();
  return (a > max - b) ? max : a + b;
}

std::size_t transient_limit(std::size_t max_frame) {
  const std::size_t doubled = add_sat(max_frame, 64u);
  const std::size_t max = std::numeric_limits<std::size_t>::max();
  return doubled > max / 2 ? max : doubled * 2;
}

Bytes make_plain_frame(std::int32_t seq, std::span<const std::uint8_t> payload,
                       std::size_t max_frame) {
  const std::size_t total = payload.size() + 12;
  if (total > max_frame) throw std::invalid_argument("ME frame exceeds limit");
  Bytes f;
  f.reserve(total);
  put32(f, static_cast<std::uint32_t>(total));
  put32(f, static_cast<std::uint32_t>(seq));
  append(f, payload);
  put32(f, crypto::crc32(f));
  return f;
}

}  // namespace

struct MiddleEndSession::Impl {
  MiddleEndConfig cfg;
  std::unique_ptr<Sink> sink;
  State state{State::Nonce};
  std::string error;

  ConnId conn{};
  std::array<std::uint8_t, 16> nonce_client{};
  std::array<std::uint8_t, 16> nonce_server{};
  std::uint32_t nonce_ts{0};
  bool started{false};

  std::int32_t write_seq{-2};
  std::int32_t read_seq{-2};

  std::unique_ptr<MiddleProxyKeys> keys;
  std::unique_ptr<crypto::AesCbc> encryptor;
  std::unique_ptr<crypto::AesCbc> decryptor;

  // Exact sender_pid sent in RPC_HANDSHAKE. The ME echo in peer_pid is checked
  // against these bytes; the placeholder constant mtdd used before was neither
  // an IP, nor a port, nor a process identity.
  ProcessId sender_pid{};
  ProcessId peer_pid{};
  std::uint16_t process_id{0};
  std::uint32_t process_time{0};

  // Monotonic inbound control-constructor counters (session lifetime).
  ControlCounters control{};
  // Raw flags of the last RPC_HANDSHAKE answer (0 before one is parsed);
  // observable even when the answer is rejected.
  std::uint32_t handshake_flags{0};

  Bytes nonce_wire;   // plaintext RPC_NONCE exchange only
  Bytes cipher_wire;  // encrypted bytes waiting for a 16-byte block (< 16 bytes)
  Bytes plaintext;    // decrypted RPC frames; consumed prefix tracked by offset
  std::size_t plaintext_pos{0};  // read offset into plaintext (avoids per-call erase)
  ChecksumMode crc_mode{ChecksumMode::Crc32};

  ~Impl() {
    crypto::secure_zero(cfg.secret);
    crypto::secure_zero(nonce_wire);
    crypto::secure_zero(cipher_wire);
    crypto::secure_zero(plaintext);
  }

  Status fail(std::string msg) {
    error = std::move(msg);
    state = State::Failed;
    return Status::ProtocolError;
  }

  // A local request validation error must not poison a shared ME connection.
  Status local_error(std::string msg) {
    error = std::move(msg);
    return Status::ProtocolError;
  }

  Bytes handshake_payload() const {
    Bytes p;
    p.reserve(32);
    put32(p, kRpcHandshake);
    // Advertise the only optional crypto mode we implement. A peer that does
    // not understand the flag answers with 0 and stays on IEEE CRC-32.
    put32(p, kRpcFlagUseCrc32c);
    p.insert(p.end(), sender_pid.begin(), sender_pid.end());
    p.insert(p.end(), peer_pid.begin(), peer_pid.end());
    return p;
  }

  // Encrypts one RPC payload with the continuous write CBC stream and advances
  // the write sequence. Encodes the whole frame directly into the caller's
  // output vector (no intermediate rpc/frame copies): header, sequence, payload,
  // CRC and padding are appended first, then only that tail is encrypted in
  // place. The sequence advances only on success, so a failed append cannot
  // leave a gap in the ME RPC stream.
  void append_encrypted(std::span<const std::uint8_t> payload, std::vector<std::uint8_t>& to_me) {
    Bytes alias_copy;
    payload = detach_aliased(payload, to_me, alias_copy);
    const std::size_t total = payload.size() + 12;  // len + seq + payload + crc
    const std::size_t padded = (total + 15u) & ~std::size_t{15};
    const std::size_t start = to_me.size();
    // Reserve before mutating: the appends below then cannot reallocate/throw.
    to_me.reserve(start + padded);
    put32(to_me, static_cast<std::uint32_t>(total));
    put32(to_me, static_cast<std::uint32_t>(write_seq));
    append(to_me, payload);
    put32(to_me, rpc_crc(crc_mode, std::span<const std::uint8_t>(to_me).subspan(start)));
    while (to_me.size() - start < padded) put32(to_me, 4);
    try {
      encryptor->encrypt(std::span<std::uint8_t>(to_me).subspan(start));
    } catch (...) {
      // An EVP failure leaves the continuous CBC stream in an undefined state:
      // the session is unrecoverable, so the caller fails it (defer_me_failure).
      // Wipe the half-written frame instead of leaving plaintext/RPC bytes in
      // the vector's slack before dropping it.
      crypto::secure_zero(std::span<std::uint8_t>(to_me).subspan(start));
      to_me.resize(start);
      throw;
    }
    write_seq = next_seq(write_seq);
  }

  // Drops the consumed prefix of `plaintext` only when it is worth a memmove.
  void compact_plaintext() {
    if (plaintext_pos == 0) return;
    if (plaintext_pos == plaintext.size()) {
      plaintext.clear();
      plaintext_pos = 0;
      return;
    }
    if (plaintext_pos > plaintext.size() / 2) {
      plaintext.erase(plaintext.begin(),
                      plaintext.begin() + static_cast<std::ptrdiff_t>(plaintext_pos));
      plaintext_pos = 0;
    }
  }

  // Decrypts aligned ciphertext into the tail of `plaintext`. The destination
  // vector grows once per batch; no temporary block buffer is allocated.
  Status append_cipher_blocks(std::span<const std::uint8_t> src) {
    if (src.empty()) return Status::Ok;
    const std::size_t limit = transient_limit(cfg.max_frame);
    const std::size_t base = plaintext.size() - plaintext_pos;
    if (base > limit || src.size() > limit - base) return fail("ME plaintext buffering limit");
    const std::size_t old = plaintext.size();
    plaintext.resize(old + src.size());
    try {
      decryptor->decrypt(src, std::span<std::uint8_t>(plaintext).subspan(old));
    } catch (...) {
      // Unrecoverable EVP failure: wipe the partially decrypted tail and let
      // the caller fail the shared session.
      crypto::secure_zero(std::span<std::uint8_t>(plaintext).subspan(old));
      plaintext.resize(old);
      throw;
    }
    return Status::Ok;
  }

  // Decrypts every complete 16-byte block currently available, taking full
  // blocks straight from `wire` when no partial block is buffered. Sets
  // `decrypted` when at least one block was appended to `plaintext`.
  Status decrypt_available(std::span<const std::uint8_t> wire, bool& decrypted) {
    const std::size_t buffered = cipher_wire.size() - cipher_wire.size() % 16;
    if (buffered != 0) {
      const Status st =
          append_cipher_blocks(std::span<const std::uint8_t>(cipher_wire).first(buffered));
      if (st != Status::Ok) return st;
      cipher_wire.erase(cipher_wire.begin(),
                        cipher_wire.begin() + static_cast<std::ptrdiff_t>(buffered));
      decrypted = true;
    }
    std::size_t off = 0;
    if (!cipher_wire.empty() && !wire.empty()) {
      // Complete the buffered partial block from the head of this batch.
      const std::size_t need = 16 - cipher_wire.size();
      const std::size_t take = std::min(need, wire.size());
      append(cipher_wire, wire.first(take));
      off = take;
      if (cipher_wire.size() == 16) {
        const Status st = append_cipher_blocks(cipher_wire);
        if (st != Status::Ok) return st;
        cipher_wire.clear();
        decrypted = true;
      }
    }
    const std::size_t direct = (wire.size() - off) / 16 * 16;
    if (direct != 0) {
      const Status st = append_cipher_blocks(wire.subspan(off, direct));
      if (st != Status::Ok) return st;
      off += direct;
      decrypted = true;
    }
    if (off < wire.size()) append(cipher_wire, wire.subspan(off));
    return Status::Ok;
  }

  Status process_nonce_frame(std::span<const std::uint8_t> frame,
                             std::vector<std::uint8_t>& to_me) {
    const std::size_t len = frame.size();
    if (crypto::crc32(frame.first(len - 4)) != rd32(frame, len - 4)) {
      return fail("ME CRC mismatch (nonce)");
    }
    if (static_cast<std::int32_t>(rd32(frame, 4)) != -2) {
      return fail("ME nonce answer seq mismatch");
    }
    const auto payload = frame.subspan(8, len - 12);
    if (payload.size() != 32) return fail("ME nonce answer length");
    if (rd32(payload, 0) != kRpcNonce) return fail("ME nonce answer type");
    const std::size_t sel = std::min<std::size_t>(4, cfg.secret.size());
    if (!std::equal(payload.begin() + 4, payload.begin() + 4 + static_cast<std::ptrdiff_t>(sel),
                    cfg.secret.begin()) ||
        !std::all_of(payload.begin() + 4 + static_cast<std::ptrdiff_t>(sel), payload.begin() + 8,
                     [](std::uint8_t b) { return b == 0; })) {
      return fail("ME key selector mismatch");
    }
    if (rd32(payload, 8) != 1) return fail("ME crypto schema");
    const std::int64_t ts_delta = static_cast<std::int64_t>(rd32(payload, 12)) -
                                  static_cast<std::int64_t>(nonce_ts);
    if (ts_delta > 30 || ts_delta < -30) return fail("ME nonce timestamp outside window");
    std::copy_n(payload.begin() + 16, 16, nonce_server.begin());

    MiddleProxyKdfInput in;
    in.nonce_server = nonce_server;
    in.nonce_client = nonce_client;
    in.client_timestamp = nonce_ts;
    in.server = cfg.server;
    in.local = cfg.local;
    in.secret = cfg.secret;
    try {
      keys = std::make_unique<MiddleProxyKeys>(derive_middle_proxy_keys(in));
    } catch (const std::exception& e) {
      return fail(std::string("ME key derivation failed: ") + e.what());
    }
    encryptor = std::make_unique<crypto::AesCbc>(keys->write_key, keys->write_iv);
    decryptor = std::make_unique<crypto::AesCbc>(keys->read_key, keys->read_iv);

    state = State::Handshake;
    write_seq = -1;
    read_seq = -1;
    // The handshake request is encrypted immediately, exactly like the reference
    // client after rpc_start_crypto. Its CBC stream continues into data frames.
    append_encrypted(handshake_payload(), to_me);
    return Status::Ok;
  }

  Status process_encrypted_frames(std::vector<std::uint8_t>& to_me) {
    compact_plaintext();
    std::size_t pos = plaintext_pos;
    while (plaintext.size() - pos >= 4) {
      const std::size_t len = rd32(plaintext, pos);
      if (len == 4) {
        pos += 4;
        continue;
      }
      if (len < 16 || len > cfg.max_frame || len % 4 != 0) {
        return fail("bad ME frame length");
      }
      if (plaintext.size() - pos < len) break;

      const auto frame = std::span<const std::uint8_t>(plaintext).subspan(pos, len);
      // The handshake answer still uses IEEE CRC-32; only later frames use the
      // negotiated mode.
      const ChecksumMode frame_mode =
          state == State::Handshake ? ChecksumMode::Crc32 : crc_mode;
      if (rpc_crc(frame_mode, frame.first(len - 4)) != rd32(frame, len - 4)) {
        return fail("ME CRC mismatch");
      }
      if (static_cast<std::int32_t>(rd32(frame, 4)) != read_seq) {
        return fail("ME seq mismatch");
      }
      read_seq = next_seq(read_seq);

      const auto payload = frame.subspan(8, len - 12);
      const std::uint32_t type = rd32(payload, 0);

      if (state == State::Handshake) {
        if (type == kRpcHandshakeError) {
          // RPC_HANDSHAKE_ERROR: type + i32 error_code. Surfacing the code makes
          // a PID/flag rejection distinguishable from a transport failure.
          const auto code = payload.size() >= 8
                                ? static_cast<std::int32_t>(rd32(payload, 4))
                                : std::int32_t{-1};
          return fail("ME rejected handshake (code " + std::to_string(code) + ")");
        }
        if (payload.size() != 32) return fail("ME handshake answer length");
        if (type != kRpcHandshake) return fail("ME handshake answer type");
        const std::uint32_t flags = rd32(payload, 4);
        handshake_flags = flags;
        if ((flags & kHandshakeRejectedFlags) != 0) {
          // Fail closed on low-byte flags with unknown crypto/schema meaning.
          return fail("ME handshake flags unsupported");
        }
        if ((flags & ~kKnownHandshakeFlags) != 0) {
          // Count unknown high bits while keeping the shared session alive.
          ++control.handshake_unknown_flags;
        }
        crc_mode = (flags & kRpcFlagUseCrc32c) != 0 ? ChecksumMode::Crc32c
                                                    : ChecksumMode::Crc32;
        // The ME echoes our sender_pid as peer_pid; verify the exact bytes we
        // generated instead of a placeholder constant.
        if (!std::equal(payload.begin() + 20, payload.begin() + 32, sender_pid.begin())) {
          return fail("ME handshake peer pid echo mismatch");
        }
        state = State::Ready;
        read_seq = 0;
        pos += len;
        continue;
      }

      if (type == kRpcProxyAns) {
        if (payload.size() < 16) return fail("short RPC_PROXY_ANS");
        ConnId cid{};
        std::copy_n(payload.begin() + 8, 8, cid.begin());
        try {
          sink->on_proxy_payload(cid, payload.subspan(16));
        } catch (...) {
          return fail("sink threw");
        }
      } else if (type == kRpcSimpleAck) {
        if (payload.size() != 16) return fail("short RPC_SIMPLE_ACK");
        ConnId cid{};
        std::copy_n(payload.begin() + 4, 8, cid.begin());
        std::array<std::uint8_t, 4> confirm{};
        std::copy_n(payload.begin() + 12, 4, confirm.begin());
        try {
          sink->on_quick_ack(cid, confirm);
        } catch (...) {
          return fail("sink threw");
        }
      } else if (type == kRpcCloseExt) {
        // Ignore trailing bytes; a short CLOSE_EXT cannot identify a connection.
        if (payload.size() < 12) return fail("short RPC_CLOSE_EXT");
        ++control.close_ext;
        ConnId cid{};
        std::copy_n(payload.begin() + 4, 8, cid.begin());
        // This closes ONE logical connection, not the shared ME transport.
        try {
          sink->on_remote_close(cid);
        } catch (...) {
          return fail("sink threw");
        }
      } else if (type == kRpcCloseConn) {
        // Telegram may close a logical connection with either constructor.
        if (payload.size() < 12) {
          // A newly recognized constructor must not be able to kill the shared
          // transport on a length we have never observed: count and ignore.
          ++control.malformed;
        } else {
          // Accept payloads of at least 12 bytes and ignore trailing bytes.
          ++control.close_conn;
          ConnId cid{};
          std::copy_n(payload.begin() + 4, 8, cid.begin());
          try {
            sink->on_remote_close(cid);
          } catch (...) {
            return fail("sink threw");
          }
        }
      } else if (type == kRpcPing) {
        if (payload.size() != 12) return fail("short RPC_PING");
        Bytes pong;
        put32(pong, kRpcPong);
        append(pong, payload.subspan(4, 8));
        append_encrypted(pong, to_me);
      } else if (type == kRpcPong) {
        if (payload.size() != 12) return fail("short RPC_PONG");
        // Echoed 8-byte little-endian ping id; surface it so the reactor can
        // correlate RTT and declare a connection dead after unanswered pings.
        std::uint64_t raw = 0;
        for (int i = 0; i < 8; ++i) {
          raw |= static_cast<std::uint64_t>(payload[4 + static_cast<std::size_t>(i)])
                 << (8 * i);
        }
        try {
          sink->on_pong(static_cast<std::int64_t>(raw));
        } catch (...) {
          return fail("sink threw");
        }
      } else {
        // Unknown RPC types are ignored for forward compatibility, but counted
        // so a live node can be classified instead of guessed.
        ++control.unknown;
      }
      pos += len;
    }
    plaintext_pos = pos;
    // Keep only the unconsumed residue; the consumed prefix is dropped at most
    // once per feed and only when it is at least half the buffer.
    compact_plaintext();
    release_if_large(plaintext);
    return Status::NeedMoreData;
  }
};

MiddleEndSession::MiddleEndSession(MiddleEndConfig config, std::unique_ptr<Sink> sink) {
  struct ConfigCleaner {
    MiddleEndConfig& cfg;
    ~ConfigCleaner() { crypto::secure_zero(cfg.secret); }
  } cleaner{config};
  if (!sink) throw std::invalid_argument("MiddleEndSession requires a sink");
  if (!config.random) throw std::invalid_argument("MiddleEndSession requires a random source");
  if (config.secret.size() < 4 || config.secret.size() > 392) {
    throw std::invalid_argument("ME secret must be 4..392 bytes");
  }
  if (config.server.port == 0 || config.local.port == 0) {
    throw std::invalid_argument("ME endpoints require non-zero ports");
  }
  if (config.advertised.port == 0) {
    throw std::invalid_argument("ME advertised listener endpoint requires a non-zero port");
  }
  if (config.server.ipv6 != config.local.ipv6) {
    throw std::invalid_argument("ME endpoints must use the same address family");
  }
  if (config.max_frame < 64) throw std::invalid_argument("ME max_frame is too small");
  // An all-zero ad tag means "no ad tag": the proxy runs without a sponsored
  // channel and RPC_PROXY_REQ omits the TL_PROXY_TAG block entirely (matches
  // telemt and the reference MTProxy no-tag frame).
  if (!config.clock) config.clock = &system_now;

  impl_ = std::make_unique<Impl>();
  impl_->cfg = std::move(config);
  impl_->sink = std::move(sink);
  impl_->cfg.random(std::span<std::uint8_t>(impl_->nonce_client));
  impl_->cfg.random(std::span<std::uint8_t>(impl_->conn));
  impl_->nonce_ts = static_cast<std::uint32_t>(impl_->cfg.clock());
  // Real process identity, not twelve ASCII placeholder bytes. Both values can
  // be pinned by the caller (tests, reproducible probes); otherwise derive them
  // from this process and the injected clock.
  // sender_pid describes the outbound ME socket (KDF tuple); `advertised` is
  // only our_addr in RPC_PROXY_REQ and must not enter the handshake identity.
  impl_->process_id = impl_->cfg.process_id != 0
                          ? impl_->cfg.process_id
                          : static_cast<std::uint16_t>(::getpid() & 0xffff);
  impl_->process_time = impl_->cfg.process_time != 0
                            ? impl_->cfg.process_time
                            : static_cast<std::uint32_t>(impl_->cfg.clock());
  impl_->sender_pid = make_process_id(impl_->cfg.local, impl_->process_id,
                                      impl_->process_time);
  impl_->peer_pid = make_process_id(impl_->cfg.server, 0, 0);
}

MiddleEndSession::~MiddleEndSession() = default;
MiddleEndSession::MiddleEndSession(MiddleEndSession&&) noexcept = default;
MiddleEndSession& MiddleEndSession::operator=(MiddleEndSession&&) noexcept = default;

std::vector<std::uint8_t> MiddleEndSession::start() {
  auto& s = *impl_;
  if (s.started || s.state != State::Nonce) throw std::logic_error("MiddleEndSession::start called twice");
  s.started = true;

  Bytes payload;
  payload.reserve(32);
  put32(payload, kRpcNonce);
  for (std::size_t i = 0; i < 4; ++i) {
    payload.push_back(i < s.cfg.secret.size() ? s.cfg.secret[i] : 0);
  }
  put32(payload, 1);  // RPC_CRYPTO_AES
  put32(payload, s.nonce_ts);
  append(payload, s.nonce_client);
  const auto frame = make_plain_frame(-2, payload, s.cfg.max_frame);
  s.write_seq = -1;
  return frame;
}

Status MiddleEndSession::feed(std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& to_me) {
  auto& s = *impl_;
  if (s.state == State::Failed) return Status::ProtocolError;
  if (s.state == State::Closed) return Status::Closed;
  if (!s.started) return s.fail("ME feed before start");
  s.error.clear();

  bool produced = false;
  const std::size_t out_before = to_me.size();
  const bool entered_nonce = s.state == State::Nonce;

  if (entered_nonce) {
    if (s.nonce_wire.size() + wire.size() > s.cfg.max_frame + 64) {
      return s.fail("ME nonce buffering limit");
    }
    append(s.nonce_wire, wire);
    std::size_t pos = 0;
    while (s.state == State::Nonce && s.nonce_wire.size() - pos >= 4) {
      const std::size_t len = rd32(s.nonce_wire, pos);
      if (len < 16 || len > s.cfg.max_frame || len % 4 != 0) {
        return s.fail("bad ME nonce frame length");
      }
      if (s.nonce_wire.size() - pos < len) break;
      const auto st = s.process_nonce_frame(
          std::span<const std::uint8_t>(s.nonce_wire).subspan(pos, len), to_me);
      if (st != Status::Ok) return st;
      pos += len;
      produced = true;
    }
    if (pos) s.nonce_wire.erase(s.nonce_wire.begin(),
                                s.nonce_wire.begin() + static_cast<std::ptrdiff_t>(pos));
    release_if_large(s.nonce_wire);
    if (s.state != State::Handshake) return produced ? Status::Ok : Status::NeedMoreData;
    // The answer may be pipelined with the encrypted handshake answer.
    if (!s.nonce_wire.empty()) {
      append(s.cipher_wire, s.nonce_wire);
      s.nonce_wire.clear();
      release_if_large(s.nonce_wire);
    }
  }

  // Handshake and Ready are both encrypted from the first handshake byte.
  // Ciphertext buffered from the nonce phase (pipelined handshake answer) counts
  // against the same transient budget as this batch; complete blocks are
  // decrypted straight into `plaintext`, so `cipher_wire` keeps only <16 bytes.
  const std::size_t limit = transient_limit(s.cfg.max_frame);
  const std::size_t pending =
      entered_nonce ? s.cipher_wire.size() : s.cipher_wire.size() + wire.size();
  if (pending > limit) return s.fail("ME ciphertext buffering limit");

  bool decrypted = false;
  const auto dst =
      s.decrypt_available(entered_nonce ? std::span<const std::uint8_t>() : wire, decrypted);
  if (dst != Status::Ok) return dst;
  if (entered_nonce) {
    // The pipelined handshake answer moved nonce_wire -> cipher_wire and is now
    // fully decrypted (complete blocks went straight into `plaintext`). Return
    // any large capacity the transient buffer still holds instead of keeping it
    // for the session lifetime; release_if_large() only acts on an empty vector.
    release_if_large(s.cipher_wire);
  }

  const State state_before = s.state;
  const Status st = s.process_encrypted_frames(to_me);
  if (st == Status::ProtocolError || st == Status::Closed) return st;
  // Only the unconsumed residue is bounded by the per-frame limit; a batch that
  // contained complete frames has already been demultiplexed above.
  if (s.plaintext.size() - s.plaintext_pos > add_sat(s.cfg.max_frame, 64u)) {
    return s.fail("ME plaintext buffering limit");
  }
  if (produced || decrypted || s.state != state_before || to_me.size() != out_before) {
    return Status::Ok;
  }
  return Status::NeedMoreData;
}

Status MiddleEndSession::encode_client_message(std::span<const std::uint8_t> payload,
                                               const Endpoint& peer, ProtoTag tag, bool quick_ack,
                                               std::vector<std::uint8_t>& to_me) {
  return encode_client_message(impl_->conn, payload, peer, tag, quick_ack, to_me);
}

Status MiddleEndSession::encode_client_message(const ConnId& conn_id,
                                               std::span<const std::uint8_t> payload,
                                               const Endpoint& peer, ProtoTag tag, bool quick_ack,
                                               std::vector<std::uint8_t>& to_me,
                                               const AdTag* ad_tag) {
  auto& s = *impl_;
  if (s.state != State::Ready) return Status::ProtocolError;
  if (payload.empty() || payload.size() % 4 != 0) {
    return s.local_error("client payload must be 4-byte aligned");
  }
  if (tag == ProtoTag::Abridged) return s.local_error("abridged transport is not supported");

  // A caller may pass a span into `to_me` (zero-copy forwarding). Preserve it
  // before reserve()/insert() can reallocate and free that storage; this must
  // run before the reserve below.
  Bytes alias_copy;
  payload = detach_aliased(payload, to_me, alias_copy);

  // A non-null, non-zero per-request tag (per-user) overrides the session tag;
  // otherwise the session tag is used. An all-zero result means "no ad tag":
  // the TL_PROXY_TAG block and its extra_size field are omitted and the
  // HAS_AD_TAG flag is cleared.
  const bool own_tag =
      ad_tag != nullptr && std::any_of(ad_tag->bytes.begin(), ad_tag->bytes.end(),
                                       [](std::uint8_t b) { return b != 0; });
  const AdTag& request_tag = own_tag ? *ad_tag : s.cfg.ad_tag;
  const bool has_tag = std::any_of(request_tag.bytes.begin(), request_tag.bytes.end(),
                                   [](std::uint8_t b) { return b != 0; });

  std::uint32_t flags = kFlagMagic | kFlagExtMode2;
  if (has_tag) flags |= kFlagHasAdTag;
  flags |= (tag == ProtoTag::Secure) ? (kFlagIntermediate | kFlagPad) : kFlagIntermediate;
  if (quick_ack) flags |= kFlagQuickAck;
  if (payload.size() >= 8 &&
      std::all_of(payload.begin(), payload.begin() + 8, [](std::uint8_t b) { return b == 0; })) {
    flags |= kFlagNotEncrypted;
  }

  // 56-byte header; with a tag, a 28-byte block (extra_size + TL_PROXY_TAG +
  // 16-byte tag + padding) follows. Without a tag the whole block, including
  // its extra_size field, is omitted.
  const std::size_t rpc_len = (has_tag ? 84 : 56) + payload.size();
  if (rpc_len + 12 > s.cfg.max_frame) {
    return s.local_error("client payload exceeds ME frame limit");
  }

  // Encode the ME frame straight into the caller's output vector. The previous
  // implementation built an `rpc` payload, copied it into `frame`, encrypted
  // `frame`, and copied that into `to_me`; the layered copies are gone and only
  // the appended tail is encrypted in place.
  const std::size_t total = rpc_len + 12;  // len + seq + rpc + crc
  const std::size_t padded = (total + 15u) & ~std::size_t{15};
  const std::size_t start = to_me.size();
  to_me.reserve(start + padded);
  put32(to_me, static_cast<std::uint32_t>(total));
  put32(to_me, static_cast<std::uint32_t>(s.write_seq));
  put32(to_me, kRpcProxyReq);
  put32(to_me, flags);
  to_me.insert(to_me.end(), conn_id.begin(), conn_id.end());
  const auto peer_wire = peer.wire20();
  append(to_me, peer_wire);
  const auto advertised_wire = s.cfg.advertised.wire20();
  append(to_me, advertised_wire);
  if (has_tag) {
    put32(to_me, 24);  // extra_size: TL_PROXY_TAG block
    put32(to_me, kTlProxyTag);
    to_me.push_back(16);  // TL string length
    to_me.insert(to_me.end(), request_tag.bytes.begin(), request_tag.bytes.end());
    to_me.insert(to_me.end(), {0, 0, 0});  // 4-byte alignment
  }
  append(to_me, payload);
  put32(to_me, rpc_crc(s.crc_mode, std::span<const std::uint8_t>(to_me).subspan(start)));
  while (to_me.size() - start < padded) put32(to_me, 4);
  try {
    s.encryptor->encrypt(std::span<std::uint8_t>(to_me).subspan(start));
  } catch (...) {
    // Unrecoverable EVP failure: wipe the half-written frame (header, payload,
    // CRC, padding) before dropping it; the caller fails the shared session.
    crypto::secure_zero(std::span<std::uint8_t>(to_me).subspan(start));
    to_me.resize(start);
    throw;
  }
  s.write_seq = next_seq(s.write_seq);
  return Status::Ok;
}

Status MiddleEndSession::encode_close(const ConnId& conn_id, std::vector<std::uint8_t>& to_me) {
  auto& s = *impl_;
  if (s.state != State::Ready) return Status::ProtocolError;
  s.error.clear();
  Bytes payload;
  put32(payload, kRpcCloseConn);
  payload.insert(payload.end(), conn_id.begin(), conn_id.end());
  s.append_encrypted(payload, to_me);
  return Status::Ok;
}

Status MiddleEndSession::encode_ping(std::int64_t ping_id, std::vector<std::uint8_t>& to_me) {
  auto& s = *impl_;
  if (s.state != State::Ready) return Status::ProtocolError;
  s.error.clear();
  Bytes payload;
  put32(payload, kRpcPing);
  const auto id = static_cast<std::uint64_t>(ping_id);
  for (int i = 0; i < 8; ++i) payload.push_back(static_cast<std::uint8_t>(id >> (8 * i)));
  s.append_encrypted(payload, to_me);
  return Status::Ok;
}

void MiddleEndSession::set_ad_tag(const AdTag& tag) {
  // An all-zero tag switches the session to no-tag; later RPC_PROXY_REQ frames
  // omit the TL_PROXY_TAG block.
  impl_->cfg.ad_tag = tag;
}

MiddleEndSession::State MiddleEndSession::state() const { return impl_->state; }
const MiddleEndSession::ControlCounters& MiddleEndSession::control_counters() const {
  return impl_->control;
}
std::uint32_t MiddleEndSession::handshake_flags() const { return impl_->handshake_flags; }
std::string_view MiddleEndSession::error() const { return impl_->error; }
const MiddleEndSession::ConnId& MiddleEndSession::conn_id() const { return impl_->conn; }
MiddleEndSession::Sink* MiddleEndSession::sink() const { return impl_->sink.get(); }
std::int32_t MiddleEndSession::write_seq() const { return impl_->write_seq; }
std::int32_t MiddleEndSession::read_seq() const { return impl_->read_seq; }
std::size_t MiddleEndSession::retained_bytes() const {
  if (!impl_) return 0;
  return impl_->nonce_wire.capacity() + impl_->cipher_wire.capacity() +
         impl_->plaintext.capacity();
}

}  // namespace mtdd::protocol

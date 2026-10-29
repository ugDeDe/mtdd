// mtdd protocol core: OpenSSL-backed crypto helpers, FakeTLS/obfuscation,
// MTProto transport framing, and the Telegram Middle-End (ME) RPC session.
//
// The module is self-contained: no sockets, threads, event loops, JSON, or control
// plane dependencies. It is driven by byte buffers:
//
//   client socket --> FakeTlsConnection --> TransportDecoder --> MiddleEndSession --> ME socket
//   ME socket     --> MiddleEndSession   --> TransportEncoder --> FakeTlsConnection --> client
//
// All wire parsers are incremental and fail closed with Status::ProtocolError.
// Configuration/library misuse throws std::invalid_argument. Key material is
// wiped with OPENSSL_cleanse in the owning object's destructor.
//

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace mtdd::protocol {

using Bytes = std::vector<std::uint8_t>;
using RandomFn = std::function<void(std::span<std::uint8_t>)>;
using ClockFn = std::function<std::int64_t()>;

// CSPRNG-backed random source (OpenSSL RAND_bytes) for production callers.
// Tests inject deterministic sources instead.
RandomFn system_random();
// Same CSPRNG, served from a private 16 KiB block refilled with one RAND_bytes
// call. OpenSSL's RAND_bytes checks getpid() for fork safety on every call
// (a real system call under musl); per-message padding asked for 1-3 bytes at
// a time and each handshake for ~3 KiB. Requests above 4 KiB bypass the block.
// Not thread-safe: give each reactor its own instance.
RandomFn buffered_random();

inline constexpr std::size_t kObfuscationHandshakeSize = 64;
inline constexpr std::size_t kFakeTlsMaxClientHello = 4096;
inline constexpr std::size_t kFakeTlsMaxRecordBody = 16384 + 256;
inline constexpr std::size_t kAdTagSize = 16;
inline constexpr std::size_t kMiddleEndDefaultMaxFrame = 1u << 24;
// X25519MLKEM768 key_share sizes: ML-KEM-768 public key 1184 + X25519 32 for
// the client offer, ML-KEM-768 ciphertext 1088 + X25519 32 for the server share.
inline constexpr std::size_t kPqClientKeyShare = 1216;
inline constexpr std::size_t kPqServerKeyShare = 1120;

// Result of an incremental operation. NeedMoreData never consumes an error.
enum class Status { Ok, NeedMoreData, Closed, ProtocolError };

enum class ProtoTag : std::uint32_t {
  Abridged = 0xefefefefu,
  Intermediate = 0xeeeeeeeeu,
  Secure = 0xdddddddd,  // padded intermediate (used by FakeTLS)
};

std::optional<ProtoTag> proto_tag_from_u32(std::uint32_t value);
std::string_view to_string(ProtoTag tag);

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

// IPv4 addresses are stored as the four wire-order octets in the first four
// bytes; IPv6 uses all 16 bytes. Ports are host byte order.
struct Endpoint {
  std::array<std::uint8_t, 16> address{};
  std::uint16_t port{0};
  bool ipv6{false};

  static Endpoint v4(std::array<std::uint8_t, 4> address, std::uint16_t port);
  static Endpoint v6(std::array<std::uint8_t, 16> address, std::uint16_t port);

  bool is_v6() const { return ipv6; }
  // 20-byte ME form: 16-byte IPv4-mapped/IPv6 address + little-endian u32 port.
  std::array<std::uint8_t, 20> wire20() const;

  friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

// ---------------------------------------------------------------------------
// Crypto helpers (OpenSSL EVP / EVP_MAC). Stable small surface for KAT tests.
// ---------------------------------------------------------------------------

namespace crypto {

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data);
std::array<std::uint8_t, 20> sha1(std::span<const std::uint8_t> data);
std::array<std::uint8_t, 16> md5(std::span<const std::uint8_t> data);
std::array<std::uint8_t, 32> hmac_sha256(std::span<const std::uint8_t> key,
                                        std::span<const std::uint8_t> data);
std::uint32_t crc32(std::span<const std::uint8_t> data);

// HMAC-SHA256 with a fixed 16-byte key whose inner/outer pad blocks are
// absorbed once. mac() only copies the two digest states, so checking one
// ClientHello against many user secrets costs two short hashes per secret
// instead of a full keyed HMAC setup. Byte-identical to hmac_sha256().
class HmacSha256Key {
 public:
  explicit HmacSha256Key(std::span<const std::uint8_t, 16> key);
  ~HmacSha256Key();
  HmacSha256Key(HmacSha256Key&&) noexcept;
  HmacSha256Key& operator=(HmacSha256Key&&) noexcept;
  HmacSha256Key(const HmacSha256Key&) = delete;
  HmacSha256Key& operator=(const HmacSha256Key&) = delete;

  std::array<std::uint8_t, 32> mac(std::span<const std::uint8_t> data) const;
  std::span<const std::uint8_t, 16> key() const noexcept { return key_; }

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  std::array<std::uint8_t, 16> key_{};
};

// Castagnoli CRC-32C (reflected polynomial 0x82F63B78), as negotiated by the ME
// RPC_HANDSHAKE flag USE_CRC32C. Uses SSE4.2 crc32 instructions when the CPU
// supports them (runtime CPUID check) and a slicing-by-8 fallback otherwise; the
// binary stays portable x86-64 because only this function is compiled for
// sse4.2, not the translation unit.
std::uint32_t crc32c(std::span<const std::uint8_t> data);
// Portable slicing-by-8 CRC-32C. Exposed so tests can cross-check the selected
// (possibly hardware) path against it on the same machine; production code
// should call crc32c().
std::uint32_t crc32c_portable(std::span<const std::uint8_t> data);
bool constant_time_equal(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b);
void secure_zero(std::span<std::uint8_t> data);
void secure_zero(void* data, std::size_t size);

// AES-256-CTR with a continuous big-endian counter. Move-only.
class AesCtr {
 public:
  AesCtr(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv);
  ~AesCtr();
  AesCtr(AesCtr&&) noexcept;
  AesCtr& operator=(AesCtr&&) noexcept;
  AesCtr(const AesCtr&) = delete;
  AesCtr& operator=(const AesCtr&) = delete;

  void apply(std::span<std::uint8_t> data);  // XOR in place, advancing the stream
  void skip(std::size_t bytes);
  void wipe();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// AES-256-CBC without padding. The IV is carried across calls, so a single
// object models one continuous CBC stream (as used by ME RPC framing).
class AesCbc {
 public:
  AesCbc(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv);
  ~AesCbc();
  AesCbc(AesCbc&&) noexcept;
  AesCbc& operator=(AesCbc&&) noexcept;
  AesCbc(const AesCbc&) = delete;
  AesCbc& operator=(const AesCbc&) = delete;

  void encrypt(std::span<std::uint8_t> data);  // data.size() % 16 == 0
  void decrypt(std::span<std::uint8_t> data);
  // Decrypts src into dst (both 16-byte aligned, src.size() == dst.size()).
  // Separate buffers let callers append plaintext straight into the tail of a
  // reassembly vector instead of decrypting a temporary copy.
  void decrypt(std::span<const std::uint8_t> src, std::span<std::uint8_t> dst);
  void wipe();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace crypto

// ---------------------------------------------------------------------------
// Middle-End key derivation
// ---------------------------------------------------------------------------

struct MiddleProxyKdfInput {
  std::array<std::uint8_t, 16> nonce_server{};
  std::array<std::uint8_t, 16> nonce_client{};
  std::uint32_t client_timestamp{0};
  Endpoint server;  // ME/DC endpoint (server_ip / server_port)
  Endpoint local;   // source address/port Telegram observes (client_ip / client_port)
  std::span<const std::uint8_t> secret;  // global ME secret, 1..392 bytes
};

struct MiddleProxyKeys {
  std::array<std::uint8_t, 32> write_key{};
  std::array<std::uint8_t, 16> write_iv{};
  std::array<std::uint8_t, 32> read_key{};
  std::array<std::uint8_t, 16> read_iv{};

  MiddleProxyKeys() = default;
  MiddleProxyKeys(MiddleProxyKeys&&) = default;
  MiddleProxyKeys& operator=(MiddleProxyKeys&&) = default;
  MiddleProxyKeys(const MiddleProxyKeys&) = delete;
  MiddleProxyKeys& operator=(const MiddleProxyKeys&) = delete;
  ~MiddleProxyKeys() { wipe(); }

  void wipe();
};

// Throws std::invalid_argument for an empty/oversized secret, endpoint family
// mismatch, or a zero port.
MiddleProxyKeys derive_middle_proxy_keys(const MiddleProxyKdfInput& input);

// ---------------------------------------------------------------------------
// FakeTLS ClientHello / ServerHello
// ---------------------------------------------------------------------------

struct ClientHelloInfo {
  std::array<std::uint8_t, 32> digest{};  // masked field from the wire
  // HMAC before timestamp XOR masking; use this for replay-cache insertion.
  std::array<std::uint8_t, 32> canonical_hmac{};
  std::array<std::uint8_t, 32> session_id{};
  std::array<std::uint8_t, 16> secret{};
  std::uint16_t cipher{0x1301};
  std::uint32_t timestamp{0};
  std::string server_name;  // first host_name SNI entry, empty when absent
  bool offers_pq{false};

  ClientHelloInfo() = default;
  ClientHelloInfo(ClientHelloInfo&&) = default;
  ClientHelloInfo& operator=(ClientHelloInfo&&) = default;
  ClientHelloInfo(const ClientHelloInfo&) = delete;
  ClientHelloInfo& operator=(const ClientHelloInfo&) = delete;
  ~ClientHelloInfo() { wipe(); }

  void wipe();
};

enum class HelloStatus { Ok, NeedMoreData, NotTls, Invalid, Unauthenticated, ClockSkew };

// Extracts the SNI host_name from a raw TLS ClientHello record without any
// FakeTLS authentication. Used by the masking relay to front the real server
// of the probed name. Returns nullopt for unparseable input or absent SNI;
// the returned name is lowercased.
[[nodiscard]] std::optional<std::string> client_hello_sni(
    std::span<const std::uint8_t> record);

// Validates exactly one TLS record containing one ClientHello. `secret` must be
// the 16-byte FakeTLS user secret. The timestamp is masked into digest[28..32].
// A ClientHello that offers no TLS 1.3 cipher (1301/1302/1303) is Invalid: the
// ServerHello never invents a cipher the client did not offer.
HelloStatus validate_client_hello(std::span<const std::uint8_t> record,
                                  std::span<const std::uint8_t, 16> secret,
                                  std::int64_t now_unix, std::uint32_t skew_seconds,
                                  ClientHelloInfo& out);

// Same contract, tried against every key with the canonical HMAC input built
// once. On Ok, @p matched is the index of the first authenticating key; any
// other status leaves it unspecified. Unauthenticated means no key matched.
HelloStatus validate_client_hello(std::span<const std::uint8_t> record,
                                  std::span<const crypto::HmacSha256Key* const> keys,
                                  std::int64_t now_unix, std::uint32_t skew_seconds,
                                  ClientHelloInfo& out, std::size_t& matched);

// Builds ServerHello + CCS + fake encrypted certificate. Uses the classical
// x25519 template, or the X25519MLKEM768 shape when info.offers_pq is set.
std::vector<std::uint8_t> build_server_hello(const ClientHelloInfo& info, const RandomFn& random);

// ---------------------------------------------------------------------------
// MTProto obfuscation (obfuscated2)
// ---------------------------------------------------------------------------

enum class ObfuscationStatus {
  Ok,
  NeedMoreData,
  Invalid,          // key/tag mismatch or malformed
  ReservedNonce,    // likely HTTP/TLS/probe prefix
  UnsupportedTag,   // recognized tag we do not serve (abridged)
};

struct ObfuscationParams {
  std::array<std::uint8_t, 32> decrypt_key{};
  std::array<std::uint8_t, 16> decrypt_iv{};
  std::array<std::uint8_t, 32> encrypt_key{};
  std::array<std::uint8_t, 16> encrypt_iv{};
  ProtoTag tag{ProtoTag::Secure};
  // Client-controlled exact signed DC id (non-zero); runtime maps it through the
  // configured DC table. Never index memory with it or fall back to another DC.
  std::int16_t dc_id{0};

  ObfuscationParams() = default;
  ObfuscationParams(ObfuscationParams&&) = default;
  ObfuscationParams& operator=(ObfuscationParams&&) = default;
  ObfuscationParams(const ObfuscationParams&) = delete;
  ObfuscationParams& operator=(const ObfuscationParams&) = delete;
  ~ObfuscationParams() { wipe(); }

  void wipe();
};

ObfuscationStatus parse_obfuscation_handshake(std::span<const std::uint8_t> handshake,
                                              std::span<const std::uint8_t, 16> secret,
                                              ObfuscationParams& out);

// SHA-256 of handshake bytes 8..56, suitable as a replay-cache key.
std::array<std::uint8_t, 32> obfuscation_replay_key(std::span<const std::uint8_t> handshake);

// ---------------------------------------------------------------------------
// FakeTLS connection (client side of the proxy)
// ---------------------------------------------------------------------------

class FakeTlsConnection {
 public:
  struct Config {
    std::array<std::uint8_t, 16> secret{};
    RandomFn random;   // required
    ClockFn clock;     // defaults to system time
    bool enforce_time_skew{true};
    std::uint32_t skew_seconds{120};
    // When set, the ClientHello must carry this exact SNI (ASCII case-insensitive).
    std::optional<std::string> expected_server_name;
    std::size_t max_client_hello{kFakeTlsMaxClientHello};
    std::size_t max_record_body{kFakeTlsMaxRecordBody};
    std::size_t max_pending_plaintext{1u << 20};
  };

  enum class State { ClientHello, Obfuscation, Ready, Closed, Failed };

  explicit FakeTlsConnection(Config config);
  ~FakeTlsConnection();
  FakeTlsConnection(FakeTlsConnection&&) noexcept;
  FakeTlsConnection& operator=(FakeTlsConnection&&) noexcept;
  FakeTlsConnection(const FakeTlsConnection&) = delete;
  FakeTlsConnection& operator=(const FakeTlsConnection&) = delete;

  // Consumes wire bytes. On ClientHello completion, appends the ServerHello to
  // to_client. Once ready, decrypted MTProto transport bytes are appended to
  // plaintext_out. Both output vectors are append-only; drain them per call.
  // Arbitrarily large recv() batches are accepted; only unconsumed partial-record
  // residue is bounded by Config limits. Returns ProtocolError on failure.
  //
  // Replay order: after the feed that first produces a ServerHello (state becomes
  // Obfuscation), check client_hello().canonical_hmac (or digest) against the
  // replay cache BEFORE sending to_client or forwarding any plaintext_out. If it
  // is a replay, discard both and close. Do not use replay_key() before Ready:
  // it is all-zero until the obfuscation handshake has been parsed.
  Status feed(std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& to_client,
              std::vector<std::uint8_t>& plaintext_out);

  // Encrypts and TLS-frames payload for the client, appending to to_client.
  // Splits into <=16 KiB application-data records.
  //
  // Record coalescing: when @p open_record is non-null and holds the offset of
  // the last ApplicationData record header in @p to_client (kNoOpenRecord when
  // there is none), bytes are first appended to that record's body until it
  // reaches 16 KiB, then new records follow. On return it names the last record
  // written. AES-CTR is a continuous stream, so the client decodes extended and
  // fresh records identically; this only removes per-message record headers.
  static constexpr std::size_t kNoOpenRecord = static_cast<std::size_t>(-1);
  Status send(std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& to_client,
              std::size_t* open_record = nullptr);

  // Fused transport framing + TLS record encoding: equivalent to
  // encode_transport_message(tag, payload, tmp, &random) followed by
  // send(tmp, to_client) — byte-identical on the wire for the same random
  // stream — but writes the intermediate transport header, payload and padding
  // straight into the TLS record body and applies AES-CTR in place. This removes
  // one full-payload copy and one scratch buffer from the S2C hot path.
  Status send_transport_message(ProtoTag tag, std::span<const std::uint8_t> payload,
                                std::vector<std::uint8_t>& to_client, const RandomFn& random,
                                std::size_t* open_record = nullptr);

  State state() const;
  ProtoTag proto_tag() const;
  std::int16_t dc_id() const;
  const ClientHelloInfo& client_hello() const;
  // SHA-256(raw obfuscation handshake[8..56]); all-zero until state()==Ready.
  // Prefer client_hello().canonical_hmac for the TLS replay decision.
  std::array<std::uint8_t, 32> replay_key() const;
  std::string_view error() const;
  // Allocated capacity (bytes), not length, for aggregate budget accounting.
  std::size_t retained_bytes() const;
  // Releases empty reassembly buffers without touching pending bytes or the
  // crypto state.
  void release_idle();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// MTProto client transport framing (intermediate / padded intermediate)
// ---------------------------------------------------------------------------

class TransportDecoder {
 public:
  struct Config {
    ProtoTag tag{ProtoTag::Secure};
    // Per-message bound. The runtime must size this together with the ME budget,
    // keeping max_message + 96 <= MiddleEndConfig::max_frame (96 = RPC_PROXY_REQ
    // header + ad-tag block + ME frame overhead). A forged 4-byte header can
    // buffer up to max_message before rejection; account using retained_bytes().
    std::size_t max_message{4u << 20};
  };
  struct Message {
    std::vector<std::uint8_t> data;  // 4-byte aligned, non-empty
    bool quick_ack{false};
  };

  explicit TransportDecoder(Config config);  // throws for Abridged
  // Appends complete messages to out; unconsumed bytes stay buffered.
  Status feed(std::span<const std::uint8_t> wire, std::vector<Message>& out);
  std::size_t buffered() const;
  std::size_t retained_bytes() const;  // allocated capacity, not length
  // Releases an empty reassembly buffer; a partially buffered frame is kept.
  void release_idle();

 private:
  ProtoTag tag_;
  std::size_t max_message_;
  Bytes buffer_;
};

// Appends one framed server->client message. For Secure, 0..3 random padding
// bytes are added when `random` is non-null (zero padding otherwise).
void encode_transport_message(ProtoTag tag, std::span<const std::uint8_t> data,
                              std::vector<std::uint8_t>& out, const RandomFn* random = nullptr);
void encode_quick_ack(ProtoTag tag, std::array<std::uint8_t, 4> confirm,
                      std::vector<std::uint8_t>& out);

// ---------------------------------------------------------------------------
// Telegram Middle-End session (one shared ME TCP connection)
// ---------------------------------------------------------------------------

struct AdTag {
  std::array<std::uint8_t, kAdTagSize> bytes{};
  friend bool operator==(const AdTag&, const AdTag&) = default;
};

struct MiddleEndConfig {
  std::vector<std::uint8_t> secret;  // global ME secret, owned
  Endpoint server;                   // ME address/port (DC endpoint)
  // Source address/port of this ME TCP connection. This is KDF material and
  // must stay the outbound socket endpoint: its ephemeral port is part of the
  // AES key derivation, so it is NOT what Telegram may be told about the proxy.
  Endpoint local;
  // Proxy listener endpoint advertised to ME in RPC_PROXY_REQ "our_addr".
  // Deliberately separate from `local`: Telegram must see the address/port that
  // clients actually connect to (e.g. 443), not the ME socket's ephemeral
  // source port. The address family may differ from the transport (the wire
  // form supports IPv4-mapped and native IPv6); the port must be non-zero.
  Endpoint advertised;
  AdTag ad_tag;                      // mandatory; always emitted in RPC_PROXY_REQ
  RandomFn random;                   // required
  ClockFn clock;                     // defaults to system time
  // RPC_HANDSHAKE process_id material (12-byte process ids, same layout as
  // Telegram's struct process_id: *reversed* IPv4 octets (host-order u32),
  // port16 LE, pid16 LE, utime32 LE).
  // sender_pid = `local` (the outbound ME/KDF socket tuple) + these values;
  // peer_pid = the ME endpoint with
  // wildcard pid/time. `advertised` is only our_addr in RPC_PROXY_REQ.
  // Zero means "derive": pid16 from getpid(), time from clock(). Tests set both
  // explicitly for known-byte vectors.
  std::uint16_t process_id{0};
  std::uint32_t process_time{0};
  // Per-frame ceiling. Size TransportDecoder::max_message so that
  // max_message + 96 <= max_frame. One feed may transiently hold up to
  // 2*(max_frame+64) while complete frames are demultiplexed; residue after
  // demux is bounded by max_frame+64.
  std::size_t max_frame{kMiddleEndDefaultMaxFrame};
};

class MiddleEndSession {
 public:
  using ConnId = std::array<std::uint8_t, 8>;

  class Sink {
   public:
    virtual ~Sink() = default;
    // All callbacks are synchronous and non-reentrant: do not call feed(),
    // encode_*(), or destroy the session from a callback. A thrown exception
    // marks the shared ME session terminal Failed ("sink threw").
    // conn_data from RPC_PROXY_ANS, already stripped of the 16-byte header.
    virtual void on_proxy_payload(const ConnId& conn_id, std::span<const std::uint8_t> payload) = 0;
    // 4-byte confirm from RPC_SIMPLE_ACK. The runtime reverses it for abridged.
    virtual void on_quick_ack(const ConnId&, std::array<std::uint8_t, 4>) {}
    // The ME peer closed ONE logical connection; the shared transport stays open.
    virtual void on_remote_close(const ConnId&) {}
    // RPC_PONG keepalive answer carrying the 8-byte id we sent in RPC_PING.
    virtual void on_pong(std::int64_t) {}
  };

  // Bounded, monotonic counters for inbound RPC control constructors. They make
  // it observable which close constructors Telegram actually sends; a malformed
  // RPC_CLOSE_CONN is ignored (counted) instead of failing the shared transport.
  struct ControlCounters {
    std::uint64_t close_conn{0};  // inbound RPC_CLOSE_CONN, well formed
    std::uint64_t close_ext{0};   // inbound RPC_CLOSE_EXT
    std::uint64_t malformed{0};   // recognized control type with a bad length
    std::uint64_t unknown{0};     // unrecognized RPC constructors
    // RPC_HANDSHAKE answers that carried unknown HIGH flag bits. Such bits are
    // ignored for forward compatibility; only `flags & 0xff` is rejected,
    // but counted so a new ME flag is observable. Not published to metrics yet.
    std::uint64_t handshake_unknown_flags{0};
  };

  enum class State { Nonce, Handshake, Ready, Closed, Failed };

  struct ClientRequest {
    ConnId conn_id{};
    Endpoint peer;  // MTProto client address as seen by the proxy
    ProtoTag proto_tag{ProtoTag::Secure};
    std::span<const std::uint8_t> payload;  // non-empty, 4-byte aligned
    bool quick_ack{false};
  };

  MiddleEndSession(MiddleEndConfig config, std::unique_ptr<Sink> sink);
  ~MiddleEndSession();
  MiddleEndSession(MiddleEndSession&&) noexcept;
  MiddleEndSession& operator=(MiddleEndSession&&) noexcept;
  MiddleEndSession(const MiddleEndSession&) = delete;
  MiddleEndSession& operator=(const MiddleEndSession&) = delete;

  // Initial RPC_NONCE request frame (plain, seq -2). Call once, write it to ME.
  std::vector<std::uint8_t> start();

  // Consumes ME wire bytes. After the plaintext RPC_NONCE answer, `to_me`
  // receives the AES-CBC encrypted RPC_HANDSHAKE request (seq -1) exactly once;
  // the handshake answer is encrypted too. Events are delivered to the Sink.
  Status feed(std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& to_me);

  // Wraps one client MTProto message in RPC_PROXY_REQ + ad-tag + ME framing and
  // appends the encrypted frame to to_me. dc_id from ObfuscationParams is
  // client-controlled: the runtime must map it through the configured signed DC
  // table (exact match, no fallback) and must own/validate conn_id and peer
  // (non-zero port, uniqueness). Never index arrays by dc_id. After the nonce
  // response, every frame including RPC_HANDSHAKE (seq -1) and later data is
  // AES-CBC encrypted.
  Status encode_client_message(std::span<const std::uint8_t> payload, const Endpoint& peer,
                               ProtoTag tag, bool quick_ack, std::vector<std::uint8_t>& to_me);
  // Same, with an explicit per-logical-client connection id (shared ME multiplexing).
  Status encode_client_message(const ConnId& conn_id, std::span<const std::uint8_t> payload,
                               const Endpoint& peer, ProtoTag tag, bool quick_ack,
                               std::vector<std::uint8_t>& to_me);
  // RPC_CLOSE_CONN (0x1fcf425d) for one logical connection; transport stays up.
  // This is the outgoing notification. Inbound RPC_CLOSE_CONN and RPC_CLOSE_EXT
  // are both delivered via Sink::on_remote_close and also do not close the
  // multiplexed transport.
  Status encode_close(const ConnId& conn_id, std::vector<std::uint8_t>& to_me);
  // RPC_PING (0x5730a2df) + ping_id for connection keepalive; transport stays up.
  Status encode_ping(std::int64_t ping_id, std::vector<std::uint8_t>& to_me);

  State state() const;
  bool ready() const { return state() == State::Ready; }
  std::string_view error() const;
  const ConnId& conn_id() const;
  Sink* sink() const;
  std::int32_t write_seq() const;
  std::int32_t read_seq() const;
  const ControlCounters& control_counters() const;
  // Raw flags of the last RPC_HANDSHAKE answer (0 before one is parsed). Lets a
  // caller observe unknown high bits that were ignored, without publishing them
  // to metrics here.
  std::uint32_t handshake_flags() const;
  // Allocated capacity (bytes) of internal reassembly buffers, not length.
  // Buffers that become empty and exceed 64 KiB are released.
  std::size_t retained_bytes() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace mtdd::protocol

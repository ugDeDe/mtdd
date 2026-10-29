#include "mtdd/protocol.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

namespace mtdd::protocol {

RandomFn buffered_random() {
  struct Pool {
    std::array<std::uint8_t, 16384> bytes{};
    std::size_t used{16384};
    ~Pool() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
  };
  auto pool = std::make_shared<Pool>();
  return [pool](std::span<std::uint8_t> out) {
    if (out.empty()) return;
    if (out.size() > 4096) {
      if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("openssl: RAND_bytes failed");
      }
      return;
    }
    if (pool->bytes.size() - pool->used < out.size()) {
      if (RAND_bytes(pool->bytes.data(), static_cast<int>(pool->bytes.size())) != 1) {
        throw std::runtime_error("openssl: RAND_bytes failed");
      }
      pool->used = 0;
    }
    std::memcpy(out.data(), pool->bytes.data() + pool->used, out.size());
    // Served bytes are erased so the block never hands out a value twice.
    OPENSSL_cleanse(pool->bytes.data() + pool->used, out.size());
    pool->used += out.size();
  };
}

RandomFn system_random() {
  return [](std::span<std::uint8_t> out) {
    if (out.empty()) return;
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
      throw std::runtime_error("openssl: RAND_bytes failed");
    }
  };
}

namespace crypto {
namespace {

[[noreturn]] void fail(const char* what) { throw std::runtime_error(std::string("openssl: ") + what); }

int update_size(std::size_t size, std::size_t headroom = 0) {
  if (size > static_cast<std::size_t>(std::numeric_limits<int>::max()) - headroom)
    throw std::length_error("AES update exceeds EVP int size limit");
  return static_cast<int>(size);
}

std::array<std::uint8_t, 32> digest(const EVP_MD* md, std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, 32> out{};
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), out.data(), &len, md, nullptr) != 1) fail("digest");
  return out;
}

struct CipherCtx {
  EVP_CIPHER_CTX* ctx{EVP_CIPHER_CTX_new()};
  CipherCtx() {
    if (!ctx) fail("EVP_CIPHER_CTX_new");
  }
  ~CipherCtx() { EVP_CIPHER_CTX_free(ctx); }
  CipherCtx(const CipherCtx&) = delete;
  CipherCtx& operator=(const CipherCtx&) = delete;
};

}  // namespace

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data) {
  return digest(EVP_sha256(), data);
}

std::array<std::uint8_t, 20> sha1(std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, 20> out{};
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha1(), nullptr) != 1) fail("sha1");
  return out;
}

std::array<std::uint8_t, 16> md5(std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, 16> out{};
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_md5(), nullptr) != 1) fail("md5");
  return out;
}

std::array<std::uint8_t, 32> hmac_sha256(std::span<const std::uint8_t> key,
                                        std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, 32> out{};
  unsigned int len = 0;
  if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
            out.data(), &len) ||
      len != out.size()) {
    fail("hmac");
  }
  return out;
}

struct HmacSha256Key::Impl {
  EVP_MD_CTX* inner{nullptr};
  EVP_MD_CTX* outer{nullptr};
  ~Impl() {
    EVP_MD_CTX_free(inner);
    EVP_MD_CTX_free(outer);
  }
};

HmacSha256Key::HmacSha256Key(std::span<const std::uint8_t, 16> key) : impl_(std::make_unique<Impl>()) {
  std::copy(key.begin(), key.end(), key_.begin());
  std::array<std::uint8_t, 64> ipad{};
  std::array<std::uint8_t, 64> opad{};
  ipad.fill(0x36);
  opad.fill(0x5c);
  for (std::size_t i = 0; i < key.size(); ++i) {
    ipad[i] = static_cast<std::uint8_t>(ipad[i] ^ key[i]);
    opad[i] = static_cast<std::uint8_t>(opad[i] ^ key[i]);
  }
  impl_->inner = EVP_MD_CTX_new();
  impl_->outer = EVP_MD_CTX_new();
  const bool ok = impl_->inner != nullptr && impl_->outer != nullptr &&
                  EVP_DigestInit_ex(impl_->inner, EVP_sha256(), nullptr) == 1 &&
                  EVP_DigestUpdate(impl_->inner, ipad.data(), ipad.size()) == 1 &&
                  EVP_DigestInit_ex(impl_->outer, EVP_sha256(), nullptr) == 1 &&
                  EVP_DigestUpdate(impl_->outer, opad.data(), opad.size()) == 1;
  secure_zero(ipad);
  secure_zero(opad);
  if (!ok) {
    secure_zero(key_);
    fail("hmac key");
  }
}

HmacSha256Key::~HmacSha256Key() { secure_zero(key_); }
HmacSha256Key::HmacSha256Key(HmacSha256Key&&) noexcept = default;
HmacSha256Key& HmacSha256Key::operator=(HmacSha256Key&&) noexcept = default;

std::array<std::uint8_t, 32> HmacSha256Key::mac(std::span<const std::uint8_t> data) const {
  if (!impl_) fail("hmac key moved-from");
  struct Ctx {
    EVP_MD_CTX* value{EVP_MD_CTX_new()};
    ~Ctx() { EVP_MD_CTX_free(value); }
  } ctx;
  std::array<std::uint8_t, 32> inner{};
  std::array<std::uint8_t, 32> out{};
  unsigned int len = 0;
  if (ctx.value == nullptr || EVP_MD_CTX_copy_ex(ctx.value, impl_->inner) != 1 ||
      EVP_DigestUpdate(ctx.value, data.data(), data.size()) != 1 ||
      EVP_DigestFinal_ex(ctx.value, inner.data(), &len) != 1 || len != inner.size() ||
      EVP_MD_CTX_copy_ex(ctx.value, impl_->outer) != 1 ||
      EVP_DigestUpdate(ctx.value, inner.data(), inner.size()) != 1 ||
      EVP_DigestFinal_ex(ctx.value, out.data(), &len) != 1 || len != out.size()) {
    secure_zero(inner);
    fail("hmac");
  }
  secure_zero(inner);
  return out;
}

std::uint32_t crc32(std::span<const std::uint8_t> data) {
  // IEEE 802.3 CRC-32 (reflected polynomial 0xEDB88320), as used by MTProxy RPC.
  static constexpr auto table = [] {
    std::array<std::array<std::uint32_t, 256>, 8> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1u) ? (0xedb88320u ^ (c >> 1u)) : (c >> 1u);
      t[0][i] = c;
    }
    for (std::size_t slice = 1; slice < t.size(); ++slice)
      for (std::size_t i = 0; i < 256; ++i) {
        const auto c = t[slice - 1][i];
        t[slice][i] = t[0][c & 0xffu] ^ (c >> 8u);
      }
    return t;
  }();
  std::uint32_t c = 0xffffffffu;
  // Slicing-by-8, with explicit little-endian byte assembly: no host-endian,
  // alignment or aliasing dependency, and never read beyond the span's tail.
  while (data.size() >= 8) {
    c ^= static_cast<std::uint32_t>(data[0]) |
         (static_cast<std::uint32_t>(data[1]) << 8u) |
         (static_cast<std::uint32_t>(data[2]) << 16u) |
         (static_cast<std::uint32_t>(data[3]) << 24u);
    c = table[7][c & 0xffu] ^ table[6][(c >> 8u) & 0xffu] ^
        table[5][(c >> 16u) & 0xffu] ^ table[4][c >> 24u] ^
        table[3][data[4]] ^ table[2][data[5]] ^ table[1][data[6]] ^ table[0][data[7]];
    data = data.subspan(8);
  }
  for (auto b : data) c = table[0][(c ^ b) & 0xffu] ^ (c >> 8u);
  return c ^ 0xffffffffu;
}

bool constant_time_equal(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  if (a.size() != b.size()) return false;
  if (a.empty()) return true;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void secure_zero(std::span<std::uint8_t> data) {
  if (!data.empty()) OPENSSL_cleanse(data.data(), data.size());
}

void secure_zero(void* data, std::size_t size) {
  if (size) OPENSSL_cleanse(data, size);
}

namespace {

// Reflected Castagnoli polynomial, as used by CRC-32C.
constexpr std::uint32_t kCrc32cPoly = 0x82f63b78u;

using Crc32cTable = std::array<std::array<std::uint32_t, 256>, 8>;

const Crc32cTable& crc32c_table() {
  static const Crc32cTable table = [] {
    Crc32cTable t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1u) ? (kCrc32cPoly ^ (c >> 1u)) : (c >> 1u);
      t[0][i] = c;
    }
    for (std::size_t slice = 1; slice < t.size(); ++slice) {
      for (std::size_t i = 0; i < 256; ++i) {
        const auto c = t[slice - 1][i];
        t[slice][i] = t[0][c & 0xffu] ^ (c >> 8u);
      }
    }
    return t;
  }();
  return table;
}

std::uint32_t crc32c_portable_impl(std::span<const std::uint8_t> data) {
  const auto& table = crc32c_table();
  std::uint32_t c = 0xffffffffu;
  // Same shape as crypto::crc32(): explicit little-endian assembly, no
  // host-endian or alignment dependency, never reads past the span's tail.
  while (data.size() >= 8) {
    c ^= static_cast<std::uint32_t>(data[0]) |
         (static_cast<std::uint32_t>(data[1]) << 8u) |
         (static_cast<std::uint32_t>(data[2]) << 16u) |
         (static_cast<std::uint32_t>(data[3]) << 24u);
    c = table[7][c & 0xffu] ^ table[6][(c >> 8u) & 0xffu] ^
        table[5][(c >> 16u) & 0xffu] ^ table[4][c >> 24u] ^
        table[3][data[4]] ^ table[2][data[5]] ^ table[1][data[6]] ^ table[0][data[7]];
    data = data.subspan(8);
  }
  for (auto b : data) c = table[0][(c ^ b) & 0xffu] ^ (c >> 8u);
  return c ^ 0xffffffffu;
}

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#define MTDD_HAVE_SSE42_CRC32C 1

// Only this function carries the sse4.2 target attribute, so the translation unit
// (and therefore the portable binary) never requires SSE4.2 to load.
// _mm_crc32_u64 exists only on x86-64; 32-bit x86 (__i386__) uses the 32-bit
// instruction. Long inputs are slower there, but the code builds and is correct.
__attribute__((target("sse4.2"))) std::uint32_t crc32c_sse42(
    std::span<const std::uint8_t> data) {
#if defined(__x86_64__)
  std::uint64_t c = 0xffffffffu;
  while (data.size() >= 8) {
    std::uint64_t word = 0;
    std::memcpy(&word, data.data(), sizeof(word));
    c = static_cast<std::uint64_t>(_mm_crc32_u64(c, word));
    data = data.subspan(8);
  }
  std::uint32_t crc = static_cast<std::uint32_t>(c);
#else
  std::uint32_t crc = 0xffffffffu;
  while (data.size() >= 4) {
    std::uint32_t word = 0;
    std::memcpy(&word, data.data(), sizeof(word));
    crc = _mm_crc32_u32(crc, word);
    data = data.subspan(4);
  }
#endif
  if (data.size() >= 4) {
    std::uint32_t word = 0;
    std::memcpy(&word, data.data(), sizeof(word));
    crc = _mm_crc32_u32(crc, word);
    data = data.subspan(4);
  }
  if (data.size() >= 2) {
    std::uint16_t word = 0;
    std::memcpy(&word, data.data(), sizeof(word));
    crc = _mm_crc32_u16(crc, word);
    data = data.subspan(2);
  }
  if (!data.empty()) crc = _mm_crc32_u8(crc, data[0]);
  return ~crc;
}

bool cpu_has_sse42() {
  // __builtin_cpu_supports consults CPUID once and is thread-safe.
  static const bool supported = __builtin_cpu_supports("sse4.2") != 0;
  return supported;
}
#else
#define MTDD_HAVE_SSE42_CRC32C 0
#endif

}  // namespace

std::uint32_t crc32c_portable(std::span<const std::uint8_t> data) {
  return crc32c_portable_impl(data);
}

std::uint32_t crc32c(std::span<const std::uint8_t> data) {
#if MTDD_HAVE_SSE42_CRC32C
  if (cpu_has_sse42()) return crc32c_sse42(data);
#endif
  return crc32c_portable_impl(data);
}

struct AesCtr::Impl {
  CipherCtx ctx;
  Impl(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv) {
    if (EVP_EncryptInit_ex(ctx.ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) != 1) {
      fail("aes-256-ctr init");
    }
  }
};

AesCtr::AesCtr(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv)
    : impl_(std::make_unique<Impl>(key, iv)) {}

AesCtr::~AesCtr() = default;
AesCtr::AesCtr(AesCtr&&) noexcept = default;
AesCtr& AesCtr::operator=(AesCtr&&) noexcept = default;

void AesCtr::apply(std::span<std::uint8_t> data) {
  if (data.empty()) return;
  const int size = update_size(data.size());
  int out_len = 0;
  // CTR has no buffered partial output; EVP permits exact input/output aliasing.
  if (EVP_EncryptUpdate(impl_->ctx.ctx, data.data(), &out_len, data.data(), size) != 1 ||
      out_len != size) {
    fail("aes-256-ctr update");
  }
}

void AesCtr::skip(std::size_t bytes) {
  std::array<std::uint8_t, 256> zeros{};
  while (bytes > 0) {
    const std::size_t n = std::min(bytes, zeros.size());
    apply(std::span<std::uint8_t>(zeros).first(n));
    bytes -= n;
  }
  secure_zero(zeros);
}

void AesCtr::wipe() {
  if (impl_) {
    EVP_CIPHER_CTX_reset(impl_->ctx.ctx);
  }
}

struct AesCbc::Impl {
  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 16> iv{};
  CipherCtx ctx;
  int mode{0};  // 0 = uninitialised, 1 = encrypt, 2 = decrypt

  Impl(std::span<const std::uint8_t, 32> k, std::span<const std::uint8_t, 16> i) {
    std::copy(k.begin(), k.end(), key.begin());
    std::copy(i.begin(), i.end(), iv.begin());
  }
  ~Impl() { secure_zero(key); secure_zero(iv); }

  void ensure(int requested) {
    if (mode == requested) return;
    if (mode != 0) throw std::logic_error("AES-CBC stream reused in both directions");
    if (EVP_CipherInit_ex(ctx.ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data(),
                          requested == 1 ? 1 : 0) != 1) {
      fail("aes-256-cbc init");
    }
    if (EVP_CIPHER_CTX_set_padding(ctx.ctx, 0) != 1) fail("aes-256-cbc padding");
    mode = requested;
  }
};

AesCbc::AesCbc(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv)
    : impl_(std::make_unique<Impl>(key, iv)) {}

AesCbc::~AesCbc() = default;
AesCbc::AesCbc(AesCbc&&) noexcept = default;
AesCbc& AesCbc::operator=(AesCbc&&) noexcept = default;

void AesCbc::encrypt(std::span<std::uint8_t> data) {
  if (data.empty()) return;
  if (data.size() % 16 != 0) throw std::invalid_argument("AES-CBC input must be 16-byte aligned");
  // Leave one block of headroom for EVP's internal signed-int length arithmetic.
  const int size = update_size(data.size(), 16);
  impl_->ensure(1);
  int out_len = 0;
  // No padding and exclusively full-block calls mean EVP has no buffered tail.
  if (EVP_EncryptUpdate(impl_->ctx.ctx, data.data(), &out_len, data.data(), size) != 1 ||
      out_len != size) {
    fail("aes-256-cbc encrypt");
  }
}

void AesCbc::decrypt(std::span<std::uint8_t> data) {
  if (data.empty()) return;
  if (data.size() % 16 != 0) throw std::invalid_argument("AES-CBC input must be 16-byte aligned");
  const int size = update_size(data.size(), 16);
  impl_->ensure(2);
  int out_len = 0;
  if (EVP_DecryptUpdate(impl_->ctx.ctx, data.data(), &out_len, data.data(), size) != 1 ||
      out_len != size) {
    fail("aes-256-cbc decrypt");
  }
}

void AesCbc::decrypt(std::span<const std::uint8_t> src, std::span<std::uint8_t> dst) {
  if (src.size() != dst.size()) throw std::invalid_argument("AES-CBC src/dst size mismatch");
  if (src.empty()) return;
  if (src.size() % 16 != 0) throw std::invalid_argument("AES-CBC input must be 16-byte aligned");
  const int size = update_size(src.size(), 16);
  impl_->ensure(2);
  int out_len = 0;
  if (EVP_DecryptUpdate(impl_->ctx.ctx, dst.data(), &out_len, src.data(), size) != 1 ||
      out_len != size) {
    fail("aes-256-cbc decrypt");
  }
}

void AesCbc::wipe() {
  if (impl_) {
    EVP_CIPHER_CTX_reset(impl_->ctx.ctx);
    secure_zero(impl_->key);
    secure_zero(impl_->iv);
    impl_->mode = 0;
  }
}

}  // namespace crypto
}  // namespace mtdd::protocol

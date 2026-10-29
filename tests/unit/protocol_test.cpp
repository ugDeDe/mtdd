#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {
namespace {

TEST(Crypto, HashKnownAnswers) {
  const std::string abc = "abc";
  auto span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size());
  EXPECT_EQ(crypto::sha256(span), arr<32>(from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
  EXPECT_EQ(crypto::sha1(span), arr<20>(from_hex("a9993e364706816aba3e25717850c26c9cd0d89d")));
  EXPECT_EQ(crypto::md5(span), arr<16>(from_hex("900150983cd24fb0d6963f7d28e17f72")));
}

TEST(Crypto, HmacRfc4231) {
  Bytes key(20, 0x0b);
  const std::string data = "Hi There";
  auto out = crypto::hmac_sha256(key,
                                 std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
  EXPECT_EQ(out, arr<32>(from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")));
}

TEST(Crypto, AesCtrNistSp80038a) {
  auto key = arr<32>(from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  auto iv = arr<16>(from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  Bytes data = from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
  crypto::AesCtr ctr(key, iv);
  ctr.apply(data);
  EXPECT_EQ(data, from_hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"));

  // Counter continuity: a short first call must not reset the stream.
  Bytes split = from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
  crypto::AesCtr ctr2(key, iv);
  ctr2.apply(std::span<std::uint8_t>(split).first(5));
  ctr2.apply(std::span<std::uint8_t>(split).subspan(5));
  EXPECT_EQ(split, from_hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"));
}

TEST(Crypto, AesCbcNistSp80038a) {
  auto key = arr<32>(from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  auto iv = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));
  Bytes block = from_hex("6bc1bee22e409f96e93d7e117393172a");
  crypto::AesCbc enc(key, iv);
  enc.encrypt(block);
  EXPECT_EQ(block, from_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));

  crypto::AesCbc dec(key, iv);
  dec.decrypt(block);
  EXPECT_EQ(block, from_hex("6bc1bee22e409f96e93d7e117393172a"));
}

TEST(Crypto, AesCbcContinuityAcrossCalls) {
  auto key = arr<32>(from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  auto iv = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));
  crypto::AesCbc enc(key, iv);
  Bytes b1 = from_hex("6bc1bee22e409f96e93d7e117393172a");
  Bytes b2 = from_hex("ae2d8a571e03ac9c9eb76fac45af8e51");
  enc.encrypt(b1);
  enc.encrypt(b2);
  EXPECT_EQ(b1, from_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
  EXPECT_EQ(b2, from_hex("9cfc4e967edb808d679f777bc6702c7d"));  // chained with previous block

  crypto::AesCbc dec(key, iv);
  dec.decrypt(b1);
  dec.decrypt(b2);
  EXPECT_EQ(b1, from_hex("6bc1bee22e409f96e93d7e117393172a"));
  EXPECT_EQ(b2, from_hex("ae2d8a571e03ac9c9eb76fac45af8e51"));
}

TEST(Crypto, Crc32AndConstantTime) {
  const std::string s = "123456789";
  auto span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  EXPECT_EQ(crypto::crc32(span), 0xcbf43926u);
  std::array<std::uint8_t, 4> a{1, 2, 3, 4}, b{1, 2, 3, 4}, c{1, 2, 3, 5};
  EXPECT_TRUE(crypto::constant_time_equal(a, b));
  EXPECT_FALSE(crypto::constant_time_equal(a, c));
  crypto::secure_zero(a);
  EXPECT_EQ(a, (std::array<std::uint8_t, 4>{0, 0, 0, 0}));
}

TEST(Crypto, Crc32IndependentReferenceAlignmentTailsAndLargeBuffers) {
  // Bitwise reference deliberately shares neither tables nor slicing logic.
  const auto reference = [](std::span<const std::uint8_t> data) {
    std::uint32_t crc{0xffffffffu};
    for (const auto byte : data) {
      crc ^= byte;
      for (int bit = 0; bit < 8; ++bit)
        crc = (crc >> 1) ^ ((crc & 1u) ? 0xedb88320u : 0u);
    }
    return crc ^ 0xffffffffu;
  };
  EXPECT_EQ(crypto::crc32({}), 0u);
  std::mt19937 rng(0x43524332u);
  Bytes storage((1u << 20) + 64);
  for (auto& byte : storage) byte = static_cast<std::uint8_t>(rng());
  for (std::size_t offset = 0; offset < 32; ++offset) {
    for (std::size_t length = 0; length < 128; ++length) {
      const auto data = std::span<const std::uint8_t>(storage).subspan(offset, length);
      EXPECT_EQ(crypto::crc32(data), reference(data)) << offset << ":" << length;
    }
    for (const std::size_t length : {255u, 256u, 257u, 4095u, 4096u, 4097u, 65535u}) {
      const auto data = std::span<const std::uint8_t>(storage).subspan(offset, length);
      EXPECT_EQ(crypto::crc32(data), reference(data));
    }
  }
  for (int iteration = 0; iteration < 32; ++iteration) {
    const auto data = std::span<const std::uint8_t>(storage).subspan(
        rng() % 32, 128 + rng() % (1u << 20));
    EXPECT_EQ(crypto::crc32(data), reference(data));
  }
}

TEST(Crypto, Crc32cKnownVectorsAndIndependentReference) {
  // CRC-32C (Castagnoli) check value for "123456789" and the empty string.
  const std::string s = "123456789";
  const auto span =
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  EXPECT_EQ(crypto::crc32c(span), 0xe3069283u);
  EXPECT_EQ(crypto::crc32c({}), 0u);

  // Bitwise reference with the reflected Castagnoli polynomial: shares no table
  // or slicing logic with the implementation under test.
  const auto reference = [](std::span<const std::uint8_t> data) {
    std::uint32_t crc{0xffffffffu};
    for (const auto byte : data) {
      crc ^= byte;
      for (int bit = 0; bit < 8; ++bit)
        crc = (crc >> 1) ^ ((crc & 1u) ? 0x82f63b78u : 0u);
    }
    return crc ^ 0xffffffffu;
  };
  std::mt19937 rng(0x43524343u);
  Bytes storage((1u << 20) + 64);
  for (auto& byte : storage) byte = static_cast<std::uint8_t>(rng());
  for (std::size_t offset = 0; offset < 32; ++offset) {
    for (std::size_t length = 0; length < 128; ++length) {
      const auto data = std::span<const std::uint8_t>(storage).subspan(offset, length);
      EXPECT_EQ(crypto::crc32c(data), reference(data)) << offset << ":" << length;
    }
    for (const std::size_t length : {255u, 256u, 257u, 4095u, 4096u, 4097u, 65535u}) {
      const auto data = std::span<const std::uint8_t>(storage).subspan(offset, length);
      EXPECT_EQ(crypto::crc32c(data), reference(data));
    }
  }
  // CRC-32C and IEEE CRC-32 must not be interchangeable: a frame silently
  // checksummed with the wrong mode has to be rejected, not accepted.
  EXPECT_NE(crypto::crc32c(span), crypto::crc32(span));
}

TEST(Crypto, Crc32cPortableMatchesSelectedPath) {
  // The selected path is SSE4.2 on capable x86-64 CPUs and the portable
  // slicing-by-8 otherwise; both must agree on every length and alignment.
  std::mt19937 rng(0x53534534u);
  Bytes storage(70000);
  for (auto& byte : storage) byte = static_cast<std::uint8_t>(rng());
  for (std::size_t offset = 0; offset < 16; ++offset) {
    for (std::size_t length = 0; length <= 300; ++length) {
      const auto data = std::span<const std::uint8_t>(storage).subspan(offset, length);
      EXPECT_EQ(crypto::crc32c(data), crypto::crc32c_portable(data)) << offset << ":" << length;
    }
    for (const std::size_t length : {1023u, 1024u, 1025u, 16383u, 16384u, 65535u}) {
      const auto data = std::span<const std::uint8_t>(storage).subspan(offset, length);
      EXPECT_EQ(crypto::crc32c(data), crypto::crc32c_portable(data));
    }
  }
}

TEST(Crypto, AesCbcOutOfPlaceDecryptMatchesInPlace) {
  const auto key = arr<32>(from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  const auto iv = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));
  const auto plain = from_hex(
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
  Bytes cipher = plain;
  crypto::AesCbc enc(key, iv);
  enc.encrypt(cipher);

  crypto::AesCbc in_place_dec(key, iv);
  Bytes expected = cipher;
  in_place_dec.decrypt(expected);

  crypto::AesCbc out_of_place_dec(key, iv);
  Bytes actual(cipher.size());
  out_of_place_dec.decrypt(cipher, actual);
  EXPECT_EQ(actual, expected);
  EXPECT_EQ(actual, plain);
  EXPECT_THROW(out_of_place_dec.decrypt(cipher, std::span<std::uint8_t>(actual).first(16)),
               std::invalid_argument);
}


TEST(Crypto, AesStreamingUnalignedFourBlockKnownAnswers) {
  const auto key = arr<32>(from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  const auto plain = from_hex(
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
  const auto ctr_iv = arr<16>(from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  const auto ctr_cipher = from_hex(
      "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
      "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
  const auto cbc_iv = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));
  const auto cbc_cipher = from_hex(
      "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
      "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
  for (std::size_t offset = 1; offset <= 17; ++offset) {
    Bytes storage(plain.size() + offset + 1, 0xa5);
    auto data = std::span<std::uint8_t>(storage).subspan(offset, plain.size());
    std::copy(plain.begin(), plain.end(), data.begin());
    crypto::AesCtr enc(key, ctr_iv), dec(key, ctr_iv);
    for (std::size_t pos = 0; pos < data.size();) {
      const auto n = std::min((pos % 19) + 1, data.size() - pos);
      enc.apply(data.subspan(pos, n));
      enc.apply({});
      pos += n;
    }
    expect_bytes(data, ctr_cipher);
    dec.apply(data.first(31));
    dec.apply(data.subspan(31));
    expect_bytes(data, plain);
    crypto::AesCbc cbc_enc(key, cbc_iv), cbc_dec(key, cbc_iv);
    cbc_enc.encrypt(data.first(16));
    cbc_enc.encrypt({});
    cbc_enc.encrypt(data.subspan(16));
    expect_bytes(data, cbc_cipher);
    const Bytes before(data.begin(), data.end());
    EXPECT_THROW(cbc_enc.decrypt(data), std::logic_error);
    expect_bytes(data, before);
    cbc_dec.decrypt(data.first(48));
    cbc_dec.decrypt(data.subspan(48));
    expect_bytes(data, plain);
    EXPECT_THROW(cbc_dec.encrypt(data), std::logic_error);
    expect_bytes(data, plain);
    EXPECT_EQ(storage.front(), 0xa5);
    EXPECT_EQ(storage.back(), 0xa5);
  }
  crypto::AesCbc invalid(key, cbc_iv);
  Bytes short_block(15, 0x42);
  EXPECT_THROW(invalid.encrypt(short_block), std::invalid_argument);
  EXPECT_THROW(invalid.decrypt(short_block), std::invalid_argument);
  EXPECT_EQ(short_block, Bytes(15, 0x42));
  Bytes valid = cbc_cipher;
  invalid.decrypt(valid);  // rejected encryption must not latch the direction
  EXPECT_EQ(valid, plain);
}

TEST(Crypto, OversizeUpdatesRejectBeforeDataOrDirectionMutation) {
  // Reserve virtual address space, not 2 GiB of committed RAM. Unlike a forged
  // span over a tiny array this supplies a valid range, including under ASan.
  const auto size = static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1;
  void* mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  ASSERT_NE(mapping, MAP_FAILED);
  const auto unmap = [size](std::uint8_t* p) { (void)munmap(p, size); };
  const std::unique_ptr<std::uint8_t, decltype(unmap)> memory(
      static_cast<std::uint8_t*>(mapping), unmap);
  const std::span<std::uint8_t> oversized(memory.get(), size);
  oversized.front() = 0x5a;
  const A32 key{};
  const A16 iv{};
  crypto::AesCtr ctr(key, iv), reference(key, iv);
  EXPECT_THROW(ctr.apply(oversized), std::length_error);
  Bytes block(16), expected(16);
  ctr.apply(block);
  reference.apply(expected);
  EXPECT_EQ(block, expected);
  crypto::AesCbc cbc(key, iv), cbc_reference(key, iv);
  EXPECT_THROW(cbc.encrypt(oversized), std::length_error);
  EXPECT_THROW(cbc.decrypt(oversized), std::length_error);
  EXPECT_THROW(cbc.encrypt(oversized.first(size - 16)), std::length_error);
  EXPECT_THROW(cbc.decrypt(oversized.first(size - 16)), std::length_error);
  block.assign(16, 0);
  expected = block;
  cbc.decrypt(block);  // oversized encrypt must not latch encryption mode
  cbc_reference.decrypt(expected);
  EXPECT_EQ(block, expected);
  EXPECT_EQ(oversized.front(), 0x5a);
}

// ----------------------------- endpoint/KDF -----------------------------

TEST(Endpoint, Wire20Golden) {
  auto v4 = Endpoint::v4({203, 0, 113, 9}, 54321);
  EXPECT_EQ(v4.wire20(), arr<20>(from_hex("00000000000000000000ffffcb00710931d40000")));
  auto v6 = Endpoint::v6(arr<16>(from_hex("20010db8000000000000000000000001")), 54321);
  EXPECT_EQ(v6.wire20(), arr<20>(from_hex("20010db800000000000000000000000131d40000")));
}

TEST(MiddleProxyKdf, V4KnownAnswer) {
  MiddleProxyKdfInput in;
  in.nonce_server = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));
  in.nonce_client = arr<16>(from_hex("101112131415161718191a1b1c1d1e1f"));
  in.client_timestamp = 1600000000;
  in.server = Endpoint::v4({149, 154, 175, 50}, 8888);
  in.local = Endpoint::v4({203, 0, 113, 9}, 54321);
  in.secret = kSecret;

  auto keys = derive_middle_proxy_keys(in);
  EXPECT_EQ(keys.write_key, arr<32>(from_hex("c0b754f7556d3695748b2e23940619cb19ea987c3c7ae55ece1a8ec5803be610")));
  EXPECT_EQ(keys.write_iv, arr<16>(from_hex("837ee2c147cb70a7a8653f442dd2d596")));
  EXPECT_EQ(keys.read_key, arr<32>(from_hex("f36661bd6be44b4055caac5945e98fb4752e397bc014195d3dec0861c5ae6cc1")));
  EXPECT_EQ(keys.read_iv, arr<16>(from_hex("0ac4bffe527ce74a5b7538bc510813c4")));
}

TEST(MiddleProxyKdf, V6KnownAnswer) {
  MiddleProxyKdfInput in;
  in.nonce_server = arr<16>(from_hex("000102030405060708090a0b0c0d0e0f"));
  in.nonce_client = arr<16>(from_hex("101112131415161718191a1b1c1d1e1f"));
  in.client_timestamp = 1600000000;
  in.server = Endpoint::v6(arr<16>(from_hex("2001b28f23df0010000000000000000d")), 8888);
  in.local = Endpoint::v6(arr<16>(from_hex("20010db8000000000000000000000001")), 54321);
  in.secret = kSecret;

  auto keys = derive_middle_proxy_keys(in);
  EXPECT_EQ(keys.write_key, arr<32>(from_hex("c5edfcaf017f7ad0cb2aae15f0258e8ed97c439661e929ff47204f01a30eb1a8")));
  EXPECT_EQ(keys.write_iv, arr<16>(from_hex("c1827d2cf5f3c5c4ea01b5d81c61f934")));
  EXPECT_EQ(keys.read_key, arr<32>(from_hex("b3da6ae526d3a92a44124100be52e10b3165be572120371b53cc5a64102bf961")));
  EXPECT_EQ(keys.read_iv, arr<16>(from_hex("4b56699e8c9b9747807918237b2aba54")));
}

TEST(MiddleProxyKdf, RejectsBadInput) {
  MiddleProxyKdfInput in;
  in.nonce_server.fill(1);
  in.nonce_client.fill(2);
  in.client_timestamp = 1;
  in.server = Endpoint::v4({1, 2, 3, 4}, 8888);
  in.local = Endpoint::v4({5, 6, 7, 8}, 1000);
  EXPECT_THROW(derive_middle_proxy_keys(in), std::invalid_argument);  // empty secret
  in.secret = Bytes(400, 0x42);
  EXPECT_THROW(derive_middle_proxy_keys(in), std::invalid_argument);  // > 392 bytes
  in.secret = kSecret;
  in.local = Endpoint::v6(std::array<std::uint8_t, 16>{}, 1000);
  EXPECT_THROW(derive_middle_proxy_keys(in), std::invalid_argument);  // family mismatch
}

// ----------------------------- FakeTLS -----------------------------

// Golden ClientHello generated by the independent Python script described above.
constexpr std::string_view kClientHelloHex =
    "16030100810100007d0303e9554afbd8c6fccd0dd851be7043e8cac9904b7d18f4ef8b6b0dd0f274c3f4f220"
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00041301130301000030002b"
    "00020304003300260024001d0020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

TEST(FakeTls, ClientHelloKnownAnswer) {
  auto rec = from_hex(kClientHelloHex);
  ClientHelloInfo info;
  EXPECT_EQ(validate_client_hello(rec, kSecret, kNow, 120, info), HelloStatus::Ok);
  EXPECT_EQ(info.timestamp, 1600000000u);
  EXPECT_EQ(info.cipher, 0x1301);
  EXPECT_EQ(info.session_id, arr<32>(from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")));
  EXPECT_EQ(info.digest, arr<32>(from_hex("e9554afbd8c6fccd0dd851be7043e8cac9904b7d18f4ef8b6b0dd0f274c3f4f2")));
  EXPECT_FALSE(info.offers_pq);
  EXPECT_TRUE(info.server_name.empty());
}

TEST(Crypto, BufferedRandomServesFreshBytesAcrossRefills) {
  const auto random = buffered_random();
  std::set<Bytes> seen;
  std::size_t served = 0;
  // Small requests cross several 4 KiB refills; large ones bypass the block.
  for (const std::size_t size : {1U, 3U, 16U, 32U, 257U, 4096U}) {
    for (int round = 0; round < 300; ++round) {
      Bytes out(size, 0);
      random(out);
      served += size;
      if (size >= 16) {
        EXPECT_TRUE(seen.insert(out).second) << "repeated block of " << size;
        EXPECT_NE(out, Bytes(size, 0));
      }
    }
  }
  EXPECT_GT(served, 3U * 4096U);
  Bytes empty;
  random(empty);
}

TEST(Crypto, PrekeyedHmacMatchesOneShotHmac) {
  A16 key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 7 + 1);
  const crypto::HmacSha256Key keyed(key);
  for (const std::size_t size : {0U, 1U, 55U, 64U, 517U, 4096U}) {
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i) data[i] = static_cast<std::uint8_t>(i ^ 0xa5);
    EXPECT_EQ(keyed.mac(data), crypto::hmac_sha256(key, data)) << size;
    // The keyed state is reusable: a second call gives the same answer.
    EXPECT_EQ(keyed.mac(data), crypto::hmac_sha256(key, data)) << size;
  }
  crypto::HmacSha256Key source(key);
  crypto::HmacSha256Key moved(std::move(source));
  EXPECT_EQ(moved.mac(Bytes{1, 2, 3}), crypto::hmac_sha256(key, Bytes{1, 2, 3}));
}

TEST(FakeTls, ClientHelloMultiKeyPicksFirstMatchingKey) {
  auto rec = from_hex(kClientHelloHex);
  A16 wrong{};
  wrong.fill(0x5a);
  const crypto::HmacSha256Key bad_key(wrong);
  const crypto::HmacSha256Key good_key(kSecret);
  const crypto::HmacSha256Key* keys[] = {&bad_key, nullptr, &good_key, &good_key};
  ClientHelloInfo info;
  std::size_t matched = 99;
  ASSERT_EQ(validate_client_hello(rec, keys, kNow, 120, info, matched), HelloStatus::Ok);
  EXPECT_EQ(matched, 2U);
  EXPECT_EQ(info.timestamp, 1600000000u);
  EXPECT_EQ(info.secret, kSecret);
  ClientHelloInfo single;
  ASSERT_EQ(validate_client_hello(rec, kSecret, kNow, 120, single), HelloStatus::Ok);
  EXPECT_EQ(info.canonical_hmac, single.canonical_hmac);

  const crypto::HmacSha256Key* only_bad[] = {&bad_key};
  EXPECT_EQ(validate_client_hello(rec, only_bad, kNow, 120, info, matched),
            HelloStatus::Unauthenticated);
  EXPECT_EQ(validate_client_hello(rec, std::span<const crypto::HmacSha256Key* const>{}, kNow,
                                  120, info, matched),
            HelloStatus::Unauthenticated);
  EXPECT_EQ(validate_client_hello(rec, keys, kNow + 121, 120, info, matched),
            HelloStatus::ClockSkew);
}

TEST(FakeTls, ClientHelloRejectsTamperWrongSecretAndSkew) {
  auto rec = from_hex(kClientHelloHex);
  ClientHelloInfo info;
  A16 wrong{};
  wrong.fill(0x5a);
  EXPECT_EQ(validate_client_hello(rec, wrong, kNow, 120, info), HelloStatus::Unauthenticated);

  auto bad = rec;
  bad[45] ^= 0x01;
  EXPECT_EQ(validate_client_hello(bad, kSecret, kNow, 120, info), HelloStatus::Unauthenticated);

  EXPECT_EQ(validate_client_hello(rec, kSecret, kNow + 121, 120, info), HelloStatus::ClockSkew);

  auto truncated = rec;
  truncated.resize(50);
  EXPECT_EQ(validate_client_hello(truncated, kSecret, kNow, 120, info), HelloStatus::NeedMoreData);

  auto not_tls = rec;
  not_tls[0] = 0x15;
  EXPECT_EQ(validate_client_hello(not_tls, kSecret, kNow, 120, info), HelloStatus::NotTls);
}

TEST(FakeTls, ServerHelloNonPqGolden) {
  auto rec = from_hex(kClientHelloHex);
  ClientHelloInfo info;
  ASSERT_EQ(validate_client_hello(rec, kSecret, kNow, 120, info), HelloStatus::Ok);
  CountingRng rng;
  auto sh = build_server_hello(info, rng.fn());
  ASSERT_EQ(sh.size(), 3016u);
  EXPECT_EQ(crypto::sha256(sh),
            arr<32>(from_hex("36409ca31d0e7cdc7da0f2570151fe82ff29fc56b50eb477497d34c9b3d88c77")));
  auto prefix = from_hex(
      "160303007a0200007603031dd1e689041d5d338af0012d3b4ba92b0961d54a22f809853eb00d2921124d0620"
      "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f130100002e002b00020304"
      "00330024001d0020303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f14030300"
      "01011703030b3e101112131415161718191a1b1c1d1e1f202122232425");
  EXPECT_TRUE(std::equal(prefix.begin(), prefix.end(), sh.begin()));
  expect_bytes(std::span<const std::uint8_t>(sh).subspan(11, 32),
               from_hex("1dd1e689041d5d338af0012d3b4ba92b0961d54a22f809853eb00d2921124d06"));

  // Client-side verification described by the reference: HMAC over
  // digest || response-with-zeroed-server-random.
  Bytes zeroed = sh;
  std::fill(zeroed.begin() + 11, zeroed.begin() + 43, 0);
  auto expect = crypto::hmac_sha256(info.secret, cat({Bytes(info.digest.begin(), info.digest.end()), zeroed}));
  expect_bytes(std::span<const std::uint8_t>(sh).subspan(11, 32), expect);
}

}  // namespace

TEST(FakeTls, ServerHelloPqStructure) {
  auto rec = make_client_hello(kSecret, 1600000000, 0x11ec, 1216);
  ClientHelloInfo info;
  ASSERT_EQ(validate_client_hello(rec, kSecret, kNow, 120, info), HelloStatus::Ok);
  EXPECT_TRUE(info.offers_pq);
  CountingRng rng;
  auto sh = build_server_hello(info, rng.fn());
  ASSERT_EQ(sh.size(), 4104u);
  EXPECT_EQ(rd16be(sh, 3), 1210);   // ServerHello record payload
  EXPECT_EQ(rd16be(sh, 91), 0x11ec);
  EXPECT_EQ(rd16be(sh, 93), 1120);  // server share = ML-KEM ciphertext 1088 + X25519 32
  EXPECT_EQ(sh[1215], 0x14);        // CCS
  EXPECT_EQ(rd16be(sh, 1224), 2878);  // AppData body length
  Bytes zeroed = sh;
  std::fill(zeroed.begin() + 11, zeroed.begin() + 43, 0);
  auto expect = crypto::hmac_sha256(info.secret, cat({Bytes(info.digest.begin(), info.digest.end()), zeroed}));
  expect_bytes(std::span<const std::uint8_t>(sh).subspan(11, 32), expect);
}

namespace {

Bytes tls_wrap(std::uint8_t type, std::span<const std::uint8_t> body) {
  return cat({Bytes{type, 0x03, 0x03}, be16(static_cast<std::uint16_t>(body.size())), Bytes(body.begin(), body.end())});
}

struct ClientObfuscation {
  Bytes wire;      // what the client sends (first 56 plaintext, last 8 encrypted)
  A32 dec_key;     // client -> proxy
  A16 dec_iv;
  A32 enc_key;     // proxy -> client
  A16 enc_iv;
};

ClientObfuscation make_client_obfuscation(const A16& secret, std::uint32_t tag, std::int16_t dc) {
  Bytes raw(64);
  for (std::size_t i = 0; i < 64; ++i) raw[i] = static_cast<std::uint8_t>(i);
  for (int i = 0; i < 4; ++i) raw[56 + i] = static_cast<std::uint8_t>(tag >> (8 * i));
  raw[60] = static_cast<std::uint8_t>(dc);
  raw[61] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(dc) >> 8);

  auto prekey = std::span<const std::uint8_t>(raw).subspan(8, 32);
  auto iv = std::span<const std::uint8_t>(raw).subspan(40, 16);

  ClientObfuscation out;
  out.dec_key = crypto::sha256(cat({prekey, std::span<const std::uint8_t>(secret)}));
  std::copy(iv.begin(), iv.end(), out.dec_iv.begin());

  Bytes rev;
  for (auto it = raw.rbegin() + 8; it != raw.rend() - 8; ++it) rev.push_back(*it);
  // The 48-byte slice raw[8..56] reversed.
  rev.clear();
  for (int i = 55; i >= 8; --i) rev.push_back(raw[static_cast<std::size_t>(i)]);
  out.enc_key = crypto::sha256(cat({std::span<const std::uint8_t>(rev).first(32), std::span<const std::uint8_t>(secret)}));
  std::copy(rev.begin() + 32, rev.end(), out.enc_iv.begin());

  crypto::AesCtr client_enc(out.dec_key, out.dec_iv);
  Bytes enc = raw;
  client_enc.apply(enc);
  out.wire.assign(raw.begin(), raw.begin() + 56);
  out.wire.insert(out.wire.end(), enc.begin() + 56, enc.end());
  return out;
}

TEST(FakeTls, PqClientShareSizeAndCipherRules) {
  // Real X25519MLKEM768 client offer: X25519 32 + ML-KEM-768 public key 1184 = 1216.
  auto pq = make_client_hello(kSecret, 1600000000, 0x11ec, 1216);
  ClientHelloInfo info;
  ASSERT_EQ(validate_client_hello(pq, kSecret, kNow, 120, info), HelloStatus::Ok);
  EXPECT_TRUE(info.offers_pq);

  // A 1120-byte 0x11ec share is the server share size, not a valid client offer;
  // it must not trigger the PQ ServerHello path.
  auto bad_pq = make_client_hello(kSecret, 1600000000, 0x11ec, 1120);
  ClientHelloInfo info2;
  ASSERT_EQ(validate_client_hello(bad_pq, kSecret, kNow, 120, info2), HelloStatus::Ok);
  EXPECT_FALSE(info2.offers_pq);

  // No TLS 1.3 suite offered -> Invalid; do not invent 1301.
  auto legacy = make_client_hello(kSecret, 1600000000, 0x001d, 32, 0x1301, "", false);
  ClientHelloInfo info3;
  EXPECT_EQ(validate_client_hello(legacy, kSecret, kNow, 120, info3), HelloStatus::Invalid);
}

TEST(FakeTls, SniParsedAndEnforced) {
  auto hello = make_client_hello(kSecret, 1600000000, 0x001d, 32, 0x1301, "Example.ORG");
  ClientHelloInfo info;
  ASSERT_EQ(validate_client_hello(hello, kSecret, kNow, 120, info), HelloStatus::Ok);
  EXPECT_EQ(info.server_name, "Example.ORG");

  auto run = [&](std::optional<std::string> expected) {
    FakeTlsConnection::Config cfg;
    cfg.secret = kSecret;
    CountingRng rng;
    cfg.random = rng.fn();
    cfg.clock = [] { return kNow; };
    cfg.expected_server_name = std::move(expected);
    FakeTlsConnection conn(cfg);
    std::vector<std::uint8_t> to_client, plain;
    const Status st = conn.feed(hello, to_client, plain);
    return std::pair<Status, FakeTlsConnection::State>(st, conn.state());
  };
  auto ok = run(std::string("example.org"));
  EXPECT_EQ(ok.first, Status::Ok);
  EXPECT_EQ(ok.second, FakeTlsConnection::State::Obfuscation);
  auto bad = run(std::string("other.example"));
  EXPECT_EQ(bad.first, Status::ProtocolError);
  auto missing = run(std::nullopt);
  EXPECT_EQ(missing.first, Status::Ok);  // no enforcement when unset
}

TEST(FakeTls, RejectsMalformedExtensionLength) {
  auto hello = from_hex(kClientHelloHex);
  // Extension total length at offset 84 in this golden hello; make it overrun.
  EXPECT_EQ(rd16be(hello, 84), 0x0030);
  hello[85] = 0x31;
  reseal_client_hello(hello, kSecret, 1600000000);
  ClientHelloInfo info;
  EXPECT_EQ(validate_client_hello(hello, kSecret, kNow, 120, info), HelloStatus::Invalid);
}

}  // namespace

TEST(FakeTls, ObfuscationParseAndReserved) {
  auto c = make_client_obfuscation(kSecret, 0xdddddddd, 3);
  ObfuscationParams p;
  EXPECT_EQ(parse_obfuscation_handshake(c.wire, kSecret, p), ObfuscationStatus::Ok);
  EXPECT_EQ(p.tag, ProtoTag::Secure);
  EXPECT_EQ(p.dc_id, 3);

  A16 wrong{};
  wrong.fill(0x77);
  ObfuscationParams p2;
  EXPECT_EQ(parse_obfuscation_handshake(c.wire, wrong, p2), ObfuscationStatus::Invalid);

  auto abridged = make_client_obfuscation(kSecret, 0xefefefef, 1);
  EXPECT_EQ(parse_obfuscation_handshake(abridged.wire, kSecret, p2), ObfuscationStatus::UnsupportedTag);

  auto reserved = c.wire;
  reserved[0] = 0xef;
  EXPECT_EQ(parse_obfuscation_handshake(reserved, kSecret, p2), ObfuscationStatus::ReservedNonce);
}

TEST(FakeTls, HandshakeEverySplitPointAndRecords) {
  auto hello = from_hex(kClientHelloHex);
  auto sh_golden = [&] {
    ClientHelloInfo info;
    EXPECT_EQ(validate_client_hello(hello, kSecret, kNow, 120, info), HelloStatus::Ok);
    CountingRng rng;
    return build_server_hello(info, rng.fn());
  }();

  for (std::size_t split = 1; split < hello.size(); ++split) {
    FakeTlsConnection::Config cfg;
    cfg.secret = kSecret;
    CountingRng rng;
    cfg.random = rng.fn();
    cfg.clock = [] { return kNow; };
    FakeTlsConnection conn(cfg);
    std::vector<std::uint8_t> to_client, plain;
    auto st = conn.feed(std::span<const std::uint8_t>(hello).first(split), to_client, plain);
    EXPECT_EQ(st, Status::NeedMoreData) << "split=" << split;
    st = conn.feed(std::span<const std::uint8_t>(hello).subspan(split), to_client, plain);
    EXPECT_EQ(st, Status::Ok) << "split=" << split;
    EXPECT_EQ(conn.state(), FakeTlsConnection::State::Obfuscation) << "split=" << split;
    EXPECT_EQ(to_client, sh_golden) << "split=" << split;
    EXPECT_TRUE(plain.empty());
  }

  // Byte-at-a-time, then CCS + obfuscation handshake + one payload, over several
  // app-data records with deliberately awkward boundaries.
  auto obf = make_client_obfuscation(kSecret, 0xdddddddd, 2);
  Bytes payload = from_hex("deadbeef0102030405060708");
  Bytes client_stream;
  {
    crypto::AesCtr c(obf.dec_key, obf.dec_iv);
    c.skip(64);
    Bytes enc = payload;
    c.apply(enc);
    client_stream = enc;
  }

  FakeTlsConnection::Config cfg;
  cfg.secret = kSecret;
  CountingRng rng;
  cfg.random = rng.fn();
  cfg.clock = [] { return kNow; };
  FakeTlsConnection conn(cfg);
  std::vector<std::uint8_t> to_client, plain;

  Bytes wire = hello;  // already a complete TLS 1.2-compatible ClientHello record
  wire = cat({wire, tls_wrap(0x14, from_hex("01"))});
  Bytes body = cat({obf.wire, client_stream});
  for (std::size_t off = 0; off < body.size(); off += 7) {
    Bytes rec = tls_wrap(0x17, std::span<const std::uint8_t>(body).subspan(off, std::min<std::size_t>(7, body.size() - off)));
    wire = cat({wire, rec});
  }
  for (std::size_t i = 0; i + 1 < wire.size(); ++i) {
    EXPECT_NE(conn.feed(std::span<const std::uint8_t>(wire).subspan(i, 1), to_client, plain),
              Status::ProtocolError);
  }
  EXPECT_EQ(conn.feed(std::span<const std::uint8_t>(wire).subspan(wire.size() - 1), to_client, plain), Status::Ok);
  EXPECT_EQ(conn.state(), FakeTlsConnection::State::Ready);
  EXPECT_EQ(conn.proto_tag(), ProtoTag::Secure);
  EXPECT_EQ(conn.dc_id(), 2);
  EXPECT_EQ(plain, payload);

  // Server -> client: encrypt with the client's decrypt stream and TLS-wrap.
  Bytes to_peer;
  ASSERT_EQ(conn.send(from_hex("cafebabe00112233"), to_peer), Status::Ok);
  ASSERT_GE(to_peer.size(), 5u);
  EXPECT_EQ(to_peer[0], 0x17);
  EXPECT_EQ(rd16be(to_peer, 3), 8);
  Bytes dec = Bytes(to_peer.begin() + 5, to_peer.end());
  crypto::AesCtr client_dec(obf.enc_key, obf.enc_iv);
  client_dec.apply(dec);
  EXPECT_EQ(dec, from_hex("cafebabe00112233"));
}

TEST(FakeTls, FusedTransportSendMatchesTwoStepSend) {
  // A ready FakeTLS connection with a deterministic handshake. Both instances
  // below are driven by identical inputs, so their AES-CTR streams match.
  auto make_ready_conn = [] {
    auto obf = make_client_obfuscation(kSecret, 0xdddddddd, 4);
    FakeTlsConnection::Config cfg;
    cfg.secret = kSecret;
    CountingRng rng;
    cfg.random = rng.fn();
    cfg.clock = [] { return kNow; };
    FakeTlsConnection conn(cfg);
    std::vector<std::uint8_t> to_client, plain;
    Bytes wire = cat({from_hex(kClientHelloHex), tls_wrap(0x14, from_hex("01")),
                      tls_wrap(0x17, obf.wire)});
    EXPECT_EQ(conn.feed(wire, to_client, plain), Status::Ok);
    EXPECT_EQ(conn.state(), FakeTlsConnection::State::Ready);
    return conn;
  };

  for (const std::size_t size : {4u, 12u, 4096u, 16384u, 20000u, 65536u}) {
    for (std::uint64_t seed : {0u, 1u, 2u, 3u}) {
      Bytes payload(size);
      for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i * 31 + size);
      }
      auto conn_a = make_ready_conn();
      auto conn_b = make_ready_conn();
      CountingRng rng_a;
      CountingRng rng_b;
      rng_a.total = seed;
      rng_b.total = seed;

      Bytes frame;
      const auto fn_a = rng_a.fn();
      encode_transport_message(ProtoTag::Secure, payload, frame, &fn_a);
      Bytes out_a;
      ASSERT_EQ(conn_a.send(frame, out_a), Status::Ok);

      Bytes out_b;
      const auto fn_b = rng_b.fn();
      ASSERT_EQ(conn_b.send_transport_message(ProtoTag::Secure, payload, out_b, fn_b), Status::Ok);

      EXPECT_EQ(out_a, out_b) << "size=" << size << " seed=" << seed;
      EXPECT_EQ(rng_a.total, rng_b.total) << "random consumption must match";

      // The decrypted TLS bodies reproduce the two-step transport frame.
      const auto obf = make_client_obfuscation(kSecret, 0xdddddddd, 4);
      crypto::AesCtr client_dec(obf.enc_key, obf.enc_iv);
      Bytes bodies;
      std::size_t off = 0;
      while (off < out_b.size()) {
        ASSERT_GE(out_b.size() - off, 5u);
        EXPECT_EQ(out_b[off], 0x17);
        const std::size_t len = rd16be(out_b, off + 3);
        ASSERT_GE(out_b.size() - off - 5, len);
        Bytes chunk(out_b.begin() + static_cast<std::ptrdiff_t>(off + 5),
                    out_b.begin() + static_cast<std::ptrdiff_t>(off + 5 + len));
        client_dec.apply(chunk);
        bodies.insert(bodies.end(), chunk.begin(), chunk.end());
        off += 5 + len;
      }
      EXPECT_EQ(bodies, frame) << "size=" << size << " seed=" << seed;
    }
  }
}

TEST(FakeTls, FullWireEverySplitPoint) {
  auto hello = from_hex(kClientHelloHex);
  auto obf = make_client_obfuscation(kSecret, 0xdddddddd, 2);
  Bytes payload = from_hex("deadbeef0102030405060708");
  Bytes stream;
  {
    crypto::AesCtr c(obf.dec_key, obf.dec_iv);
    c.skip(64);
    stream = payload;
    c.apply(stream);
  }

  Bytes wire = hello;
  wire = cat({wire, tls_wrap(0x14, from_hex("01"))});
  Bytes body = cat({obf.wire, stream});
  for (std::size_t off = 0; off < body.size(); off += 7) {
    Bytes rec = tls_wrap(0x17, std::span<const std::uint8_t>(body).subspan(off, std::min<std::size_t>(7, body.size() - off)));
    wire = cat({wire, rec});
  }

  for (std::size_t split = 1; split < wire.size(); ++split) {
    FakeTlsConnection::Config cfg;
    cfg.secret = kSecret;
    CountingRng rng;
    cfg.random = rng.fn();
    cfg.clock = [] { return kNow; };
    FakeTlsConnection conn(cfg);
    std::vector<std::uint8_t> to_client, plain;
    EXPECT_NE(conn.feed(std::span<const std::uint8_t>(wire).first(split), to_client, plain),
              Status::ProtocolError) << "split=" << split;
    EXPECT_NE(conn.feed(std::span<const std::uint8_t>(wire).subspan(split), to_client, plain),
              Status::ProtocolError) << "split=" << split;
    ASSERT_EQ(conn.state(), FakeTlsConnection::State::Ready) << "split=" << split;
    EXPECT_EQ(plain, payload) << "split=" << split;
    EXPECT_FALSE(to_client.empty()) << "split=" << split;
    EXPECT_LT(conn.retained_bytes(), 128u * 1024u) << "split=" << split;
  }
}

TEST(FakeTls, RejectsOversizeAndUnsupportedTag) {
  auto hello = from_hex(kClientHelloHex);
  FakeTlsConnection::Config cfg;
  cfg.secret = kSecret;
  CountingRng rng;
  cfg.random = rng.fn();
  cfg.clock = [] { return kNow; };
  cfg.max_client_hello = 64;
  FakeTlsConnection small(cfg);
  std::vector<std::uint8_t> to_client, plain;
  EXPECT_EQ(small.feed(hello, to_client, plain), Status::ProtocolError);

  auto obf = make_client_obfuscation(kSecret, 0xefefefef, 1);
  FakeTlsConnection::Config cfg2;
  cfg2.secret = kSecret;
  CountingRng rng2;
  cfg2.random = rng2.fn();
  cfg2.clock = [] { return kNow; };
  FakeTlsConnection conn(cfg2);
  Bytes wire = hello;
  wire = cat({wire, tls_wrap(0x14, from_hex("01")), tls_wrap(0x17, obf.wire)});
  EXPECT_EQ(conn.feed(wire, to_client, plain), Status::ProtocolError);
  EXPECT_EQ(conn.state(), FakeTlsConnection::State::Failed);
}

TEST(Robustness, MalformedInputsFailClosedWithoutCrash) {
  std::mt19937 rng(0x4d544444u);
  std::uniform_int_distribution<int> len_dist(0, 300);
  std::uniform_int_distribution<int> byte_dist(0, 255);

  for (int iter = 0; iter < 400; ++iter) {
    Bytes junk(static_cast<std::size_t>(len_dist(rng)));
    for (auto& b : junk) b = static_cast<std::uint8_t>(byte_dist(rng));

    TransportDecoder dec({(iter & 1) ? ProtoTag::Secure : ProtoTag::Intermediate, 512});
    std::vector<TransportDecoder::Message> msgs;
    (void)dec.feed(junk, msgs);

    FakeTlsConnection::Config cfg;
    cfg.secret = kSecret;
    CountingRng crng;
    cfg.random = crng.fn();
    cfg.clock = [] { return kNow; };
    FakeTlsConnection conn(cfg);
    std::vector<std::uint8_t> to_client, plain;
    (void)conn.feed(junk, to_client, plain);
    EXPECT_TRUE(conn.state() == FakeTlsConnection::State::ClientHello ||
                conn.state() == FakeTlsConnection::State::Failed ||
                conn.state() == FakeTlsConnection::State::Obfuscation);
  }
}

TEST(FakeTls, AcceptsMultipleRecordsIn32KiBBatch) {
  auto hello = from_hex(kClientHelloHex);
  auto obf = make_client_obfuscation(kSecret, 0xdddddddd, 2);
  Bytes payload(40000);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i * 13 + 7);

  Bytes stream = payload;
  {
    crypto::AesCtr c(obf.dec_key, obf.dec_iv);
    c.skip(64);
    c.apply(stream);
  }
  Bytes body = cat({obf.wire, stream});
  Bytes records;
  for (std::size_t off = 0; off < body.size(); off += 10000) {
    records = cat({records, tls_wrap(0x17, std::span<const std::uint8_t>(body).subspan(
                                              off, std::min<std::size_t>(10000, body.size() - off)))});
  }
  records = cat({tls_wrap(0x14, from_hex("01")), records});

  FakeTlsConnection::Config cfg;
  cfg.secret = kSecret;
  CountingRng rng;
  cfg.random = rng.fn();
  cfg.clock = [] { return kNow; };
  FakeTlsConnection conn(cfg);
  std::vector<std::uint8_t> to_client, plain;
  ASSERT_EQ(conn.feed(hello, to_client, plain), Status::Ok);
  ASSERT_EQ(conn.state(), FakeTlsConnection::State::Obfuscation);
  // One recv() batch of ~40 KiB, all records complete.
  ASSERT_EQ(conn.feed(records, to_client, plain), Status::Ok);
  EXPECT_EQ(conn.state(), FakeTlsConnection::State::Ready);
  EXPECT_EQ(plain, payload);
}

TEST(FakeTls, Accepts16KiBRecordsIn12KiBChunks) {
  auto hello = from_hex(kClientHelloHex);
  auto obf = make_client_obfuscation(kSecret, 0xdddddddd, 2);
  Bytes payload(32768);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i * 5 + 3);

  Bytes stream = payload;
  {
    crypto::AesCtr c(obf.dec_key, obf.dec_iv);
    c.skip(64);
    c.apply(stream);
  }
  Bytes body = cat({obf.wire, stream});
  Bytes records;
  for (std::size_t off = 0; off < body.size(); off += 16384) {
    records = cat({records, tls_wrap(0x17, std::span<const std::uint8_t>(body).subspan(
                                              off, std::min<std::size_t>(16384, body.size() - off)))});
  }
  records = cat({tls_wrap(0x14, from_hex("01")), records});

  FakeTlsConnection::Config cfg;
  cfg.secret = kSecret;
  CountingRng rng;
  cfg.random = rng.fn();
  cfg.clock = [] { return kNow; };
  FakeTlsConnection conn(cfg);
  std::vector<std::uint8_t> to_client, plain;
  ASSERT_EQ(conn.feed(hello, to_client, plain), Status::Ok);
  for (std::size_t off = 0; off < records.size(); off += 12000) {
    auto st = conn.feed(std::span<const std::uint8_t>(records).subspan(
                            off, std::min<std::size_t>(12000, records.size() - off)),
                        to_client, plain);
    EXPECT_NE(st, Status::ProtocolError) << "chunk=" << off;
  }
  EXPECT_EQ(conn.state(), FakeTlsConnection::State::Ready);
  EXPECT_EQ(plain, payload);
}

// ----------------------------- transport codec -----------------------------

TEST(Transport, IntermediateFragmentedAndQuickAck) {
  auto tag = ProtoTag::Intermediate;
  TransportDecoder dec({tag, 1 << 20});
  Bytes p1 = from_hex("01020304");
  Bytes p2 = from_hex("05060708090a0b0c");
  Bytes wire = cat({le32(4), p1, le32(0x80000008), p2});
  std::vector<TransportDecoder::Message> msgs;
  for (std::size_t i = 0; i < wire.size(); ++i) {
    auto st = dec.feed(std::span<const std::uint8_t>(wire).subspan(i, 1), msgs);
    EXPECT_NE(st, Status::ProtocolError) << "byte=" << i;
  }
  ASSERT_EQ(msgs.size(), 2u);
  EXPECT_EQ(msgs[0].data, p1);
  EXPECT_FALSE(msgs[0].quick_ack);
  EXPECT_EQ(msgs[1].data, p2);
  EXPECT_TRUE(msgs[1].quick_ack);
}

TEST(Transport, SecurePaddingAndEncoding) {
  auto tag = ProtoTag::Secure;
  CountingRng rng;
  Bytes msg = from_hex("11223344");
  Bytes wire;
  auto random = rng.fn();
  encode_transport_message(tag, msg, wire, &random);
  ASSERT_GE(wire.size(), 8u);
  std::uint32_t declared = rd32(wire);
  EXPECT_GE(declared, 4u);
  EXPECT_LE(declared, 7u);
  TransportDecoder dec({tag, 1 << 20});
  std::vector<TransportDecoder::Message> msgs;
  // Split every boundary.
  for (std::size_t i = 0; i < wire.size(); ++i) dec.feed(std::span<const std::uint8_t>(wire).subspan(i, 1), msgs);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, msg);

  Bytes ack;
  encode_quick_ack(tag, {1, 2, 3, 4}, ack);
  EXPECT_EQ(ack, from_hex("01020304"));
}

TEST(Transport, RejectsMalformedAndUnsupported) {
  EXPECT_THROW(TransportDecoder({ProtoTag::Abridged, 1 << 20}), std::invalid_argument);
  {
    TransportDecoder dec({ProtoTag::Intermediate, 16});
    Bytes wire = le32(17);
    std::vector<TransportDecoder::Message> msgs;
    EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);
  }
  {
    TransportDecoder dec({ProtoTag::Intermediate, 1 << 20});
    Bytes wire = le32(0);
    std::vector<TransportDecoder::Message> msgs;
    EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);
  }
  {
    TransportDecoder dec({ProtoTag::Secure, 1 << 20});
    Bytes wire = cat({le32(3), from_hex("aabbcc")});
    std::vector<TransportDecoder::Message> msgs;
    EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);  // all padding
  }
}

}  // namespace mtdd::protocol

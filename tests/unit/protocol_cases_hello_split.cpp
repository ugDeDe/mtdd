// FakeTLS ClientHello split over several TLS handshake records.
//
// DPI-circumvention tools on users' routers (ByeDPI --tlsrec, zapret) cut the
// ClientHello record into several handshake records, the first carrying as
// little as 1-3 body bytes. scan_client_hello() classifies a received prefix;
// reassemble_client_hello() rebuilds the single record the client signed.
#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {

namespace {

constexpr std::uint32_t kTs = static_cast<std::uint32_t>(kNow);

Bytes valid_hello() { return make_client_hello(kSecret, kTs, 0x001d, 32, 0x1301, "example.com"); }

Bytes record_header(std::uint8_t type, std::uint8_t major, std::uint8_t minor, std::size_t length) {
  return {type, major, minor, static_cast<std::uint8_t>(length >> 8),
          static_cast<std::uint8_t>(length)};
}

// Re-frames the body of one ClientHello record as consecutive handshake
// records whose bodies have `sizes` bytes; the last record takes the rest.
// Every fragment keeps the original record version.
Bytes split(const Bytes& record, std::initializer_list<std::size_t> sizes) {
  const auto body = std::span<const std::uint8_t>(record).subspan(5);
  Bytes out;
  std::size_t pos = 0;
  for (const std::size_t size : sizes) {
    out = cat({out, record_header(0x16, record[1], record[2], size),
               Bytes(body.begin() + static_cast<std::ptrdiff_t>(pos),
                     body.begin() + static_cast<std::ptrdiff_t>(pos + size))});
    pos += size;
  }
  if (pos < body.size()) {
    out = cat({out, record_header(0x16, record[1], record[2], body.size() - pos),
               Bytes(body.begin() + static_cast<std::ptrdiff_t>(pos), body.end())});
  }
  return out;
}

// `count` records of (almost) equal size.
Bytes split_even(const Bytes& record, std::size_t count) {
  const auto body = std::span<const std::uint8_t>(record).subspan(5);
  Bytes out;
  std::size_t pos = 0;
  for (std::size_t i = 0; i < count; ++i) {
    const std::size_t size = body.size() / count + (i < body.size() % count ? 1 : 0);
    out = cat({out, record_header(0x16, record[1], record[2], size),
               Bytes(body.begin() + static_cast<std::ptrdiff_t>(pos),
                     body.begin() + static_cast<std::ptrdiff_t>(pos + size))});
    pos += size;
  }
  return out;
}

HelloStatus validate(std::span<const std::uint8_t> record, const A16& secret = kSecret) {
  ClientHelloInfo info;
  return validate_client_hello(record, secret, kNow, 120, info);
}

// Feeds `wire` the way the runtime reads it: never more than `want` bytes at
// a time (and at most `chunk`). Returns the final scan and how much was read.
ClientHelloScan feed_like_runtime(const Bytes& wire, std::size_t chunk, std::size_t& read) {
  read = 0;
  ClientHelloScan scan = scan_client_hello({});
  while (scan.status == HelloStatus::NeedMoreData && read < wire.size()) {
    EXPECT_GE(scan.want, 1u);
    const std::size_t take = std::min({scan.want, chunk, wire.size() - read});
    read += take;
    scan = scan_client_hello(std::span<const std::uint8_t>(wire).first(read));
  }
  return scan;
}

}  // namespace

TEST(HelloSplit, UnsplitHelloIsUnchanged) {
  const Bytes rec = valid_hello();
  const auto scan = scan_client_hello(rec);
  EXPECT_EQ(scan.status, HelloStatus::Ok);
  EXPECT_EQ(scan.records, 1u);
  EXPECT_EQ(reassemble_client_hello(rec), rec);
  EXPECT_EQ(validate(rec), HelloStatus::Ok);

  // The record body is requested whole right after the header, as before.
  const auto header = scan_client_hello(std::span<const std::uint8_t>(rec).first(5));
  EXPECT_EQ(header.status, HelloStatus::NeedMoreData);
  EXPECT_EQ(header.want, rec.size() - 5);
  for (std::size_t n = 0; n < 5; ++n) {
    const auto partial = scan_client_hello(std::span<const std::uint8_t>(rec).first(n));
    EXPECT_EQ(partial.status, HelloStatus::NeedMoreData);
    EXPECT_EQ(partial.want, 5 - n);
  }
}

TEST(HelloSplit, ShortFirstFragmentsAuthenticateAsTheOriginalRecord) {
  const Bytes rec = valid_hello();
  for (const std::size_t first : {1u, 2u, 3u, 4u, 5u, 100u}) {
    SCOPED_TRACE(first);
    const Bytes wire = split(rec, {first});
    const auto scan = scan_client_hello(wire);
    EXPECT_EQ(scan.status, HelloStatus::Ok);
    EXPECT_EQ(scan.records, 2u);
    const Bytes canonical = reassemble_client_hello(wire);
    EXPECT_EQ(canonical, rec);
    EXPECT_EQ(validate(canonical), HelloStatus::Ok);
    // Authentication never accepts the fragmented wire bytes themselves.
    EXPECT_NE(validate(wire), HelloStatus::Ok);
  }
}

TEST(HelloSplit, TwoAndSixteenFragmentsAreAccepted) {
  const Bytes rec = valid_hello();
  for (const std::size_t count : {2u, 7u, 16u}) {
    SCOPED_TRACE(count);
    const Bytes wire = split_even(rec, count);
    const auto scan = scan_client_hello(wire);
    EXPECT_EQ(scan.status, HelloStatus::Ok);
    EXPECT_EQ(scan.records, count);
    EXPECT_EQ(reassemble_client_hello(wire), rec);
    EXPECT_EQ(validate(reassemble_client_hello(wire)), HelloStatus::Ok);
  }
  // Tiny fragments everywhere: 15 one-byte records, then the rest.
  const Bytes tiny = split(rec, {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1});
  EXPECT_EQ(scan_client_hello(tiny).status, HelloStatus::Ok);
  EXPECT_EQ(reassemble_client_hello(tiny), rec);
}

TEST(HelloSplit, SeventeenFragmentsAreRejectedWithoutReadingTheSeventeenth) {
  const Bytes rec = valid_hello();
  const Bytes wire = split_even(rec, 17);
  EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
  // Decided at the end of the 16th record: its header is never needed.
  std::size_t end16 = 0;
  for (std::size_t i = 0; i < 16; ++i) {
    end16 += 5 + ((static_cast<std::size_t>(wire[end16 + 3]) << 8) | wire[end16 + 4]);
  }
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(end16)).status,
            HelloStatus::Invalid);
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(end16 - 1)).status,
            HelloStatus::NeedMoreData);
}

TEST(HelloSplit, ZeroLengthFragmentIsInvalid) {
  const Bytes rec = valid_hello();
  Bytes wire = split(rec, {3});
  // Insert an empty handshake record between the two fragments.
  const Bytes empty = record_header(0x16, 0x03, 0x01, 0);
  wire.insert(wire.begin() + 8, empty.begin(), empty.end());
  EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(13)).status,
            HelloStatus::Invalid);
  // An empty first record was already a probe.
  EXPECT_EQ(scan_client_hello(record_header(0x16, 0x03, 0x01, 0)).status, HelloStatus::Invalid);
}

TEST(HelloSplit, NonHandshakeRecordInTheMiddleIsInvalid) {
  const Bytes rec = valid_hello();
  for (const std::uint8_t type : {std::uint8_t{0x14}, std::uint8_t{0x15}, std::uint8_t{0x17},
                                   std::uint8_t{0x47}}) {
    SCOPED_TRACE(static_cast<int>(type));
    Bytes wire = split(rec, {3, 50});
    wire[8] = type;  // header of the second record
    EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
    // Decided from the type byte alone.
    EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(9)).status,
              HelloStatus::Invalid);
  }
  // A bad first record header stays "not TLS".
  Bytes first = split(rec, {3});
  first[0] = 0x17;
  EXPECT_EQ(scan_client_hello(first).status, HelloStatus::NotTls);
}

TEST(HelloSplit, BadFragmentVersionIsInvalid) {
  const Bytes rec = valid_hello();
  // The second record header starts at offset 8.
  Bytes wire = split(rec, {3});
  wire[10] = 0x00;  // 03 00
  EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(11)).status,
            HelloStatus::Invalid);
  wire = split(rec, {3});
  wire[10] = 0x02;  // 03 02 is not accepted for the first record either
  EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
  wire = split(rec, {3});
  wire[9] = 0x02;  // 02 03
  wire[10] = 0x03;
  EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(10)).status,
            HelloStatus::Invalid);

  Bytes first = split(rec, {3});
  first[2] = 0x02;
  EXPECT_EQ(scan_client_hello(first).status, HelloStatus::NotTls);

  // Fragments may use either accepted version; the canonical record takes
  // the version of the first one.
  Bytes mixed = split(rec, {3});
  mixed[10] = 0x03;  // second record 03 03, first stays 03 01
  EXPECT_EQ(scan_client_hello(mixed).status, HelloStatus::Ok);
  EXPECT_EQ(reassemble_client_hello(mixed), rec);
  Bytes tls12 = split(rec, {3});
  tls12[2] = 0x03;
  const Bytes canonical = reassemble_client_hello(tls12);
  EXPECT_EQ(canonical[2], 0x03);
  // The client signed a 03 01 header, so a re-labelled first record does not
  // authenticate (exactly as if the unsplit header had been changed).
  EXPECT_EQ(validate(canonical), HelloStatus::Unauthenticated);
}

TEST(HelloSplit, TrailingExcessBytesAreInvalid) {
  const Bytes rec = valid_hello();
  // The last fragment carries one byte more than the handshake still needs.
  Bytes wire = split(rec, {3});
  wire.push_back(0x00);
  const std::size_t last_len = rec.size() - 5 - 3 + 1;
  wire[11] = static_cast<std::uint8_t>(last_len >> 8);
  wire[12] = static_cast<std::uint8_t>(last_len);
  EXPECT_EQ(scan_client_hello(wire).status, HelloStatus::Invalid);
  // Known once the handshake length (its 4th byte is the first byte of the
  // second record) and the header of the oversized record are both in.
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(13)).status,
            HelloStatus::NeedMoreData);
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(wire).first(14)).status,
            HelloStatus::Invalid);

  // A first record that already carries more than the handshake message.
  Bytes single = rec;
  single.push_back(0x00);
  single[3] = static_cast<std::uint8_t>((rec.size() - 5 + 1) >> 8);
  single[4] = static_cast<std::uint8_t>(rec.size() - 5 + 1);
  EXPECT_EQ(scan_client_hello(single).status, HelloStatus::Invalid);

  // Bytes after a complete hello are not part of it.
  Bytes after = split(rec, {3});
  after.push_back(0x14);
  EXPECT_EQ(scan_client_hello(after).status, HelloStatus::Invalid);
  Bytes after_single = rec;
  after_single.push_back(0x14);
  EXPECT_EQ(scan_client_hello(after_single).status, HelloStatus::Invalid);
}

TEST(HelloSplit, DeclaredHandshakeLengthOutsideLimitsIsInvalid) {
  // Too small: 4 + 0x50 = 84 < 100, decided from the four handshake bytes,
  // even when they are split across records.
  const Bytes small = cat({record_header(0x16, 0x03, 0x01, 1), Bytes{0x01},
                           record_header(0x16, 0x03, 0x01, 2), Bytes{0x00, 0x00},
                           record_header(0x16, 0x03, 0x01, 1), Bytes{0x50}});
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(small).first(small.size() - 1)).status,
            HelloStatus::NeedMoreData);
  EXPECT_EQ(scan_client_hello(small).status, HelloStatus::Invalid);
  // 96 is the smallest accepted handshake body (canonical record body 100).
  const Bytes edge = cat({record_header(0x16, 0x03, 0x01, 4), Bytes{0x01, 0x00, 0x00, 0x60}});
  EXPECT_EQ(scan_client_hello(edge).status, HelloStatus::NeedMoreData);
  const Bytes below = cat({record_header(0x16, 0x03, 0x01, 4), Bytes{0x01, 0x00, 0x00, 0x5f}});
  EXPECT_EQ(scan_client_hello(below).status, HelloStatus::Invalid);

  // Too large: 4 + 0x1000 > kFakeTlsMaxClientHello. The high length bytes
  // alone decide it.
  const Bytes large = cat({record_header(0x16, 0x03, 0x01, 1), Bytes{0x01},
                           record_header(0x16, 0x03, 0x01, 3), Bytes{0x00, 0x10, 0x00}});
  EXPECT_EQ(scan_client_hello(std::span<const std::uint8_t>(large).first(large.size() - 1)).status,
            HelloStatus::Invalid);
  const Bytes huge = cat({record_header(0x16, 0x03, 0x01, 2), Bytes{0x01, 0x01}});
  EXPECT_EQ(scan_client_hello(huge).status, HelloStatus::Invalid);
  // The largest accepted one: 4 + 4092.
  const Bytes max = cat({record_header(0x16, 0x03, 0x01, 4), Bytes{0x01, 0x00, 0x0f, 0xfc}});
  EXPECT_EQ(scan_client_hello(max).status, HelloStatus::NeedMoreData);

  // A record declaring more than the bounded maximum is refused from its
  // header alone, before any body byte is read (as before).
  EXPECT_EQ(scan_client_hello(record_header(0x16, 0x03, 0x01, kFakeTlsMaxClientHello + 1)).status,
            HelloStatus::Invalid);
  EXPECT_EQ(scan_client_hello(cat({record_header(0x16, 0x03, 0x01, 3), Bytes{0x01, 0x00, 0x0f},
                                   record_header(0x16, 0x03, 0x01, kFakeTlsMaxClientHello - 2)}))
                .status,
            HelloStatus::Invalid);

  // Not a ClientHello handshake message: decided from the first body byte.
  const Bytes server_hello = cat({record_header(0x16, 0x03, 0x01, 1), Bytes{0x02}});
  EXPECT_EQ(scan_client_hello(server_hello).status, HelloStatus::Invalid);
  Bytes not_hello = valid_hello();
  not_hello[5] = 0x02;
  EXPECT_EQ(scan_client_hello(not_hello).status, HelloStatus::Invalid);
}

TEST(HelloSplit, ShortFirstRecordIsNoLongerClassifiedFromItsHeader) {
  // Previously any first record shorter than 100 bytes was a probe.
  const auto scan = scan_client_hello(record_header(0x16, 0x03, 0x01, 3));
  EXPECT_EQ(scan.status, HelloStatus::NeedMoreData);
  EXPECT_EQ(scan.want, 3u);
}

TEST(HelloSplit, ByteAtATimeFeedingMatchesOneShot) {
  const Bytes rec = valid_hello();
  Bytes excess = split(rec, {3});
  excess.push_back(0x00);
  excess[11] = static_cast<std::uint8_t>((rec.size() - 5 - 3 + 1) >> 8);
  excess[12] = static_cast<std::uint8_t>(rec.size() - 5 - 3 + 1);
  Bytes bad_type = split(rec, {3, 50});
  bad_type[8] = 0x17;
  const std::vector<Bytes> inputs{rec,
                                  split(rec, {1}),
                                  split(rec, {3}),
                                  split(rec, {4}),
                                  split(rec, {5}),
                                  split_even(rec, 16),
                                  split_even(rec, 17),
                                  excess,
                                  bad_type};
  for (std::size_t index = 0; index < inputs.size(); ++index) {
    SCOPED_TRACE(index);
    const Bytes& wire = inputs[index];
    const auto one_shot = scan_client_hello(wire);
    // Every prefix is either still undecided (and asks for no byte beyond the
    // end of the hello) or already carries the final verdict.
    bool decided = false;
    for (std::size_t n = 0; n <= wire.size(); ++n) {
      const auto scan = scan_client_hello(std::span<const std::uint8_t>(wire).first(n));
      if (scan.status == HelloStatus::NeedMoreData) {
        EXPECT_FALSE(decided) << "verdict revoked at " << n;
        EXPECT_GE(scan.want, 1u);
        if (one_shot.status == HelloStatus::Ok) {
          EXPECT_LE(n + scan.want, wire.size());
        }
      } else {
        decided = true;
        if (n < wire.size() || one_shot.status != HelloStatus::Ok) {
          EXPECT_NE(scan.status, HelloStatus::Ok) << n;
        }
      }
    }
    // The runtime's bounded reads, byte by byte and in large chunks, reach the
    // same verdict and never read past a valid hello.
    for (const std::size_t chunk : {std::size_t{1}, std::size_t{7}, std::size_t{1} << 20}) {
      std::size_t read = 0;
      const auto fed = feed_like_runtime(wire, chunk, read);
      EXPECT_EQ(fed.status, one_shot.status) << chunk;
      if (one_shot.status == HelloStatus::Ok) {
        EXPECT_EQ(read, wire.size());
        EXPECT_EQ(fed.records, one_shot.records);
      }
    }
  }
}

TEST(HelloSplit, WrongSecretOnASplitHelloIsUnauthenticated) {
  const Bytes rec = valid_hello();
  const Bytes wire = split(rec, {2, 40});
  ASSERT_EQ(scan_client_hello(wire).status, HelloStatus::Ok);
  A16 wrong{};
  wrong.fill(0xaa);
  EXPECT_EQ(validate(reassemble_client_hello(wire), wrong), HelloStatus::Unauthenticated);
  // The SNI of the reassembled hello is visible for masking/suspect decisions.
  EXPECT_EQ(client_hello_sni(reassemble_client_hello(wire)), std::optional<std::string>("example.com"));
}

TEST(HelloSplit, ReassemblyOfAnIncompleteOrInvalidPrefixIsBestEffort) {
  const Bytes rec = valid_hello();
  EXPECT_TRUE(reassemble_client_hello({}).empty());
  EXPECT_TRUE(reassemble_client_hello(Bytes{0x47, 0x45, 0x54, 0x20, 0x2f}).empty());
  // Header only: an empty canonical record.
  EXPECT_EQ(reassemble_client_hello(std::span<const std::uint8_t>(rec).first(5)),
            cat({record_header(0x16, 0x03, 0x01, 0)}));
  // A partial fragmented prefix reassembles the bytes received so far.
  const Bytes wire = split(rec, {3});
  const std::size_t n = 8 + 5 + 100;
  const Bytes partial = reassemble_client_hello(std::span<const std::uint8_t>(wire).first(n));
  ASSERT_EQ(partial.size(), 5u + 103u);
  EXPECT_EQ(Bytes(partial.begin() + 5, partial.end()), Bytes(rec.begin() + 5, rec.begin() + 108));
  EXPECT_EQ(partial[3], 0x00);
  EXPECT_EQ(partial[4], 103);
  // Reassembly stops at the first record that is not a TLS handshake record.
  Bytes bad = split(rec, {3, 50});
  bad[8] = 0x17;
  EXPECT_EQ(reassemble_client_hello(bad), cat({record_header(0x16, 0x03, 0x01, 3),
                                              Bytes(rec.begin() + 5, rec.begin() + 8)}));
}

}  // namespace mtdd::protocol

#include <gtest/gtest.h>

#include "../support/fake_tls_fixture.hpp"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <new>

namespace {
std::atomic<bool> track_allocations{false};
std::atomic<std::size_t> allocations{0};
}

// Test-executable-only interposition: measure C++ payload allocations, not the
// OpenSSL allocator. Never linked into mtdd or the other test executables.
void* operator new(std::size_t size) {
    if (void* value = std::malloc(size == 0 ? 1 : size)) {
        if (track_allocations.load(std::memory_order_relaxed)) {
            allocations.fetch_add(1, std::memory_order_relaxed);
        }
        return value;
    }
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* value) noexcept { ::operator delete(value); }
void operator delete[](void* value, std::size_t) noexcept { ::operator delete(value); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new[](size); } catch (...) { return nullptr; }
}
void operator delete(void* value, const std::nothrow_t&) noexcept { ::operator delete(value); }
void operator delete[](void* value, const std::nothrow_t&) noexcept { ::operator delete[](value); }

namespace mtdd::test {
namespace {

using Bytes = std::vector<std::uint8_t>;

TEST(FakeTlsSend, PreallocatedOutputNeedsNoPerRecordCppAllocation) {
    auto connection = ready_fake_tls();
    const Bytes plaintext(65537, 0x5a);
    Bytes output;
    output.reserve(plaintext.size() + 5 * 5);
    allocations.store(0);
    track_allocations.store(true);
    protocol::Status result{};
    try {
        result = connection.send(plaintext, output);
    } catch (...) {
        track_allocations.store(false);
        throw;
    }
    track_allocations.store(false);
    EXPECT_EQ(result, protocol::Status::Ok);
    EXPECT_EQ(allocations.load(), 0u);
}

TEST(FakeTlsSend, MultiRecordAppendPreservesPrefixAndCipherContinuity) {
    auto connection = ready_fake_tls();
    auto decryptor = fake_tls_client_decryptor();
    for (const std::size_t size : {0u, 1u, 16383u, 16384u, 16385u, 131073u}) {
        Bytes plaintext(size);
        for (std::size_t i = 0; i < size; ++i) plaintext[i] = static_cast<std::uint8_t>(i * 17);
        const auto original = plaintext;
        Bytes output{0xa5, 0x5a};
        ASSERT_EQ(connection.send(plaintext, output), protocol::Status::Ok);
        EXPECT_EQ(plaintext, original);
        ASSERT_EQ(output[0], 0xa5);
        ASSERT_EQ(output[1], 0x5a);
        Bytes decoded;
        std::size_t offset = 2;
        while (offset < output.size()) {
            ASSERT_GE(output.size() - offset, 5u);
            EXPECT_EQ(output[offset], 0x17);
            EXPECT_EQ(output[offset + 1], 0x03);
            EXPECT_EQ(output[offset + 2], 0x03);
            const std::size_t length = (static_cast<std::size_t>(output[offset + 3]) << 8) |
                                       output[offset + 4];
            ASSERT_GT(length, 0u);
            ASSERT_LE(length, 16384u);
            ASSERT_LE(length, output.size() - offset - 5);
            auto body = std::span<std::uint8_t>(output).subspan(offset + 5, length);
            decryptor.apply(body);
            decoded.insert(decoded.end(), body.begin(), body.end());
            offset += 5 + length;
        }
        EXPECT_EQ(decoded, plaintext);
    }
}

// Decrypts every record body of `wire` in order and checks record framing.
Bytes decode_records(const Bytes& wire, protocol::crypto::AesCtr& decryptor,
                     std::size_t& records) {
    Bytes decoded;
    records = 0;
    std::size_t offset = 0;
    while (offset < wire.size()) {
        EXPECT_GE(wire.size() - offset, 5u);
        if (wire.size() - offset < 5) break;
        EXPECT_EQ(wire[offset], 0x17);
        const std::size_t length =
            (static_cast<std::size_t>(wire[offset + 3]) << 8) | wire[offset + 4];
        EXPECT_GT(length, 0u);
        EXPECT_LE(length, 16384u);
        EXPECT_LE(length, wire.size() - offset - 5);
        Bytes body(wire.begin() + static_cast<std::ptrdiff_t>(offset + 5),
                   wire.begin() + static_cast<std::ptrdiff_t>(offset + 5 + length));
        decryptor.apply(body);
        decoded.insert(decoded.end(), body.begin(), body.end());
        offset += 5 + length;
        ++records;
    }
    return decoded;
}

TEST(FakeTlsSend, OpenRecordCoalescingKeepsTheDecryptedStreamIdentical) {
    // Same message sequence through two identical connections: one record per
    // message vs. one open record extended across messages. The decrypted
    // streams must match byte for byte; only the record count differs.
    const std::vector<std::size_t> sizes{8, 12, 1024, 4, 16000, 600, 40000, 8, 4};
    const auto random_for = [](std::uint8_t& state) {
        return protocol::RandomFn([&state](std::span<std::uint8_t> out) {
            for (auto& byte : out) byte = state++;
        });
    };
    auto separate = ready_fake_tls();
    auto merged = ready_fake_tls();
    std::uint8_t state_a = 7;
    std::uint8_t state_b = 7;
    const auto random_a = random_for(state_a);
    const auto random_b = random_for(state_b);
    Bytes wire_a;
    Bytes wire_b{0xee}; // unrelated prefix must never be treated as a record
    std::size_t open = 0;  // points at the prefix byte: not a record
    for (std::size_t index = 0; index < sizes.size(); ++index) {
        Bytes payload(sizes[index]);
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<std::uint8_t>(i * 13 + index);
        }
        if (index == 3) {
            // A quick-ack style plain frame shares the same open record.
            const Bytes ack{0x01, 0x02, 0x03, 0x84};
            ASSERT_EQ(separate.send(ack, wire_a), protocol::Status::Ok);
            ASSERT_EQ(merged.send(ack, wire_b, &open), protocol::Status::Ok);
        }
        ASSERT_EQ(separate.send_transport_message(protocol::ProtoTag::Secure, payload, wire_a,
                                                  random_a),
                  protocol::Status::Ok);
        ASSERT_EQ(merged.send_transport_message(protocol::ProtoTag::Secure, payload, wire_b,
                                                random_b, &open),
                  protocol::Status::Ok);
    }
    ASSERT_EQ(wire_b.front(), 0xee);
    const Bytes merged_wire(wire_b.begin() + 1, wire_b.end());
    auto decryptor_a = fake_tls_client_decryptor();
    auto decryptor_b = fake_tls_client_decryptor();
    std::size_t records_a = 0;
    std::size_t records_b = 0;
    const Bytes stream_a = decode_records(wire_a, decryptor_a, records_a);
    const Bytes stream_b = decode_records(merged_wire, decryptor_b, records_b);
    ASSERT_EQ(stream_a.size(), stream_b.size());
    const auto mismatch = std::mismatch(stream_a.begin(), stream_a.end(), stream_b.begin());
    EXPECT_EQ(static_cast<std::size_t>(mismatch.first - stream_a.begin()), stream_a.size())
        << "first differing stream byte";
    EXPECT_GT(records_a, records_b);
    // ~58 KiB of frames fit in 4 full-size records.
    EXPECT_LE(records_b, 5u);

    // kNoOpenRecord always starts a fresh record.
    std::size_t none = protocol::FakeTlsConnection::kNoOpenRecord;
    Bytes fresh;
    ASSERT_EQ(merged.send(Bytes{1, 2, 3, 4}, fresh, &none), protocol::Status::Ok);
    EXPECT_EQ(none, 0u);
    EXPECT_EQ(fresh.size(), 9u);
}

TEST(FakeTlsSend, AliasedInputSurvivesOutputReallocation) {
    auto connection = ready_fake_tls();
    auto decryptor = fake_tls_client_decryptor();
    Bytes output(32769, 0x69);
    output.shrink_to_fit();
    const Bytes expected(output.begin() + 1, output.end());
    const std::size_t prefix = output.size();
    ASSERT_EQ(connection.send(std::span<const std::uint8_t>(output).subspan(1), output),
              protocol::Status::Ok);
    EXPECT_EQ(Bytes(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(prefix)),
              Bytes(prefix, 0x69));
    Bytes decoded;
    for (std::size_t offset = prefix; offset < output.size();) {
        ASSERT_GE(output.size() - offset, 5u);
        const std::size_t length = (static_cast<std::size_t>(output[offset + 3]) << 8) |
                                   output[offset + 4];
        ASSERT_GT(length, 0u);
        ASSERT_LE(length, output.size() - offset - 5);
        auto body = std::span<std::uint8_t>(output).subspan(offset + 5, length);
        decryptor.apply(body);
        decoded.insert(decoded.end(), body.begin(), body.end());
        offset += 5 + length;
    }
    EXPECT_EQ(decoded, expected);
}

} // namespace
} // namespace mtdd::test

namespace {

std::vector<std::uint8_t> make_probe_hello(std::string_view name) {
    const auto put = [](std::vector<std::uint8_t>& out, std::uint16_t value) {
        out.push_back(static_cast<std::uint8_t>(value >> 8));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };
    const auto append = [](std::vector<std::uint8_t>& out,
                           const std::vector<std::uint8_t>& in) {
        out.insert(out.end(), in.begin(), in.end());
    };

    // server_name extension: type(2) len(2) [ list_len(2) type(1) len(2) name ]
    std::vector<std::uint8_t> server_name{0x00};
    put(server_name, static_cast<std::uint16_t>(name.size()));
    server_name.insert(server_name.end(), name.begin(), name.end());
    std::vector<std::uint8_t> sni_list;
    put(sni_list, static_cast<std::uint16_t>(server_name.size()));
    append(sni_list, server_name);
    std::vector<std::uint8_t> extensions;
    put(extensions, 0x0000);
    put(extensions, static_cast<std::uint16_t>(sni_list.size()));
    append(extensions, sni_list);

    // ClientHello body: version(2) random(32) sid(1) ciphers(2+2) comp(1+1)
    // extensions(2 + content).
    std::vector<std::uint8_t> body{0x03, 0x03};
    body.insert(body.end(), 32, 0xAB);
    body.push_back(0x00);
    put(body, 0x0002);
    body.push_back(0x13);
    body.push_back(0x01);
    body.push_back(0x01);
    body.push_back(0x00);
    put(body, static_cast<std::uint16_t>(extensions.size()));
    append(body, extensions);

    // TLS record: type(1) version(2) length(2) handshake: type(1) length(3).
    std::vector<std::uint8_t> record{0x16, 0x03, 0x01};
    put(record, static_cast<std::uint16_t>(body.size() + 4));
    record.push_back(0x01);
    record.push_back(static_cast<std::uint8_t>((body.size() >> 16) & 0xFF));
    record.push_back(static_cast<std::uint8_t>((body.size() >> 8) & 0xFF));
    record.push_back(static_cast<std::uint8_t>(body.size() & 0xFF));
    append(record, body);
    return record;
}

}  // namespace

TEST(FakeTlsSni, ExtractsAndLowercasesHostName) {
    const auto hello = make_probe_hello("M.Beboo.RU");
    const auto sni = mtdd::protocol::client_hello_sni(hello);
    ASSERT_TRUE(sni.has_value());
    EXPECT_EQ(*sni, "m.beboo.ru");
}

TEST(FakeTlsSni, AbsentOrGarbledSniYieldsNothing) {
    const auto empty_name = make_probe_hello("");
    EXPECT_FALSE(mtdd::protocol::client_hello_sni(empty_name).has_value());
    const auto hello = make_probe_hello("m.beboo.ru");
    EXPECT_FALSE(mtdd::protocol::client_hello_sni(
                     std::span<const std::uint8_t>(hello).first(10)).has_value());
    std::vector<std::uint8_t> not_hello(64, 0x00);
    EXPECT_FALSE(mtdd::protocol::client_hello_sni(not_hello).has_value());
}

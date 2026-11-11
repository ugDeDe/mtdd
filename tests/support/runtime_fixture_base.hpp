#pragma once

// Runtime integration tests. They use real epoll, loopback sockets, the real
// protocol/control modules, a real UserStore/RevisionBarrier/MetadataProvider,
// and a local fake Middle-End peer. No external network is contacted.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <numeric>
#include <sstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "mtdd/config.hpp"
#include "mtdd/control.hpp"
#include "mtdd/io.hpp"
#include "mtdd/metadata.hpp"
#include "mtdd/protocol.hpp"
#include "mtdd/runtime.hpp"
#include "mtdd/runtime_support.hpp"
#include "../../src/runtime/internal.hpp"
#include "../support/fake_direct_dc.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;
using A16 = std::array<std::uint8_t, 16>;
using A32 = std::array<std::uint8_t, 32>;
using ConnId = mtdd::protocol::MiddleEndSession::ConnId;
using namespace std::chrono_literals;

constexpr std::string_view kSecretHex = "000102030405060708090a0b0c0d0e0f";
constexpr std::string_view kDomain = "example.com";

A16 secret_bytes() {
    A16 out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(i);
    return out;
}

[[maybe_unused]] A16 bob_secret_bytes() {
    A16 out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(0x10 + i);
    return out;
}

[[maybe_unused]] std::array<std::uint8_t, 128> me_secret() {
    std::array<std::uint8_t, 128> out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(i);
    return out;
}

std::uint32_t rd32(const Bytes& data, std::size_t offset) {
    return static_cast<std::uint32_t>(data[offset]) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

void put32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 24));
}

void append(Bytes& out, std::span<const std::uint8_t> data) {
    out.insert(out.end(), data.begin(), data.end());
}

void put16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

Bytes tls_record(std::uint8_t type, std::span<const std::uint8_t> body) {
    Bytes out{type, 0x03, 0x03};
    put16(out, static_cast<std::uint16_t>(body.size()));
    append(out, body);
    return out;
}

mtdd::protocol::Endpoint to_protocol(const mtdd::io::Endpoint& endpoint) {
    std::array<std::uint8_t, 16> bytes{};
    if (::inet_pton(AF_INET, endpoint.address.c_str(), bytes.data()) == 1) {
        return mtdd::protocol::Endpoint::v4({bytes[0], bytes[1], bytes[2], bytes[3]},
                                            endpoint.port);
    }
    return mtdd::protocol::Endpoint::v6(bytes, endpoint.port);
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

int connect_loopback(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    timeval timeout{};
    timeout.tv_sec = 3;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

[[maybe_unused]] int connect_loopback_with_rcvbuf(std::uint16_t port, int recv_buffer_bytes) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (recv_buffer_bytes > 0) {
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_buffer_bytes, sizeof(recv_buffer_bytes));
        // Loopback autotuning can otherwise ignore a small SO_RCVBUF; clamp the
        // advertised window so the proxy's client queue really fills.
        ::setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &recv_buffer_bytes,
                     sizeof(recv_buffer_bytes));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    timeval timeout{};
    timeout.tv_sec = 3;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

[[maybe_unused]] int connect_loopback_from(std::uint16_t port, const char* source_address) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    if (::inet_pton(AF_INET, source_address, &local.sin_addr) != 1 ||
        ::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
        ::close(fd);
        return -1;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    timeval timeout{};
    timeout.tv_sec = 3;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

bool wait_readable(int fd, int timeout_ms) {
    pollfd entry{};
    entry.fd = fd;
    entry.events = POLLIN;
    const int result = ::poll(&entry, 1, timeout_ms);
    return result > 0 && (entry.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}

bool recv_exact(int fd, std::uint8_t* data, std::size_t size, int timeout_ms) {
    std::size_t done = 0;
    while (done < size) {
        if (!wait_readable(fd, timeout_ms)) return false;
        const ssize_t got = ::recv(fd, data + done, size - done, 0);
        if (got > 0) {
            done += static_cast<std::size_t>(got);
        } else if (got == 0) {
            return false;
        } else if (errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

bool send_all(int fd, std::span<const std::uint8_t> data) {
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t sent = ::send(fd, data.data() + done, data.size() - done, MSG_NOSIGNAL);
        if (sent > 0) {
            done += static_cast<std::size_t>(sent);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

// 0 = closed, 1 = data available, 2 = timeout.
int peer_state(int fd, int timeout_ms) {
    if (!wait_readable(fd, timeout_ms)) return 2;
    std::uint8_t byte = 0;
    const ssize_t got = ::recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    if (got == 0) return 0;
    if (got > 0) return 1;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 2;
    return 0;
}

bool wait_closed(int fd, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        const int state = peer_state(fd, 100);
        if (state == 0) return true;
        if (state == 1) {
            std::uint8_t sink[512];
            const ssize_t got = ::recv(fd, sink, sizeof(sink), MSG_DONTWAIT);
            if (got == 0) return true;
            if (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Client Hello / obfuscation builder (mirrors the client side of FakeTLS)
// ---------------------------------------------------------------------------

Bytes make_client_hello(const A16& secret, std::uint32_t timestamp, std::string_view sni,
                        std::uint8_t variant = 0) {
    Bytes random;
    for (int i = 0; i < 32; ++i) {
        random.push_back(static_cast<std::uint8_t>(0x20 + i + variant));
    }
    Bytes session;
    for (int i = 0; i < 32; ++i) {
        session.push_back(static_cast<std::uint8_t>(0x40 + i + variant));
    }
    Bytes key;
    for (int i = 0; i < 32; ++i) key.push_back(static_cast<std::uint8_t>(0x80 + i + variant));

    Bytes entry{0x00, 0x1d, 0x00, 0x20};
    append(entry, key);
    Bytes key_share;
    put16(key_share, static_cast<std::uint16_t>(entry.size()));
    append(key_share, entry);

    Bytes extensions{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    extensions.push_back(0x00);
    extensions.push_back(0x33);
    put16(extensions, static_cast<std::uint16_t>(key_share.size()));
    append(extensions, key_share);
    Bytes name{0x00};
    put16(name, static_cast<std::uint16_t>(sni.size()));
    name.insert(name.end(), sni.begin(), sni.end());
    Bytes list;
    put16(list, static_cast<std::uint16_t>(name.size()));
    append(list, name);
    extensions.push_back(0x00);
    extensions.push_back(0x00);
    put16(extensions, static_cast<std::uint16_t>(list.size()));
    append(extensions, list);

    Bytes ciphers{0x13, 0x01, 0x13, 0x03};
    Bytes body{0x03, 0x03};
    append(body, random);
    body.push_back(0x20);
    append(body, session);
    put16(body, static_cast<std::uint16_t>(ciphers.size()));
    append(body, ciphers);
    body.push_back(0x01);
    body.push_back(0x00);
    put16(body, static_cast<std::uint16_t>(extensions.size()));
    append(body, extensions);

    Bytes handshake{0x01};
    handshake.push_back(static_cast<std::uint8_t>(body.size() >> 16));
    handshake.push_back(static_cast<std::uint8_t>(body.size() >> 8));
    handshake.push_back(static_cast<std::uint8_t>(body.size()));
    append(handshake, body);

    Bytes record{0x16, 0x03, 0x01};
    put16(record, static_cast<std::uint16_t>(handshake.size()));
    append(record, handshake);

    Bytes hmac_input;
    append(hmac_input, std::span<const std::uint8_t>(record).first(11));
    hmac_input.insert(hmac_input.end(), 32, 0);
    append(hmac_input, std::span<const std::uint8_t>(record).subspan(43));
    auto hmac = mtdd::protocol::crypto::hmac_sha256(secret, hmac_input);
    for (int i = 0; i < 4; ++i) {
        hmac[28 + i] = static_cast<std::uint8_t>(hmac[28 + i] ^
                                                 static_cast<std::uint8_t>(timestamp >> (8 * i)));
    }
    std::copy(hmac.begin(), hmac.end(), record.begin() + 11);
    return record;
}

struct ClientObfuscation {
    Bytes wire;
    A32 decrypt_key{};
    A16 decrypt_iv{};
    A32 encrypt_key{};
    A16 encrypt_iv{};
};

ClientObfuscation make_obfuscation(const A16& secret, std::int16_t dc) {
    Bytes raw(64);
    for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<std::uint8_t>(i);
    const std::uint32_t tag = 0xddddddddU;
    for (int i = 0; i < 4; ++i) raw[56 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>(tag >> (8 * i));
    raw[60] = static_cast<std::uint8_t>(dc);
    raw[61] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(dc) >> 8);

    ClientObfuscation out;
    Bytes key_input;
    append(key_input, std::span<const std::uint8_t>(raw).subspan(8, 32));
    append(key_input, secret);
    out.decrypt_key = mtdd::protocol::crypto::sha256(key_input);
    std::copy_n(raw.begin() + 40, 16, out.decrypt_iv.begin());

    Bytes reversed;
    for (int i = 55; i >= 8; --i) reversed.push_back(raw[static_cast<std::size_t>(i)]);
    Bytes enc_input;
    append(enc_input, std::span<const std::uint8_t>(reversed).first(32));
    append(enc_input, secret);
    out.encrypt_key = mtdd::protocol::crypto::sha256(enc_input);
    std::copy_n(reversed.begin() + 32, 16, out.encrypt_iv.begin());

    mtdd::protocol::crypto::AesCtr encryptor(out.decrypt_key, out.decrypt_iv);
    Bytes encrypted = raw;
    encryptor.apply(encrypted);
    out.wire.assign(raw.begin(), raw.begin() + 56);
    out.wire.insert(out.wire.end(), encrypted.begin() + 56, encrypted.end());
    return out;
}

// ---------------------------------------------------------------------------
// FakeTLS test client
// ---------------------------------------------------------------------------

class TestClient {
public:
    struct Adopt {};
    TestClient(std::uint16_t port, const A16& secret) : secret_(secret) {
        fd_ = connect_loopback(port);
    }
    TestClient(Adopt, int fd, const A16& secret) : fd_(fd), secret_(secret) {}
    ~TestClient() {
        if (fd_ >= 0) ::close(fd_);
    }
    TestClient(const TestClient&) = delete;
    TestClient& operator=(const TestClient&) = delete;

    bool valid() const { return fd_ >= 0; }
    int fd() const { return fd_; }

    bool send_hello(std::uint32_t timestamp = 0, std::uint8_t variant = 0) {
        if (timestamp == 0) {
            timestamp = static_cast<std::uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
        }
        hello_ = make_client_hello(secret_, timestamp, kDomain, variant);
        if (!send_all(fd_, hello_)) return false;
        return read_server_hello();
    }

    bool send_hello_bytes(const Bytes& hello) {
        hello_ = hello;
        return send_all(fd_, hello_);
    }

    bool start_obfuscation(std::int16_t dc) {
        obfuscation_ = make_obfuscation(secret_, dc);
        const Bytes ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        Bytes wire = ccs;
        const Bytes record = tls_record(0x17, obfuscation_.wire);
        append(wire, record);
        if (!send_all(fd_, wire)) return false;
        c2s_.emplace(obfuscation_.decrypt_key, obfuscation_.decrypt_iv);
        c2s_->skip(64);
        s2c_.emplace(obfuscation_.encrypt_key, obfuscation_.encrypt_iv);
        return true;
    }

    bool send_message(std::span<const std::uint8_t> payload) {
        if (!c2s_) return false;
        Bytes frame;
        put32(frame, static_cast<std::uint32_t>(payload.size()));
        append(frame, payload);
        c2s_->apply(frame);
        return send_all(fd_, tls_record(0x17, frame));
    }

    // A single MTProto transport frame may span several FakeTLS records (the
    // real client does this). Used to move a message larger than the shared ME
    // output queue so the ready-queue path is held in its blocked state.
    bool send_message_chunked(std::span<const std::uint8_t> payload,
                              std::size_t chunk = 16000) {
        if (!c2s_) return false;
        Bytes frame;
        put32(frame, static_cast<std::uint32_t>(payload.size()));
        append(frame, payload);
        c2s_->apply(frame);
        std::size_t offset = 0;
        while (offset < frame.size()) {
            const std::size_t take = std::min(chunk, frame.size() - offset);
            if (!send_all(fd_, tls_record(
                                   0x17, std::span<const std::uint8_t>(frame)
                                              .subspan(offset, take)))) {
                return false;
            }
            offset += take;
        }
        return true;
    }

    // Queues several MTProto frames in one TCP write so a FIN can follow with a
    // tail larger than one 32 KiB reactor read batch.
    bool send_bulk_messages(const std::vector<Bytes>& payloads) {
        if (!c2s_) return false;
        Bytes wire;
        for (const auto& payload : payloads) {
            Bytes frame;
            put32(frame, static_cast<std::uint32_t>(payload.size()));
            append(frame, payload);
            c2s_->apply(frame);
            append(wire, tls_record(0x17, frame));
        }
        return send_all(fd_, wire);
    }

    // Reads one complete MTProto transport message. Returns false on close,
    // timeout, or malformed data.
    bool read_message(Bytes& payload, int timeout_ms = 3000) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (true) {
            if (s2c_plain_.size() >= 4) {
                const std::uint32_t length = rd32(s2c_plain_, 0);
                if (length == 0 || length > (4U << 20)) return false;
                if (s2c_plain_.size() >= 4 + length) {
                    const std::size_t keep = length - (length % 4);
                    payload.assign(s2c_plain_.begin() + 4,
                                   s2c_plain_.begin() + 4 + static_cast<std::ptrdiff_t>(keep));
                    s2c_plain_.erase(s2c_plain_.begin(),
                                     s2c_plain_.begin() + static_cast<std::ptrdiff_t>(4 + length));
                    return true;
                }
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();
            if (remaining <= 0) return false;
            std::uint8_t header[5]{};
            if (!recv_exact(fd_, header, sizeof(header), static_cast<int>(remaining))) return false;
            const std::size_t length = (static_cast<std::size_t>(header[3]) << 8) | header[4];
            if (length > mtdd::protocol::kFakeTlsMaxRecordBody) return false;
            Bytes body(length);
            if (length > 0 && !recv_exact(fd_, body.data(), length, static_cast<int>(remaining))) {
                return false;
            }
            if (header[0] == 0x15) return false;
            if (header[0] != 0x17 || !s2c_) continue;
            s2c_->apply(body);
            append(s2c_plain_, body);
        }
    }

    const Bytes& hello_bytes() const { return hello_; }
    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    bool wait_closed_for(int timeout_ms) { return wait_closed(fd_, timeout_ms); }

    bool peer_sent_data(int timeout_ms) {
        const int state = peer_state(fd_, timeout_ms);
        return state == 1;
    }

private:
    bool read_server_hello() {
        bool saw_app_data = false;
        for (int record = 0; record < 4 && !saw_app_data; ++record) {
            std::uint8_t header[5]{};
            if (!recv_exact(fd_, header, sizeof(header), 3000)) return false;
            const std::size_t length = (static_cast<std::size_t>(header[3]) << 8) | header[4];
            Bytes body(length);
            if (length > 0 && !recv_exact(fd_, body.data(), length, 3000)) return false;
            if (header[0] == 0x17) saw_app_data = true;
        }
        return saw_app_data;
    }

    int fd_{-1};
    A16 secret_{};
    Bytes hello_;
    ClientObfuscation obfuscation_;
    std::optional<mtdd::protocol::crypto::AesCtr> c2s_;
    std::optional<mtdd::protocol::crypto::AesCtr> s2c_;
    Bytes s2c_plain_;
};

// ---------------------------------------------------------------------------
// Configuration / services
// ---------------------------------------------------------------------------

class TempDir {
public:
    TempDir() {
        static std::atomic<unsigned> counter{0};
        path_ = std::filesystem::temp_directory_path() /
                ("mtdd-runtime-test-" + std::to_string(::getpid()) + "-" +
                 std::to_string(counter.fetch_add(1)));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

mtdd::Config make_config(const std::filesystem::path& directory, std::uint16_t me_port,
                         bool with_metadata, const std::function<void(mtdd::Config&)>& tweak) {
    mtdd::Config config;
    config.proxy_host = "127.0.0.1";
    config.proxy_port = 0;
    config.tls_domain = std::string(kDomain);
    // Offline suites never touch the network: masking is exercised only by the
    // dedicated runtime cases that opt in with a local relay target.
    config.masking = false;
    for (std::size_t i = 0; i < config.ad_tag.size(); ++i) {
        config.ad_tag[i] = static_cast<std::uint8_t>(0x10 + i);
    }
    config.users_path = directory / "users.json";
    config.me_config_path = directory / "me.txt";
    config.me_secret_path = directory / "me-secret.bin";
    config.workers = 1;
    // Existing FakeMe tests model one sequential ME connection per DC. Pool
    // tests override this explicitly.
    config.me_connections_per_dc = 1;
    config.max_connections = 64;
    config.max_handshakes = 32;
    config.max_frame_bytes = 2U * 1024U * 1024U;
    config.connection_queue_bytes = 256U * 1024U;
    config.global_buffer_bytes = 64U * 1024U * 1024U;
    config.handshake_timeout = 2s;
    config.idle_timeout = 30s;
    config.shutdown_timeout = 2s;
    config.metadata_refresh = 3600s;
    if (with_metadata) {
        std::ofstream config_file{config.me_config_path, std::ios::binary};
        config_file << "proxy_for 2 127.0.0.1:" << me_port << ";\n";
        std::ofstream secret_file{config.me_secret_path, std::ios::binary};
        for (int i = 0; i < 128; ++i) {
            secret_file.put(static_cast<char>(i));
        }
    }
    if (tweak) tweak(config);
    return config;
}

struct Services {
    Services(std::uint16_t me_port, bool with_metadata,
             const std::function<void(mtdd::Config&)>& tweak = {})
        : dir(), config(make_config(dir.path(), me_port, with_metadata, tweak)),
          store(open_store()), metadata(std::move(make_metadata())) {}

    bool add_user(std::string name, std::string secret,
                  std::optional<std::uint32_t> max_connections = std::nullopt,
                  bool enabled = true) {
        mtdd::control::CreateUserRequest request;
        request.name = std::move(name);
        request.secret = std::move(secret);
        request.enabled = enabled;
        request.max_connections = max_connections;
        return store->create_user(request).ok();
    }

    TempDir dir;
    mtdd::Config config;
    mtdd::RevisionBarrier barrier;
    mtdd::control::Statistics stats{100};
    std::unique_ptr<mtdd::control::UserStore> store;
    std::unique_ptr<mtdd::MetadataProvider> metadata;

private:
    std::unique_ptr<mtdd::control::UserStore> open_store() {
        mtdd::control::StoreOptions options;
        options.ack_hook = [this](std::uint64_t revision, std::chrono::milliseconds timeout) {
            return barrier.wait(revision, timeout);
        };
        auto opened = mtdd::control::UserStore::open(config.users_path.string(), options);
        if (!opened) throw std::runtime_error("cannot open test user store");
        return std::make_unique<mtdd::control::UserStore>(std::move(opened).value());
    }
    std::unique_ptr<mtdd::MetadataProvider> make_metadata() {
        return std::make_unique<mtdd::MetadataProvider>(config);
    }
};

bool wait_for(const std::function<bool()>& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return predicate();
}

[[maybe_unused]] std::uint64_t stat_counter(const mtdd::control::Statistics& stats, std::string_view group,
                           std::string_view label) {
    const auto snapshot = stats.snapshot();
    const auto* map = group == "rejected" ? &snapshot.rejected_by_reason : &snapshot.handshakes_by_result;
    const auto found = map->find(std::string(label));
    return found == map->end() ? 0 : found->second;
}

// ---------------------------------------------------------------------------
// Reactor CPU / silent ME helpers
// ---------------------------------------------------------------------------

// Linux per-thread CPU time from /proc/self/task/<tid>/stat (utime + stime).
[[maybe_unused]] double thread_cpu_seconds(pid_t tid) {
    std::ifstream file("/proc/self/task/" + std::to_string(tid) + "/stat");
    std::string line;
    if (!std::getline(file, line)) return -1.0;
    const auto close = line.rfind(')');
    if (close == std::string::npos) return -1.0;
    std::istringstream fields(line.substr(close + 1));
    std::string token;
    long long utime = 0;
    long long stime = 0;
    for (int index = 0; index < 13; ++index) {
        if (!(fields >> token)) return -1.0;
        if (index == 11) utime = std::stoll(token);
        if (index == 12) stime = std::stoll(token);
    }
    const long ticks = ::sysconf(_SC_CLK_TCK);
    if (ticks <= 0) return -1.0;
    return static_cast<double>(utime + stime) / static_cast<double>(ticks);
}

// Operation counters for the EOF drain. These are produced by the real sweep in
// src/runtime/drain.cpp, so a test can assert how many scans actually happened
// without using a wall-clock CPU threshold.
struct EofDrainCounts {
    std::uint64_t sweeps{0};
    std::uint64_t visits{0};
    std::uint64_t output_pumps{0};
    std::uint64_t map_lookups{0};
    std::uint64_t closes{0};

    static EofDrainCounts read() {
        const auto& telemetry = mtdd::detail::eof_drain_telemetry();
        EofDrainCounts counts;
        counts.sweeps = telemetry.sweeps.load(std::memory_order_relaxed);
        counts.visits = telemetry.visits.load(std::memory_order_relaxed);
        counts.output_pumps = telemetry.output_pumps.load(std::memory_order_relaxed);
        counts.map_lookups = telemetry.map_lookups.load(std::memory_order_relaxed);
        counts.closes = telemetry.closes.load(std::memory_order_relaxed);
        return counts;
    }
};

[[maybe_unused]] void reset_eof_drain_counts() {
    auto& telemetry = mtdd::detail::eof_drain_telemetry();
    telemetry.sweeps.store(0, std::memory_order_relaxed);
    telemetry.visits.store(0, std::memory_order_relaxed);
    telemetry.output_pumps.store(0, std::memory_order_relaxed);
    telemetry.map_lookups.store(0, std::memory_order_relaxed);
    telemetry.closes.store(0, std::memory_order_relaxed);
}

[[maybe_unused]] void reset_client_lifecycle_telemetry() {
    auto& telemetry = mtdd::detail::client_lifecycle_telemetry();
    telemetry.allocations.store(0, std::memory_order_relaxed);
    telemetry.reuses.store(0, std::memory_order_relaxed);
    telemetry.releases.store(0, std::memory_order_relaxed);
    telemetry.discards.store(0, std::memory_order_relaxed);
    telemetry.last_recycled.store(0, std::memory_order_relaxed);
    telemetry.last_reused.store(0, std::memory_order_relaxed);
    telemetry.pooled.store(0, std::memory_order_relaxed);
    telemetry.relay_transitions.store(0, std::memory_order_relaxed);
    telemetry.relay_with_hello_capacity.store(0, std::memory_order_relaxed);
}

[[maybe_unused]] std::uint32_t current_timestamp() {
    return static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// Accepts ME TCP connections and never answers the RPC_NONCE. Used to hold the
// client in relay-without-usable-ME state without production traffic.
class SilentMe {
public:
    SilentMe() {
        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("silent ME cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = mtdd::io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("silent ME has no port");
        port_ = local->port;
        thread_ = std::thread([this] { run(); });
    }
    ~SilentMe() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        for (const int fd : held_) ::close(fd);
    }
    SilentMe(const SilentMe&) = delete;
    SilentMe& operator=(const SilentMe&) = delete;
    std::uint16_t port() const { return port_; }

private:
    void run() {
        while (!stop_.load()) {
            pollfd entry{};
            entry.fd = listener_.get();
            entry.events = POLLIN;
            if (::poll(&entry, 1, 50) > 0 && (entry.revents & POLLIN) != 0) {
                const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
                if (fd >= 0) held_.push_back(fd);
            }
        }
    }
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::vector<int> held_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
};

// Plain TCP echo used as the fixed loopback Caddy stand-in. The runtime never
// parses TLS on this path; it only relays bytes.
class EchoBackend {
public:
    explicit EchoBackend(std::chrono::milliseconds delay = std::chrono::milliseconds{0})
        : delay_(delay) {
        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("echo backend cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = mtdd::io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("echo backend has no port");
        port_ = local->port;
        thread_ = std::thread([this] { run(); });
    }
    ~EchoBackend() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
    }
    EchoBackend(const EchoBackend&) = delete;
    EchoBackend& operator=(const EchoBackend&) = delete;

    std::uint16_t port() const { return port_; }
    std::uint64_t accepted() const { return accepted_.load(); }
    std::uint64_t received() const { return received_.load(); }

private:
    void sleep_slice(std::chrono::milliseconds duration) {
        const auto end = std::chrono::steady_clock::now() + duration;
        while (!stop_.load() && std::chrono::steady_clock::now() < end) {
            std::this_thread::sleep_for(20ms);
        }
    }

    void run() {
        while (!stop_.load()) {
            pollfd entry{};
            entry.fd = listener_.get();
            entry.events = POLLIN;
            if (::poll(&entry, 1, 50) <= 0 || (entry.revents & POLLIN) == 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            ++accepted_;
            timeval timeout{};
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            if (delay_.count() > 0) sleep_slice(delay_);
            while (!stop_.load()) {
                std::array<std::uint8_t, 16384> buffer{};
                const ssize_t got = ::recv(fd, buffer.data(), buffer.size(), 0);
                if (got > 0) {
                    received_.fetch_add(static_cast<std::uint64_t>(got));
                    if (!send_all(fd, std::span<const std::uint8_t>(buffer).first(
                                          static_cast<std::size_t>(got)))) {
                        break;
                    }
                } else if (got == 0) {
                    ::shutdown(fd, SHUT_WR);
                    break;
                } else if (errno == EINTR) {
                    continue;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                } else {
                    break;
                }
            }
            ::close(fd);
        }
    }

    std::chrono::milliseconds delay_{0};
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> received_{0};
};

[[maybe_unused]] std::uint16_t closed_loopback_port() {
    auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
    if (!listener.ok()) throw std::runtime_error("cannot reserve closed port");
    const auto local = mtdd::io::local_endpoint(listener.fd.get());
    if (!local) throw std::runtime_error("cannot read reserved port");
    const std::uint16_t port = local->port;
    listener.fd.close();
    return port;
}

// ---------------------------------------------------------------------------
// Fake Middle-End peer
// ---------------------------------------------------------------------------

} // namespace

#pragma once

#include "runtime_fixture_me.hpp"

namespace {

struct PoolMeOptions {
    bool answer_pings{true};
    // The first connection ignores every PING, so the reactor's K=3 liveness
    // rule must replace it.
    bool ignore_pings_on_first{false};
    bool answer_clients{true};
    // Number of accepted connections that use secrets[0]; later ones use
    // secrets[1]. Used by the metadata secret-change test.
    std::size_t switch_secret_after{0};
    // Send periodic inbound frames of an unknown RPC constructor. The peer then
    // proves liveness by traffic while still ignoring every PING.
    bool inbound_chatter{false};
    // Answer RPC_HANDSHAKE with flag USE_CRC32C (0x800) and checksum every data
    // frame (in both directions) with Castagnoli instead of IEEE CRC-32. This is
    // the negotiated mode the real ME selects, and the mode the keepalive
    // intersection test must exercise.
    bool use_crc32c{false};
};

class PoolMe {
public:
    using Secret = std::array<std::uint8_t, 128>;
    using Options = PoolMeOptions;

    PoolMe(Secret secret, Options options = Options{}) : options_(options) {
        secrets_.push_back(std::move(secret));
        start();
    }
    PoolMe(std::vector<Secret> secrets, Options options = Options{})
        : secrets_(std::move(secrets)), options_(options) {
        start();
    }
    ~PoolMe() {
        stop_.store(true);
        {
            const std::lock_guard lock{mutex_};
            for (const auto& conn : conns_) {
                if (conn->fd >= 0) ::shutdown(conn->fd, SHUT_RDWR);
            }
        }
        if (acceptor_.joinable()) acceptor_.join();
        // Move the workers out under the lock, then join without it: serve()
        // takes mutex_ in finish(), so joining while holding it would deadlock.
        std::vector<std::thread> workers;
        {
            const std::lock_guard lock{mutex_};
            workers.swap(workers_);
        }
        for (auto& thread : workers) {
            if (thread.joinable()) thread.join();
        }
    }
    PoolMe(const PoolMe&) = delete;
    PoolMe& operator=(const PoolMe&) = delete;

    std::uint16_t port() const { return port_; }

    std::size_t accepted() const {
        return accepted_.load(std::memory_order_relaxed);
    }
    std::size_t ready() const {
        return ready_.load(std::memory_order_relaxed);
    }
    std::size_t active() const {
        const std::size_t total = accepted_.load(std::memory_order_relaxed);
        const std::size_t gone = closed_.load(std::memory_order_relaxed);
        return total - std::min(total, gone);
    }
    std::uint64_t pings(std::size_t index) const {
        const auto conn = find(index);
        return conn ? conn->pings.load(std::memory_order_relaxed) : 0;
    }
    std::uint64_t pongs(std::size_t index) const {
        const auto conn = find(index);
        return conn ? conn->pongs.load(std::memory_order_relaxed) : 0;
    }
    std::uint64_t messages(std::size_t index) const {
        const auto conn = find(index);
        return conn ? conn->messages.load(std::memory_order_relaxed) : 0;
    }
    // Wire size (including CBC padding) of the last RPC_PING frame received on
    // this connection: the keepalive frame-size invariant is observable here.
    std::uint64_t ping_frame_bytes(std::size_t index) const {
        const auto conn = find(index);
        return conn ? conn->ping_frame_bytes.load(std::memory_order_relaxed) : 0;
    }
    std::uint64_t crc_mismatches(std::size_t index) const {
        const auto conn = find(index);
        return conn ? conn->crc_mismatches.load(std::memory_order_relaxed) : 0;
    }
    int secret_index(std::size_t index) const {
        const auto conn = find(index);
        return conn ? conn->secret.load(std::memory_order_relaxed) : -1;
    }
    void close_connection(std::size_t index) {
        const auto conn = find(index);
        if (!conn) return;
        const std::lock_guard lock{mutex_};
        if (conn->fd >= 0) ::shutdown(conn->fd, SHUT_RDWR);
    }

private:
    struct Conn {
        std::size_t index{0};
        int fd{-1};
        bool answer_pings{true};
        // Read by the test thread (secret_index) and written by the connection
        // thread during the handshake, so it must be atomic under TSan.
        std::atomic<int> secret{-1};
        std::atomic<bool> ready{false};
        std::atomic<std::uint64_t> pings{0};
        std::atomic<std::uint64_t> pongs{0};
        std::atomic<std::uint64_t> messages{0};
        std::atomic<std::uint64_t> ping_frame_bytes{0};
        std::atomic<std::uint64_t> crc_mismatches{0};
    };

    std::shared_ptr<Conn> find(std::size_t index) const {
        const std::lock_guard lock{mutex_};
        if (index >= conns_.size()) return nullptr;
        return conns_[index];
    }

    void start() {
        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("pool ME cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = mtdd::io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("pool ME has no port");
        port_ = local->port;
        acceptor_ = std::thread([this] { accept_loop(); });
    }

    void accept_loop() {
        while (!stop_.load()) {
            pollfd entry{};
            entry.fd = listener_.get();
            entry.events = POLLIN;
            if (::poll(&entry, 1, 20) <= 0 || (entry.revents & POLLIN) == 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            timeval timeout{};
            timeout.tv_sec = 2;
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            timeout.tv_sec = 5;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            auto conn = std::make_shared<Conn>();
            conn->index = accepted_.load(std::memory_order_relaxed);
            conn->fd = fd;
            conn->answer_pings = options_.answer_pings &&
                                 !(options_.ignore_pings_on_first && conn->index == 0);
            accepted_.fetch_add(1, std::memory_order_relaxed);
            const std::lock_guard lock{mutex_};
            conns_.push_back(conn);
            workers_.emplace_back([this, conn] { serve(*conn); });
        }
    }

    int secret_for(std::size_t index) const {
        if (secrets_.empty()) return -1;
        if (options_.switch_secret_after != 0 && index >= options_.switch_secret_after &&
            secrets_.size() > 1) {
            return 1;
        }
        return 0;
    }

    bool read_plain_frame(int fd, Bytes& payload, std::int32_t& seq) {
        std::uint8_t header[4]{};
        if (!recv_exact(fd, header, sizeof(header), 5000)) return false;
        Bytes frame(header, header + 4);
        const std::uint32_t length = rd32(frame, 0);
        if (length < 16 || length > (16U << 20) || length % 4 != 0) return false;
        frame.resize(length);
        if (!recv_exact(fd, frame.data() + 4, length - 4, 5000)) return false;
        if (mtdd::protocol::crypto::crc32(
                std::span<const std::uint8_t>(frame).first(length - 4)) !=
            rd32(frame, length - 4)) {
            return false;
        }
        seq = static_cast<std::int32_t>(rd32(frame, 4));
        payload.assign(frame.begin() + 8, frame.end() - 4);
        return true;
    }

    // `data_frame` selects the negotiated checksum: the handshake answer is
    // always IEEE CRC-32 (only frames after it follow USE_CRC32C), so the
    // cipher pointer alone cannot discriminate (the answer is encrypted too).
    void write_frame(int fd, std::int32_t seq, std::span<const std::uint8_t> payload,
                     mtdd::protocol::crypto::AesCbc* cipher, bool data_frame = false) {
        Bytes frame;
        put32(frame, static_cast<std::uint32_t>(payload.size() + 12));
        put32(frame, static_cast<std::uint32_t>(seq));
        append(frame, payload);
        put32(frame, data_frame ? crc_for(frame) : mtdd::protocol::crypto::crc32(frame));
        if (cipher != nullptr) {
            while (frame.size() % 16 != 0) put32(frame, 4);
            cipher->encrypt(frame);
        }
        send_all(fd, frame);
    }

    std::uint32_t crc_for(std::span<const std::uint8_t> data) const {
        return options_.use_crc32c ? mtdd::protocol::crypto::crc32c(data)
                                   : mtdd::protocol::crypto::crc32(data);
    }

    bool handshake(Conn& conn, std::unique_ptr<mtdd::protocol::crypto::AesCbc>& incoming,
                   std::unique_ptr<mtdd::protocol::crypto::AesCbc>& outgoing) {
        Bytes payload;
        std::int32_t seq = 0;
        if (!read_plain_frame(conn.fd, payload, seq)) return false;
        if (seq != -2 || payload.size() != 32 || rd32(payload, 0) != 0x7acb87aaU) return false;
        const std::uint32_t timestamp = rd32(payload, 12);
        A16 nonce_client{};
        std::copy_n(payload.begin() + 16, 16, nonce_client.begin());
        const int secret_index = secret_for(conn.index);
        if (secret_index < 0) return false;
        const Secret& secret = secrets_[static_cast<std::size_t>(secret_index)];
        conn.secret.store(secret_index, std::memory_order_relaxed);

        const auto local = mtdd::io::local_endpoint(conn.fd);
        const auto peer = mtdd::io::peer_endpoint(conn.fd);
        if (!local || !peer) return false;

        A16 nonce_server{};
        for (std::size_t i = 0; i < nonce_server.size(); ++i) {
            nonce_server[i] = static_cast<std::uint8_t>(0xb0 + i);
        }
        Bytes answer;
        put32(answer, 0x7acb87aaU);
        for (int i = 0; i < 4; ++i) answer.push_back(secret[static_cast<std::size_t>(i)]);
        put32(answer, 1);
        put32(answer, timestamp);
        append(answer, nonce_server);
        write_frame(conn.fd, -2, answer, nullptr);

        std::array<std::uint8_t, 48> handshake_bytes{};
        if (!recv_exact(conn.fd, handshake_bytes.data(), handshake_bytes.size(), 5000))
            return false;

        mtdd::protocol::MiddleProxyKdfInput input;
        input.nonce_server = nonce_server;
        input.nonce_client = nonce_client;
        input.client_timestamp = timestamp;
        input.server = to_protocol(*local);
        input.local = to_protocol(*peer);
        input.secret = secret;
        const auto keys = mtdd::protocol::derive_middle_proxy_keys(input);
        incoming = std::make_unique<mtdd::protocol::crypto::AesCbc>(keys.write_key, keys.write_iv);
        incoming->decrypt(handshake_bytes);
        Bytes decrypted(handshake_bytes.begin(), handshake_bytes.end());
        if (rd32(decrypted, 4) != 0xffffffffU) return false;
        std::array<std::uint8_t, 12> sender_pid{};
        std::copy_n(handshake_bytes.begin() + 16, 12, sender_pid.begin());

        Bytes reply;
        put32(reply, 0x7682eef5U);
        put32(reply, options_.use_crc32c ? 0x800U : 0U);
        const std::array<std::uint8_t, 12> server_pid{127, 0, 0, 1, 0x22, 0x22,
                                                      0x34, 0x12, 0, 0, 0, 0x60};
        reply.insert(reply.end(), server_pid.begin(), server_pid.end());
        reply.insert(reply.end(), sender_pid.begin(), sender_pid.end());
        outgoing = std::make_unique<mtdd::protocol::crypto::AesCbc>(keys.read_key, keys.read_iv);
        write_frame(conn.fd, -1, reply, outgoing.get());
        return true;
    }

    void serve(Conn& conn) {
        std::unique_ptr<mtdd::protocol::crypto::AesCbc> incoming;
        std::unique_ptr<mtdd::protocol::crypto::AesCbc> outgoing;
        if (!handshake(conn, incoming, outgoing)) {
            finish(conn);
            return;
        }
        conn.ready.store(true, std::memory_order_relaxed);
        ready_.fetch_add(1, std::memory_order_relaxed);
        Bytes plain;
        Bytes cipher_pending;
        std::int32_t outgoing_seq = 0;
        while (!stop_.load()) {
            pollfd entry{};
            entry.fd = conn.fd;
            entry.events = POLLIN;
            if (::poll(&entry, 1, 20) <= 0) {
                if (options_.inbound_chatter && conn.fd >= 0) {
                    // Unknown RPC constructor: inbound byte progress that grants
                    // no liveness credit (no PONG, no answer, no close).
                    Bytes chatter;
                    put32(chatter, 0x5eed5eedU);
                    put32(chatter, 0);
                    write_frame(conn.fd, outgoing_seq++, chatter, outgoing.get());
                }
                continue;
            }
            if ((entry.revents & (POLLERR | POLLNVAL)) != 0) break;
            if ((entry.revents & (POLLIN | POLLHUP)) == 0) continue;
            bool eof = false;
            while (true) {
                std::array<std::uint8_t, 65536> buffer{};
                const ssize_t got = ::recv(conn.fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
                if (got > 0) {
                    append(cipher_pending,
                           std::span<const std::uint8_t>(buffer).first(
                               static_cast<std::size_t>(got)));
                } else if (got == 0) {
                    eof = true;
                    break;
                } else if (errno == EINTR) {
                    continue;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    eof = true;
                    break;
                }
            }
            while (cipher_pending.size() >= 16) {
                std::array<std::uint8_t, 16> block{};
                std::copy_n(cipher_pending.begin(), 16, block.begin());
                incoming->decrypt(block);
                append(plain, block);
                cipher_pending.erase(cipher_pending.begin(), cipher_pending.begin() + 16);
            }
            if (!consume_frames(conn, plain, outgoing.get(), outgoing_seq)) break;
            if (eof) break;
        }
        finish(conn);
    }

    bool consume_frames(Conn& conn, Bytes& plain, mtdd::protocol::crypto::AesCbc* outgoing,
                        std::int32_t& outgoing_seq) {
        while (plain.size() >= 4) {
            const std::uint32_t length = rd32(plain, 0);
            if (length == 4) {
                plain.erase(plain.begin(), plain.begin() + 4);
                continue;
            }
            if (length < 16 || length > (16U << 20) || length % 4 != 0) return false;
            if (plain.size() < length) return true;
            if (crc_for(std::span<const std::uint8_t>(plain).first(length - 4)) !=
                rd32(plain, length - 4)) {
                conn.crc_mismatches.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            const std::uint32_t type = rd32(plain, 8);
            const Bytes payload(plain.begin() + 8,
                                plain.begin() + static_cast<std::ptrdiff_t>(length) - 4);
            plain.erase(plain.begin(), plain.begin() + static_cast<std::ptrdiff_t>(length));
            if (type == 0x5730a2dfU) { // RPC_PING
                if (payload.size() != 12) return false;
                // Record the true wire size (declared length + CBC padding).
                conn.ping_frame_bytes.store(
                    (static_cast<std::uint64_t>(length) + 15U) & ~std::uint64_t{15U},
                    std::memory_order_relaxed);
                conn.pings.fetch_add(1, std::memory_order_relaxed);
                if (!conn.answer_pings) continue;
                Bytes pong;
                put32(pong, 0x8430eaa7U);
                pong.insert(pong.end(), payload.begin() + 4, payload.begin() + 12);
                write_frame(conn.fd, outgoing_seq++, pong, outgoing, /*data_frame=*/true);
                conn.pongs.fetch_add(1, std::memory_order_relaxed);
            } else if (type == 0x36cef1eeU) { // RPC_PROXY_REQ
                if (payload.size() < 84) return false;
                conn.messages.fetch_add(1, std::memory_order_relaxed);
                if (!options_.answer_clients) continue;
                ConnId conn_id{};
                std::copy_n(payload.begin() + 8, 8, conn_id.begin());
                std::array<std::uint8_t, 8> data{0xaa, 0xbb, 0xcc, 0xdd,
                                                 0x11, 0x22, 0x33, 0x44};
                if (payload.size() >= 92) {
                    std::copy_n(payload.begin() + 84, 8, data.begin());
                }
                Bytes response;
                put32(response, 0x4403da0dU);
                put32(response, 0);
                append(response, conn_id);
                append(response, data);
                write_frame(conn.fd, outgoing_seq++, response, outgoing, /*data_frame=*/true);
            }
            // RPC_CLOSE_CONN and unknown constructors are ignored: the shared
            // transport stays up, exactly like Telegram's middle end.
        }
        return true;
    }

    void finish(Conn& conn) {
        const std::lock_guard lock{mutex_};
        if (conn.fd >= 0) {
            ::close(conn.fd);
            conn.fd = -1;
        }
        closed_.fetch_add(1, std::memory_order_relaxed);
    }

    std::vector<Secret> secrets_;
    Options options_;
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::thread acceptor_;
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<Conn>> conns_;
    std::vector<std::thread> workers_;
    std::atomic<bool> stop_{false};
    std::atomic<std::size_t> accepted_{0};
    std::atomic<std::size_t> ready_{0};
    std::atomic<std::size_t> closed_{0};
};

// ---------------------------------------------------------------------------
// Daemon harness
// ---------------------------------------------------------------------------

class Daemon {
public:
    Daemon(std::uint16_t me_port, bool with_metadata,
           const std::function<void(mtdd::Config&)>& tweak = {},
           bool enable_ip_history = false)
        : services(me_port, with_metadata, tweak),
          runtime(services.config, *services.store, services.stats, *services.metadata,
                  services.barrier) {
        if (enable_ip_history) services.stats.enable_ip_history();
        worker_ = std::thread([this] {
            worker_tid_.store(static_cast<pid_t>(::syscall(SYS_gettid)));
            runtime.run();
        });
    }
    ~Daemon() {
        runtime.request_stop();
        if (worker_.joinable()) worker_.join();
    }
    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    void stop() {
        runtime.request_stop();
        if (worker_.joinable()) worker_.join();
    }

    std::uint16_t port() const { return runtime.port(); }
    pid_t worker_tid() const { return worker_tid_.load(); }
    std::size_t workers() const { return runtime.worker_count(); }
    void set_tunables(std::uint32_t clients_per_writer, std::uint32_t connections_per_dc) {
        runtime.set_tunables(clients_per_writer, connections_per_dc);
    }
    std::vector<std::uint64_t> accepted_per_worker() const {
        return runtime.accepted_clients_per_worker();
    }
    std::vector<std::uint64_t> replay_per_worker() const {
        return runtime.replay_rejections_per_worker();
    }
    Services services;

private:
    mtdd::Runtime runtime;
    std::thread worker_;
    std::atomic<pid_t> worker_tid_{0};
};

// ---------------------------------------------------------------------------

[[maybe_unused]] mtdd::control::MeDcSnapshot me_dc(const mtdd::control::Statistics& stats,
                                  std::string_view label) {
    const auto snapshot = stats.snapshot();
    const auto found = snapshot.me_dcs.find(std::string(label));
    if (found != snapshot.me_dcs.end()) return found->second;
    return {};
}

} // namespace

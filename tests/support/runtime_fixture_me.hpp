#pragma once

#include "runtime_fixture_base.hpp"

namespace {

struct FakeMeObservation {
    bool ok{false};
    ConnId conn_id{};
    Bytes inner;
    std::array<std::uint8_t, 16> ad_tag{};
    std::size_t frames{0};
    // our_addr from the first RPC_PROXY_REQ (20-byte ME endpoint form).
    std::array<std::uint8_t, 20> our_addr{};
    // The client address the proxy reported in the RPC_PROXY_REQ.
    std::array<std::uint8_t, 20> client_addr{};
    // sender_pid from the encrypted RPC_HANDSHAKE request.
    std::array<std::uint8_t, 12> sender_pid{};
    bool saw_sender_pid{false};
    // The proxy's outbound ME source port (peer of the accepted fake-ME fd).
    std::uint16_t peer_port{0};
    // RPC_CLOSE_CONN frames the proxy sent back for orphaned answers/acks.
    std::vector<ConnId> remote_closes;
};

// Distinct conn ids the fake ME uses for answers no client owns.
ConnId orphan_conn_id(std::size_t index) {
    return ConnId{0xee, 0xdd, 0xc0, 0xde, 0, 0, 0, static_cast<std::uint8_t>(index + 1)};
}

constexpr std::size_t kBurstCount = 24;
constexpr std::size_t kBurstSize = 16U * 1024U;

Bytes burst_payload(std::size_t index) {
    Bytes payload(kBurstSize, static_cast<std::uint8_t>((index + 1U) & 0xffU));
    payload[0] = static_cast<std::uint8_t>(index);
    return payload;
}

class FakeMe {
public:
    explicit FakeMe(std::array<std::uint8_t, 128> secret, std::size_t frames = 1,
                    std::chrono::milliseconds delay = std::chrono::milliseconds{0},
                    std::size_t connections = 1,
                    std::chrono::milliseconds handshake_delay = std::chrono::milliseconds{0},
                    std::chrono::milliseconds drop_delay = std::chrono::milliseconds{0},
                    bool respond_each = false, std::size_t response_bytes = 0,
                    int idle_read_timeout_ms = 1500,
                    std::size_t min_inner = kBurstSize,
                    bool require_sequence = true, std::size_t orphan_answers = 0,
                    bool inbound_control = false)
        : secret_(std::move(secret)), frames_expected_(frames), delay_(delay),
          connections_(connections), handshake_delay_(handshake_delay),
          drop_delay_(drop_delay), respond_each_(respond_each),
          response_bytes_(response_bytes), idle_read_timeout_ms_(idle_read_timeout_ms),
          min_inner_(min_inner), require_sequence_(require_sequence),
          orphan_answers_(orphan_answers), inbound_control_(inbound_control) {
        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("fake ME cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = mtdd::io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("fake ME has no port");
        port_ = local->port;
        future_ = promise_.get_future();
        thread_ = std::thread([this] { run(); });
    }
    ~FakeMe() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
    }
    std::uint16_t port() const { return port_; }
    std::shared_future<FakeMeObservation>& future() { return future_; }

private:
    void finish(FakeMeObservation observation) {
        try {
            promise_.set_value(std::move(observation));
        } catch (...) {
        }
    }

    void sleep_wait(std::chrono::milliseconds duration) {
        const auto end = std::chrono::steady_clock::now() + duration;
        while (!stop_.load()) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= end) return;
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(end - now);
            std::this_thread::sleep_for(std::min(remaining, std::chrono::milliseconds{20}));
        }
    }

    int accept_one() {
        while (!stop_.load()) {
            pollfd entry{};
            entry.fd = listener_.get();
            entry.events = POLLIN;
            if (::poll(&entry, 1, 50) > 0 && (entry.revents & POLLIN) != 0) {
                const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
                if (fd >= 0) return fd;
            }
        }
        return -1;
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
                std::span<const std::uint8_t>(frame).first(length - 4)) != rd32(frame, length - 4)) {
            return false;
        }
        seq = static_cast<std::int32_t>(rd32(frame, 4));
        payload.assign(frame.begin() + 8, frame.end() - 4);
        return true;
    }

    bool read_encrypted_frame(int fd, mtdd::protocol::crypto::AesCbc& cipher, Bytes& buffer,
                              Bytes& payload, std::int32_t& seq) {
        while (true) {
            if (buffer.size() >= 4) {
                const std::uint32_t length = rd32(buffer, 0);
                if (length == 4) {
                    buffer.erase(buffer.begin(), buffer.begin() + 4);
                    continue;
                }
                if (length < 16 || length > (16U << 20) || length % 4 != 0) return false;
                if (buffer.size() >= length) {
                    if (mtdd::protocol::crypto::crc32(
                            std::span<const std::uint8_t>(buffer).first(length - 4)) !=
                        rd32(buffer, length - 4)) {
                        return false;
                    }
                    seq = static_cast<std::int32_t>(rd32(buffer, 4));
                    payload.assign(buffer.begin() + 8,
                                   buffer.begin() + static_cast<std::ptrdiff_t>(length) - 4);
                    buffer.erase(buffer.begin(),
                                 buffer.begin() + static_cast<std::ptrdiff_t>(length));
                    return true;
                }
            }
            std::array<std::uint8_t, 16> block{};
            if (!recv_exact(fd, block.data(), block.size(), idle_read_timeout_ms_)) return false;
            cipher.decrypt(block);
            append(buffer, block);
        }
    }

    void write_frame(int fd, std::int32_t seq, std::span<const std::uint8_t> payload,
                     mtdd::protocol::crypto::AesCbc* cipher) {
        Bytes frame;
        put32(frame, static_cast<std::uint32_t>(payload.size() + 12));
        put32(frame, static_cast<std::uint32_t>(seq));
        append(frame, payload);
        put32(frame, mtdd::protocol::crypto::crc32(frame));
        if (cipher != nullptr) {
            while (frame.size() % 16 != 0) put32(frame, 4);
            cipher->encrypt(frame);
        }
        send_all(fd, frame);
    }

    void write_response(int fd, std::int32_t seq, const ConnId& conn_id,
                        const std::array<std::uint8_t, 8>& data,
                        mtdd::protocol::crypto::AesCbc& outgoing) {
        Bytes payload(data.begin(), data.end());
        if (response_bytes_ != 0) {
            payload.assign(response_bytes_, 0x5a);
            std::copy(data.begin(), data.end(), payload.begin());
        }
        Bytes response;
        put32(response, 0x4403da0dU);
        put32(response, 0);
        append(response, conn_id);
        append(response, payload);
        write_frame(fd, seq, response, &outgoing);
    }

    std::unique_ptr<mtdd::protocol::crypto::AesCbc>
    make_cipher(const A32& key, const A16& iv) {
        return std::make_unique<mtdd::protocol::crypto::AesCbc>(key, iv);
    }

    bool handshake(int fd, std::unique_ptr<mtdd::protocol::crypto::AesCbc>& incoming,
                   std::unique_ptr<mtdd::protocol::crypto::AesCbc>& outgoing,
                   FakeMeObservation& observation) {
        Bytes payload;
        std::int32_t seq = 0;
        if (!read_plain_frame(fd, payload, seq) || seq != -2 || payload.size() != 32) return false;
        if (rd32(payload, 0) != 0x7acb87aaU) return false;
        const std::uint32_t timestamp = rd32(payload, 12);
        A16 nonce_client{};
        std::copy_n(payload.begin() + 16, 16, nonce_client.begin());
        A16 nonce_server{};
        for (std::size_t i = 0; i < nonce_server.size(); ++i) {
            nonce_server[i] = static_cast<std::uint8_t>(0xa0 + i);
        }
        const auto local = mtdd::io::local_endpoint(fd);
        const auto peer = mtdd::io::peer_endpoint(fd);
        if (!local || !peer) return false;
        observation.peer_port = peer->port;
        mtdd::protocol::MiddleProxyKdfInput input;
        input.nonce_server = nonce_server;
        input.nonce_client = nonce_client;
        input.client_timestamp = timestamp;
        input.server = to_protocol(*local);
        input.local = to_protocol(*peer);
        input.secret = secret_;
        auto keys = mtdd::protocol::derive_middle_proxy_keys(input);

        if (handshake_delay_.count() > 0) sleep_wait(handshake_delay_);

        Bytes answer;
        put32(answer, 0x7acb87aaU);
        for (int i = 0; i < 4; ++i) answer.push_back(secret_[static_cast<std::size_t>(i)]);
        put32(answer, 1);
        put32(answer, timestamp);
        append(answer, nonce_server);
        write_frame(fd, -2, answer, nullptr);

        incoming = make_cipher(keys.write_key, keys.write_iv);
        std::array<std::uint8_t, 48> handshake_bytes{};
        if (!recv_exact(fd, handshake_bytes.data(), handshake_bytes.size(), 5000)) return false;
        incoming->decrypt(handshake_bytes);
        if (rd32(Bytes(handshake_bytes.begin(), handshake_bytes.end()), 4) !=
            static_cast<std::uint32_t>(-1)) {
            return false;
        }
        // RPC_HANDSHAKE payload: type, flags, sender_pid, peer_pid.
        std::copy_n(handshake_bytes.begin() + 16, 12, observation.sender_pid.begin());
        observation.saw_sender_pid = true;

        Bytes reply;
        put32(reply, 0x7682eef5U);
        put32(reply, 0);
        // ME-side process_id (server identity) followed by the echo of the
        // proxy's real sender_pid, exactly like a real middle-end answer.
        const std::array<std::uint8_t, 12> server_pid{149, 154, 175, 50, 0xb8, 0x22,
                                                      0x34, 0x12, 0x00, 0x00, 0x00, 0x60};
        reply.insert(reply.end(), server_pid.begin(), server_pid.end());
        reply.insert(reply.end(), observation.sender_pid.begin(), observation.sender_pid.end());
        outgoing = make_cipher(keys.read_key, keys.read_iv);
        write_frame(fd, -1, reply, outgoing.get());
        (void)observation;
        return true;
    }

    bool data_phase(int fd, mtdd::protocol::crypto::AesCbc& incoming,
                    mtdd::protocol::crypto::AesCbc& outgoing, FakeMeObservation& observation) {
        if (delay_.count() > 0) sleep_wait(delay_);
        Bytes buffer;
        Bytes payload;
        std::int32_t seq = 0;
        std::size_t data_frames = 0;
        std::int32_t response_seq = 0;
        while (data_frames < frames_expected_ && !stop_.load()) {
            if (!read_encrypted_frame(fd, incoming, buffer, payload, seq)) return false;
            if (payload.size() == 12 && rd32(payload, 0) == 0x1fcf425dU) {
                continue; // per-logical RPC_CLOSE_CONN: shared transport stays up
            }
            if (payload.size() < 84 + min_inner_) return false;
            if (rd32(payload, 0) != 0x36cef1eeU) return false;
            ConnId frame_conn{};
            std::copy_n(payload.begin() + 8, 8, frame_conn.begin());
            std::copy_n(payload.begin() + 16, 20, observation.client_addr.begin());
            std::copy_n(payload.begin() + 36, 20, observation.our_addr.begin());
            std::copy_n(payload.begin() + 65, 16, observation.ad_tag.begin());
            observation.inner.assign(payload.begin() + 84, payload.end());
            if (require_sequence_ && !respond_each_ &&
                observation.inner != burst_payload(data_frames)) {
                return false;
            }
            if (data_frames == 0) observation.conn_id = frame_conn;
            ++data_frames;
            ++observation.frames;
            if (respond_each_) {
                const std::array<std::uint8_t, 8> returned{0xaa, 0xbb, 0xcc, 0xdd,
                                                           0x11, 0x22, 0x33, 0x44};
                write_response(fd, response_seq, frame_conn, returned, outgoing);
                ++response_seq;
            }
        }
        if (data_frames != frames_expected_) return false;
        if (!respond_each_) {
            const std::array<std::uint8_t, 8> returned{0xaa, 0xbb, 0xcc, 0xdd,
                                                       0x11, 0x22, 0x33, 0x44};
            write_response(fd, 0, observation.conn_id, returned, outgoing);
        }
        if (orphan_answers_ != 0) {
            // Deliver answers for conn ids no client owns, then observe whether
            // the proxy releases the remote mappings with RPC_CLOSE_CONN.
            const std::array<std::uint8_t, 8> orphan_data{0x01, 0x02, 0x03, 0x04,
                                                          0x05, 0x06, 0x07, 0x08};
            // The single response above consumed seq 0 when respond_each_ is
            // off; orphan frames must continue the same write sequence.
            std::int32_t orphan_seq = respond_each_ ? response_seq : 1;
            for (std::size_t i = 0; i < orphan_answers_; ++i) {
                write_response(fd, orphan_seq, orphan_conn_id(i), orphan_data, outgoing);
                ++orphan_seq;
            }
        }
        if (inbound_control_) {
            // Inbound control constructors Telegram might send: a logical
            // CLOSE_CONN, an unrecognized constructor and a malformed CLOSE_CONN.
            std::int32_t control_seq = (respond_each_ ? response_seq : 1) +
                                       static_cast<std::int32_t>(orphan_answers_);
            const ConnId closed{0xcc, 0xcc, 0xcc, 0xcc, 0, 0, 0, 1};
            Bytes close_conn;
            put32(close_conn, 0x1fcf425dU);
            append(close_conn, closed);
            write_frame(fd, control_seq, close_conn, &outgoing);
            ++control_seq;
            Bytes unknown_ctor;
            put32(unknown_ctor, 0x12345678U);
            put32(unknown_ctor, 0);
            write_frame(fd, control_seq, unknown_ctor, &outgoing);
            ++control_seq;
            Bytes malformed_close;
            put32(malformed_close, 0x1fcf425dU);
            put32(malformed_close, 0);
            write_frame(fd, control_seq, malformed_close, &outgoing);
        }
        if (orphan_answers_ != 0 || inbound_control_) {
            // Reads end on the idle timeout; each successful read is one frame.
            Bytes close_buffer;
            Bytes close_payload;
            std::int32_t close_seq = 0;
            while (read_encrypted_frame(fd, incoming, close_buffer, close_payload,
                                        close_seq)) {
                if (close_payload.size() == 12 &&
                    rd32(close_payload, 0) == 0x1fcf425dU) {
                    ConnId closed{};
                    std::copy_n(close_payload.begin() + 4, 8, closed.begin());
                    observation.remote_closes.push_back(closed);
                }
            }
        }
        return true;
    }

    void run() {
        for (std::size_t connection = 0; connection < connections_; ++connection) {
            const int fd = accept_one();
            if (fd < 0) {
                finish(FakeMeObservation{});
                return;
            }
            const bool last = connection + 1 == connections_;
            FakeMeObservation observation;
            std::unique_ptr<mtdd::protocol::crypto::AesCbc> incoming;
            std::unique_ptr<mtdd::protocol::crypto::AesCbc> outgoing;
            bool ok = handshake(fd, incoming, outgoing, observation);
            if (ok && !last) {
                if (drop_delay_.count() > 0) sleep_wait(drop_delay_);
                ::close(fd);
                continue;
            }
            if (ok) ok = data_phase(fd, *incoming, *outgoing, observation);
            if (ok) {
                observation.ok = true;
                finish(observation);
                while (!stop_.load()) std::this_thread::sleep_for(20ms);
            } else {
                finish(FakeMeObservation{});
            }
            ::close(fd);
            return;
        }
        finish(FakeMeObservation{});
    }

    std::array<std::uint8_t, 128> secret_{};
    std::size_t frames_expected_{1};
    std::chrono::milliseconds delay_{0};
    std::size_t connections_{1};
    std::chrono::milliseconds handshake_delay_{0};
    std::chrono::milliseconds drop_delay_{0};
    bool respond_each_{false};
    std::size_t response_bytes_{0};
    int idle_read_timeout_ms_{1500};
    std::size_t min_inner_{kBurstSize};
    bool require_sequence_{true};
    std::size_t orphan_answers_{0};
    bool inbound_control_{false};
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::promise<FakeMeObservation> promise_;
    std::shared_future<FakeMeObservation> future_;
};

// Concurrent fake Middle-End used by multi-reactor tests. Each accepted TCP
// connection is served by its own thread, because every reactor opens its own
// pooled ME connection to the same endpoint; FakeMe's sequential connection
// mode would hand all traffic to the last reactor only. Every data frame is
// answered immediately so N clients can share the pool without ordering
// assumptions between reactors.
class MultiFakeMe {
public:
    explicit MultiFakeMe(std::array<std::uint8_t, 128> secret,
                         std::size_t expected_connections)
        : secret_(std::move(secret)), expected_(expected_connections) {
        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("multi fake ME cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = mtdd::io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("multi fake ME has no port");
        port_ = local->port;
        accept_thread_ = std::thread([this] { accept_loop(); });
    }
    ~MultiFakeMe() {
        stop_.store(true);
        if (accept_thread_.joinable()) accept_thread_.join();
        for (auto& thread : handlers_) {
            if (thread.joinable()) thread.join();
        }
    }
    MultiFakeMe(const MultiFakeMe&) = delete;
    MultiFakeMe& operator=(const MultiFakeMe&) = delete;

    std::uint16_t port() const { return port_; }
    std::uint64_t connections() const { return connections_.load(); }
    std::uint64_t frames() const { return frames_.load(); }

    bool wait_for_connections(std::size_t count, std::chrono::milliseconds timeout) const {
        return wait_for([&] { return connections_.load() >= count; }, timeout);
    }

private:
    bool read_exact(int fd, std::uint8_t* data, std::size_t size, int timeout_ms) {
        return recv_exact(fd, data, size, timeout_ms);
    }

    bool read_plain_frame(int fd, Bytes& payload, std::int32_t& seq) {
        std::uint8_t header[4]{};
        if (!read_exact(fd, header, sizeof(header), 5000)) return false;
        Bytes frame(header, header + 4);
        const std::uint32_t length = rd32(frame, 0);
        if (length < 16 || length > (16U << 20) || length % 4 != 0) return false;
        frame.resize(length);
        if (!read_exact(fd, frame.data() + 4, length - 4, 5000)) return false;
        if (mtdd::protocol::crypto::crc32(
                std::span<const std::uint8_t>(frame).first(length - 4)) !=
            rd32(frame, length - 4)) {
            return false;
        }
        seq = static_cast<std::int32_t>(rd32(frame, 4));
        payload.assign(frame.begin() + 8, frame.end() - 4);
        return true;
    }

    bool read_encrypted_frame(int fd, mtdd::protocol::crypto::AesCbc& cipher,
                              Bytes& buffer, Bytes& payload, std::int32_t& seq) {
        while (!stop_.load()) {
            if (buffer.size() >= 4) {
                const std::uint32_t length = rd32(buffer, 0);
                if (length == 4) {
                    buffer.erase(buffer.begin(), buffer.begin() + 4);
                    continue;
                }
                if (length < 16 || length > (16U << 20) || length % 4 != 0) return false;
                if (buffer.size() >= length) {
                    if (mtdd::protocol::crypto::crc32(
                            std::span<const std::uint8_t>(buffer).first(length - 4)) !=
                        rd32(buffer, length - 4)) {
                        return false;
                    }
                    seq = static_cast<std::int32_t>(rd32(buffer, 4));
                    payload.assign(buffer.begin() + 8,
                                   buffer.begin() + static_cast<std::ptrdiff_t>(length) - 4);
                    buffer.erase(buffer.begin(),
                                 buffer.begin() + static_cast<std::ptrdiff_t>(length));
                    return true;
                }
            }
            std::array<std::uint8_t, 16> block{};
            if (!read_exact(fd, block.data(), block.size(), 30000)) return false;
            cipher.decrypt(block);
            append(buffer, block);
        }
        return false;
    }

    void write_frame(int fd, std::int32_t seq, std::span<const std::uint8_t> payload,
                     mtdd::protocol::crypto::AesCbc* cipher) {
        Bytes frame;
        put32(frame, static_cast<std::uint32_t>(payload.size() + 12));
        put32(frame, static_cast<std::uint32_t>(seq));
        append(frame, payload);
        put32(frame, mtdd::protocol::crypto::crc32(frame));
        if (cipher != nullptr) {
            while (frame.size() % 16 != 0) put32(frame, 4);
            cipher->encrypt(frame);
        }
        send_all(fd, frame);
    }

    bool handshake(int fd, std::unique_ptr<mtdd::protocol::crypto::AesCbc>& incoming,
                   std::unique_ptr<mtdd::protocol::crypto::AesCbc>& outgoing) {
        Bytes payload;
        std::int32_t seq = 0;
        if (!read_plain_frame(fd, payload, seq) || seq != -2 || payload.size() != 32) return false;
        if (rd32(payload, 0) != 0x7acb87aaU) return false;
        const std::uint32_t timestamp = rd32(payload, 12);
        A16 nonce_client{};
        std::copy_n(payload.begin() + 16, 16, nonce_client.begin());
        A16 nonce_server{};
        for (std::size_t i = 0; i < nonce_server.size(); ++i) {
            nonce_server[i] = static_cast<std::uint8_t>(0xa0 + i);
        }
        const auto local = mtdd::io::local_endpoint(fd);
        const auto peer = mtdd::io::peer_endpoint(fd);
        if (!local || !peer) return false;
        mtdd::protocol::MiddleProxyKdfInput input;
        input.nonce_server = nonce_server;
        input.nonce_client = nonce_client;
        input.client_timestamp = timestamp;
        input.server = to_protocol(*local);
        input.local = to_protocol(*peer);
        input.secret = secret_;
        auto keys = mtdd::protocol::derive_middle_proxy_keys(input);

        Bytes answer;
        put32(answer, 0x7acb87aaU);
        for (int i = 0; i < 4; ++i) answer.push_back(secret_[static_cast<std::size_t>(i)]);
        put32(answer, 1);
        put32(answer, timestamp);
        append(answer, nonce_server);
        write_frame(fd, -2, answer, nullptr);

        incoming = std::make_unique<mtdd::protocol::crypto::AesCbc>(keys.write_key,
                                                                    keys.write_iv);
        std::array<std::uint8_t, 48> handshake_bytes{};
        if (!read_exact(fd, handshake_bytes.data(), handshake_bytes.size(), 5000)) return false;
        incoming->decrypt(handshake_bytes);
        if (rd32(Bytes(handshake_bytes.begin(), handshake_bytes.end()), 4) !=
            static_cast<std::uint32_t>(-1)) {
            return false;
        }
        Bytes reply;
        put32(reply, 0x7682eef5U);
        put32(reply, 0);
        const std::array<std::uint8_t, 12> server_pid{149, 154, 175, 50, 0xb8, 0x22,
                                                      0x34, 0x12, 0x00, 0x00, 0x00, 0x60};
        reply.insert(reply.end(), server_pid.begin(), server_pid.end());
        reply.insert(reply.end(), handshake_bytes.begin() + 16, handshake_bytes.begin() + 28);
        outgoing = std::make_unique<mtdd::protocol::crypto::AesCbc>(keys.read_key,
                                                                    keys.read_iv);
        write_frame(fd, -1, reply, outgoing.get());
        return true;
    }

    void serve(int fd) {
        std::unique_ptr<mtdd::protocol::crypto::AesCbc> incoming;
        std::unique_ptr<mtdd::protocol::crypto::AesCbc> outgoing;
        if (!handshake(fd, incoming, outgoing)) {
            ::close(fd);
            return;
        }
        connections_.fetch_add(1);
        Bytes buffer;
        Bytes payload;
        std::int32_t seq = 0;
        std::int32_t response_seq = 0;
        while (!stop_.load() &&
               read_encrypted_frame(fd, *incoming, buffer, payload, seq)) {
            if (payload.size() == 12 && rd32(payload, 0) == 0x1fcf425dU) continue;
            if (payload.size() < 92 || rd32(payload, 0) != 0x36cef1eeU) continue;
            ConnId conn_id{};
            std::copy_n(payload.begin() + 8, 8, conn_id.begin());
            frames_.fetch_add(1);
            Bytes response;
            put32(response, 0x4403da0dU);
            put32(response, 0);
            append(response, conn_id);
            const std::array<std::uint8_t, 8> returned{0xaa, 0xbb, 0xcc, 0xdd,
                                                       0x11, 0x22, 0x33, 0x44};
            append(response, returned);
            write_frame(fd, response_seq++, response, outgoing.get());
        }
        ::close(fd);
    }

    void accept_loop() {
        while (!stop_.load()) {
            pollfd entry{};
            entry.fd = listener_.get();
            entry.events = POLLIN;
            if (::poll(&entry, 1, 50) <= 0 || (entry.revents & POLLIN) == 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            handlers_.emplace_back([this, fd] { serve(fd); });
        }
    }

    std::array<std::uint8_t, 128> secret_{};
    std::size_t expected_{1};
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::thread accept_thread_;
    std::vector<std::thread> handlers_;
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> connections_{0};
    std::atomic<std::uint64_t> frames_{0};
};

// ---------------------------------------------------------------------------
// Multi-connection ME peer
// ---------------------------------------------------------------------------

// Unlike FakeMe (which models one sequential ME connection and then a single
// data phase), PoolMe accepts several concurrent ME connections, answers or
// ignores RPC_PING per connection, echoes client requests, and can be told to
// drop one connection. This is the peer used by the pool/draining tests.
} // namespace

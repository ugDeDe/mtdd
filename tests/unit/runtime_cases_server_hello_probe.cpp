#include "../support/runtime_fixture.hpp"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <map>
#include <set>

// ---------------------------------------------------------------------------
// Server-flight probe: the background masking thread measures the encrypted
// first flight of each masked tls_domain with a real TLS 1.3 handshake, and
// FakeTLS ServerHellos then carry that length (per user domain). The real
// domain is never reached: the masking endpoint override sends every probe to
// a local OpenSSL TLS 1.3 server with self-signed certificates made here.
// ---------------------------------------------------------------------------

namespace {

constexpr std::string_view kFront = "front.test";
constexpr std::string_view kBobSecretHex = "101112131415161718191a1b1c1d1e1f";

using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;

// Self-signed Ed25519 certificate (constant-size signatures, so the flight
// size is the same on every handshake). `extra_names` subjectAltNames make
// one domain's certificate, and therefore its flight, larger than another's.
std::pair<PKey, Cert> self_signed(std::string_view name, int extra_names) {
    PKey key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), &EVP_PKEY_free);
    Cert cert(X509_new(), &X509_free);
    if (!key || !cert) throw std::runtime_error("cannot create test certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), key.get());
    X509_NAME* subject = X509_get_subject_name(cert.get());
    const std::string cn(name);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert.get(), subject);
    std::string san = "DNS:" + cn;
    for (int i = 0; i < extra_names; ++i) san += ",DNS:alt" + std::to_string(i) + "." + cn;
    X509V3_CTX v3{};
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, cert.get(), cert.get(), nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, san.c_str());
    if (ext == nullptr) throw std::runtime_error("cannot add subjectAltName");
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    if (X509_sign(cert.get(), key.get(), nullptr) <= 0) throw std::runtime_error("cannot sign");
    return {std::move(key), std::move(cert)};
}

// TLS 1.3-only OpenSSL server on 127.0.0.1, one connection at a time. It
// computes, from its own record callback, the flight the probe must report
// for each SNI: the ApplicationData records it writes before reading the
// client's Finished, as one record body (sum of bodies + 5 per extra header).
// In `stall` mode it accepts TCP and never answers.
class LocalTlsServer {
public:
    enum class Mode { serve, stall };

    explicit LocalTlsServer(Mode mode = Mode::serve) : mode_(mode) {
        auto global = self_signed(kDomain, 0);
        auto front = self_signed(kFront, 40);
        global_key_ = std::move(global.first);
        global_cert_ = std::move(global.second);
        front_key_ = std::move(front.first);
        front_cert_ = std::move(front.second);
        ctx_.reset(SSL_CTX_new(TLS_server_method()));
        if (!ctx_) throw std::runtime_error("SSL_CTX_new");
        SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_3_VERSION);
        SSL_CTX_use_certificate(ctx_.get(), global_cert_.get());
        SSL_CTX_use_PrivateKey(ctx_.get(), global_key_.get());
        SSL_CTX_set_tlsext_servername_callback(ctx_.get(), &LocalTlsServer::on_servername);
        SSL_CTX_set_tlsext_servername_arg(ctx_.get(), this);

        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("tls server cannot listen");
        listener_ = std::move(listener.fd);
        port_ = mtdd::io::local_endpoint(listener_.get())->port;
        thread_ = std::thread([this] { accept_loop(); });
    }
    ~LocalTlsServer() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        for (const int fd : stalled_) ::close(fd);
    }
    LocalTlsServer(const LocalTlsServer&) = delete;
    LocalTlsServer& operator=(const LocalTlsServer&) = delete;

    std::uint16_t port() const { return port_; }
    std::uint64_t accepted() const { return accepted_.load(); }
    std::optional<std::size_t> flight_for(std::string_view sni) const {
        const std::lock_guard lock{mutex_};
        const auto found = flights_.find(std::string(sni));
        if (found == flights_.end()) return std::nullopt;
        return found->second;
    }
    std::uint64_t handshakes(std::string_view sni) const {
        const std::lock_guard lock{mutex_};
        const auto found = handshakes_.find(std::string(sni));
        return found == handshakes_.end() ? 0 : found->second;
    }
    std::set<std::string> server_names() const {
        const std::lock_guard lock{mutex_};
        std::set<std::string> out;
        for (const auto& [name, count] : handshakes_) out.insert(name);
        return out;
    }

private:
    struct Flight {
        std::size_t bodies{0};
        std::size_t records{0};
        bool done{false};
    };

    static int on_servername(SSL* ssl, int*, void* arg) {
        auto* self = static_cast<LocalTlsServer*>(arg);
        const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (name != nullptr && std::string_view(name) == kFront) {
            SSL_use_certificate(ssl, self->front_cert_.get());
            SSL_use_PrivateKey(ssl, self->front_key_.get());
        }
        return SSL_TLSEXT_ERR_OK;
    }
    static void on_record(int write_p, int, int content_type, const void* buf, std::size_t len,
                          SSL*, void* arg) {
        auto* flight = static_cast<Flight*>(arg);
        if (content_type != SSL3_RT_HEADER || len < 5 || flight->done) return;
        const auto* header = static_cast<const std::uint8_t*>(buf);
        if (write_p == 0) {
            if (flight->records > 0) flight->done = true;  // the client's Finished
            return;
        }
        if (header[0] != 0x17) return;
        flight->bodies += (static_cast<std::size_t>(header[3]) << 8) | header[4];
        ++flight->records;
    }

    void accept_loop() {
        while (!stop_.load()) {
            pollfd entry{listener_.get(), POLLIN, 0};
            if (::poll(&entry, 1, 50) <= 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            ++accepted_;
            if (mode_ == Mode::stall) {
                stalled_.push_back(fd);
                continue;
            }
            serve(fd);
            ::close(fd);
        }
    }
    void serve(int fd) {
        timeval timeout{};
        timeout.tv_sec = 3;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx_.get()), &SSL_free);
        Flight flight;
        SSL_set_msg_callback(ssl.get(), &LocalTlsServer::on_record);
        SSL_set_msg_callback_arg(ssl.get(), &flight);
        SSL_set_fd(ssl.get(), fd);
        if (SSL_accept(ssl.get()) != 1) return;
        const char* name = SSL_get_servername(ssl.get(), TLSEXT_NAMETYPE_host_name);
        {
            const std::lock_guard lock{mutex_};
            const std::string sni = name ? name : "";
            flights_[sni] = flight.bodies + 5 * (flight.records - 1);
            ++handshakes_[sni];
        }
        // The probe sends close_notify and nothing else.
        std::array<char, 256> buffer{};
        const int got = SSL_read(ssl.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (got <= 0) SSL_shutdown(ssl.get());
    }

    Mode mode_;
    PKey global_key_{nullptr, &EVP_PKEY_free};
    Cert global_cert_{nullptr, &X509_free};
    PKey front_key_{nullptr, &EVP_PKEY_free};
    Cert front_cert_{nullptr, &X509_free};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, &SSL_CTX_free};
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> accepted_{0};
    std::vector<int> stalled_;  // accept thread only, then the destructor
    mutable std::mutex mutex_;
    std::map<std::string, std::size_t> flights_;
    std::map<std::string, std::uint64_t> handshakes_;
    std::thread thread_;
};

// Every automatic masking target dials `port`; the first server-flight probe
// starts at once; any DNS lookup is counted (the override must need none).
struct ProbeScope {
    explicit ProbeScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
        mtdd::detail::MaskingResolveHooks hooks;
        hooks.resolve = [this](const std::string&) -> std::optional<std::string> {
            ++lookups;
            return std::nullopt;
        };
        hooks.probe_delay = 0ms;
        mtdd::detail::set_masking_resolve_hooks_for_test(std::move(hooks));
    }
    ~ProbeScope() {
        mtdd::detail::set_masking_resolve_hooks_for_test(std::nullopt);
        mtdd::detail::set_masking_endpoint_override(std::nullopt);
    }
    ProbeScope(const ProbeScope&) = delete;
    ProbeScope& operator=(const ProbeScope&) = delete;

    std::atomic<std::uint64_t> lookups{0};
};

std::uint16_t closed_port() {
    auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
    if (!listener.ok()) throw std::runtime_error("cannot listen");
    return mtdd::io::local_endpoint(listener.fd.get())->port;  // closed on return
}

// One authenticated FakeTLS hello; the body length of the ApplicationData
// record after ServerHello + CCS, or nullopt.
std::optional<std::size_t> app_data_length(std::uint16_t port, const A16& secret,
                                           std::string_view sni) {
    const int fd = connect_loopback(port);
    if (fd < 0) return std::nullopt;
    const auto ts = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    // A fresh client random each time: a repeated hello would be a replay.
    static std::atomic<unsigned> variant{0};
    const auto hello =
        make_client_hello(secret, ts, sni, static_cast<std::uint8_t>(variant.fetch_add(1)));
    std::optional<std::size_t> out;
    std::array<std::uint8_t, 5> header{};
    if (send_all(fd, hello) &&
        recv_exact(fd, header.data(), header.size(), 2000) && header[0] == 0x16) {
        Bytes rest((static_cast<std::size_t>(header[3]) << 8 | header[4]) + 6);
        std::array<std::uint8_t, 5> app{};
        if (recv_exact(fd, rest.data(), rest.size(), 2000) &&
            recv_exact(fd, app.data(), app.size(), 2000) && app[0] == 0x17) {
            out = static_cast<std::size_t>(app[3]) << 8 | app[4];
        }
    }
    ::close(fd);
    return out;
}

void masking_on(mtdd::Config& config) { config.masking = true; }

// Within kServerFlightJitter of the measured `flight`.
bool near(std::optional<std::size_t> length, std::size_t flight) {
    return length && *length + mtdd::detail::kServerFlightJitter >= flight &&
           *length <= flight + mtdd::detail::kServerFlightJitter;
}

bool in_fallback_range(std::optional<std::size_t> length) {
    return length && *length >= mtdd::protocol::kServerFlightFallbackMin &&
           *length <= mtdd::protocol::kServerFlightFallbackMax;
}

}  // namespace

TEST(ServerHelloProbe, MeasuresTheFlightOfALocalTls13Server) {
    LocalTlsServer server;
    const auto global =
        mtdd::detail::measure_server_flight("127.0.0.1", server.port(), std::string(kDomain), 5s);
    const auto front =
        mtdd::detail::measure_server_flight("127.0.0.1", server.port(), std::string(kFront), 5s);
    ASSERT_TRUE(global.has_value());
    ASSERT_TRUE(front.has_value());
    EXPECT_EQ(global, server.flight_for(kDomain));
    EXPECT_EQ(front, server.flight_for(kFront));
    EXPECT_GT(*front, *global + 500) << "40 extra subjectAltNames";
}

TEST(ServerHelloProbe, UnreachableOrNonTlsTargetsFailFast) {
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(mtdd::detail::measure_server_flight("127.0.0.1", closed_port(),
                                                     std::string(kDomain), 5s));
    LocalTlsServer stalled(LocalTlsServer::Mode::stall);
    EXPECT_FALSE(mtdd::detail::measure_server_flight("127.0.0.1", stalled.port(),
                                                     std::string(kDomain), 300ms));
    std::atomic<bool> cancel{true};
    EXPECT_FALSE(mtdd::detail::measure_server_flight("127.0.0.1", stalled.port(),
                                                     std::string(kDomain), 5s,
                                                     [&] { return cancel.load(); }));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 2s);
}

TEST(ServerHelloProbe, HandshakesCarryTheMeasuredLengthOfTheirUsersDomain) {
    LocalTlsServer server;
    ProbeScope scope(server.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(daemon.services.add_user("bob", std::string(kBobSecretHex)));
    mtdd::control::UpdateUserRequest update;
    update.name = "bob";
    update.policy.tls_domain = std::string(kFront);
    ASSERT_TRUE(daemon.services.store->update_user(update).ok());

    ASSERT_TRUE(wait_for([&] {
        return server.handshakes(kDomain) >= mtdd::detail::kServerFlightSamples &&
               server.handshakes(kFront) >= mtdd::detail::kServerFlightSamples;
    }, 10s)) << "both configured domains are probed";
    const auto global = server.flight_for(kDomain);
    const auto front = server.flight_for(kFront);
    ASSERT_TRUE(global && front);
    ASSERT_NE(*global, *front);

    EXPECT_TRUE(wait_for([&] {
        return near(app_data_length(daemon.port(), secret_bytes(), kDomain), *global);
    }, 5s)) << "alice (global tls_domain) gets " << *global;
    EXPECT_TRUE(wait_for([&] {
        return near(app_data_length(daemon.port(), bob_secret_bytes(), kFront), *front);
    }, 5s)) << "bob (personal tls_domain) gets " << *front;
    // The Ed25519 server answers with one constant length; every hello stays
    // within the jitter of it, and the jitter is used.
    std::set<std::size_t> seen;
    for (int i = 0; i < 30; ++i) {
        const auto length = app_data_length(daemon.port(), secret_bytes(), kDomain);
        ASSERT_TRUE(near(length, *global));
        seen.insert(*length);
    }
    EXPECT_GT(seen.size(), 1U) << "a measured length is jittered, not replayed exactly";
    EXPECT_EQ(scope.lookups.load(), 0U) << "the override needs no DNS";
    EXPECT_EQ(server.server_names(), (std::set<std::string>{std::string(kDomain), std::string(kFront)}));
}

TEST(ServerHelloProbe, StalledProbeBlocksNeitherHandshakesNorShutdown) {
    LocalTlsServer server(LocalTlsServer::Mode::stall);
    ProbeScope scope(server.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return server.accepted() >= 1U; }, 3s)) << "probe in flight";

    for (int i = 0; i < 5; ++i) {
        const auto start = std::chrono::steady_clock::now();
        EXPECT_TRUE(in_fallback_range(app_data_length(daemon.port(), secret_bytes(), kDomain)));
        EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms) << "reactor waited for the probe";
    }
    const auto start = std::chrono::steady_clock::now();
    daemon.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1500ms) << "shutdown waited for the probe";
}

TEST(ServerHelloProbe, UnreachableDomainFallsBackToARandomLength) {
    ProbeScope scope(closed_port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    std::this_thread::sleep_for(300ms);  // the first probe has failed by now

    std::set<std::size_t> seen;
    for (int i = 0; i < 20; ++i) {
        const auto start = std::chrono::steady_clock::now();
        const auto length = app_data_length(daemon.port(), secret_bytes(), kDomain);
        EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms);
        ASSERT_TRUE(in_fallback_range(length));
        seen.insert(*length);
    }
    EXPECT_GT(seen.size(), 1U) << "the fallback is a distribution, not a constant";
}

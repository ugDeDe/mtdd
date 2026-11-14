// JA4 fingerprints of client ClientHellos, for blocking diagnosis: which TLS
// clients authenticate and which fail or probe. The ClientHello is built by
// the Telegram client (or the scanner); the proxy only observes it.
//
// Lazy by design: nothing here runs during admission. A JA4 is computed only
// when it is recorded (the process-wide table, a suspect entry, a watch_ips
// log line) and at most once per connection.
#include "internal.hpp"

namespace mtdd {
namespace {

std::int64_t ja4_unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

const std::string& Runtime::Impl::client_ja4(Client& client,
                                             std::span<const std::uint8_t> record) {
    if (!client.ja4_done) {
        client.ja4_done = true;
        if (auto value = protocol::client_hello_ja4(record)) client.ja4 = std::move(*value);
    }
    return client.ja4;
}

void Runtime::Impl::record_ja4(Client& client, std::span<const std::uint8_t> record,
                               control::Ja4Outcome outcome) {
    auto& table = stats_.ja4();
    const std::int64_t now = ja4_unix_now();
    const bool failed = outcome == control::Ja4Outcome::unauthenticated ||
                        outcome == control::Ja4Outcome::throttled;
    // A failed hello may have cost no HMAC at all (foreign SNI, throttled):
    // fingerprint it only within the per-second budget, unless it is already
    // known (watched connection).
    if (failed && !client.ja4_done && !table.sample_failed(now)) return;
    const std::string& ja4 = client_ja4(client, record);
    if (!ja4.empty()) table.record(ja4, outcome, now);
}

} // namespace mtdd

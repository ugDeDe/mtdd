#include "internal.hpp"
#include "random.hpp"
#include "retry.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace mtdd {

void Runtime::Impl::connect_me(MeConn& me, Time now) {
    if (me.draining) return; // a draining connection never reconnects

    // A keepalive schedule belongs to one TCP connection. Clear it before a new
    // attempt so a stale ping deadline can never fire against a fresh socket.
    if (me.ping_token != 0) deadlines_.erase(me.ping_token);
    me.pending_pings.clear();
    me.unanswered_pings = 0;
    me.rtt_valid = false;
    me.rtt_ema_us = 0;
    if (me.fd.valid()) {
        if (me.armed != 0) set_interest(me.token, me.fd.get(), me.armed, 0);
        me.fd.close();
        me.armed = 0;
    }
    me.session.reset();
    me.frames.clear();
    me.frame_bytes = 0;
    if (me.out) me.out->clear();
    me.remote_close.clear();

    std::vector<MeEndpoint> candidates;
    if (!me_candidates(me.dc, candidates)) {
        me.state = MeConn::State::backoff;
        schedule_me_retry(me, now);
        return;
    }
    me.meta = metadata_snapshot_;
    const MeEndpoint& endpoint = candidates[me.candidate % candidates.size()];
    auto connected = io::connect_tcp(endpoint.host, endpoint.port);
    if (!connected.ok()) {
        if (const auto found = me_pool_.find(me.dc); found != me_pool_.end()) {
            ++found->second.creation_failures_total;
        }
        stats_.me_request(worker_index_, me.dc, control::MeResult::failure);
        ++me.candidate;
        // Refreshes the per-reactor pool gauge and the connected flag in one
        // place (publish_me_pool owns the readiness transition).
        publish_me_pool(me.dc);
        me.state = MeConn::State::backoff;
        schedule_me_retry(me, now);
        recompute_ready();
        return;
    }
    me.fd = std::move(connected.fd);
    // Small MTProto records: Nagle would add avoidable latency. Keepalive
    // detects a half-open ME socket (NAT/peer restart) even when no traffic and
    // no PONG is pending, complementing the application-level ping.
    (void)io::set_tcp_nodelay(me.fd.get());
    (void)io::set_tcp_keepalive(me.fd.get(), 30, 10, 3);
    // A shared ME stream whose frames stay unacknowledged for this long is
    // dead; failing it in ~30 s instead of the ping window (3 x 25 s) lets its
    // clients reconnect to a live writer sooner.
    (void)io::set_tcp_user_timeout(me.fd.get(), detail::kMeUserTimeoutMs);
    me.state = MeConn::State::connecting;
    me.armed = 0;
    update_me_interest(me);
    deadlines_.set(me.token, now + config_.handshake_timeout);
    publish_me_pool(me.dc);
    if (!me.attempted) {
        me.attempted = true;
    } else {
        stats_.me_reconnect(me.dc);
    }
    reaccount(me);
    update_me_interest(me);
}

void Runtime::Impl::on_me_connected(MeConn& me, Time now) {
    if (!me.fd.valid()) {
        fail_me(me, now);
        return;
    }
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(me.fd.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0) {
        fail_me(me, now);
        return;
    }
    const auto local = io::local_endpoint(me.fd.get());
    const auto peer = io::peer_endpoint(me.fd.get());
    if (!local || !peer || local->port == 0 || peer->port == 0) {
        fail_me(me, now);
        return;
    }
    const auto protocol_local = to_protocol_endpoint(*local);
    const auto protocol_server = to_protocol_endpoint(*peer);
    if (!protocol_local || !protocol_server ||
        protocol_local->ipv6 != protocol_server->ipv6) {
        fail_me(me, now);
        return;
    }
    const auto metadata = me.meta ? me.meta : metadata_snapshot_;
    if (!metadata || metadata->secret.empty()) {
        fail_me(me, now);
        return;
    }

    // RPC_PROXY_REQ must advertise the proxy listener, not this ME socket.
    // Telegram's KDF still binds the outbound source port (config.local); the
    // advertised value keeps the outbound source *IP* because that address is
    // what ME/NAT observes, and replaces the port with the listener's.
    const std::uint16_t listener_port = port_public_.load(std::memory_order_relaxed);
    if (listener_port == 0) {
        fail_me(me, now);
        return;
    }
    protocol::Endpoint advertised = *protocol_local;
    advertised.port = listener_port;

    protocol::MiddleEndConfig config;
    config.secret = metadata->secret;
    config.server = *protocol_server;
    config.local = *protocol_local;
    config.advertised = advertised;
    config.ad_tag.bytes = config_.ad_tag;
    config.random = random_;
    config.max_frame =
        std::min<std::size_t>(config_.max_frame_bytes + detail::kMeFrameOverhead,
                              32U * 1024U * 1024U);
    try {
        me.session = std::make_unique<protocol::MiddleEndSession>(
            std::move(config), std::make_unique<MeSink>(this, &me));
        auto nonce = me.session->start();
        if (!push_me_frame(me, std::move(nonce))) {
            fail_me(me, now);
            return;
        }
    } catch (const std::exception&) {
        fail_me(me, now);
        return;
    }
    me.state = MeConn::State::handshaking;
    deadlines_.set(me.token, now + config_.handshake_timeout);
    update_me_interest(me);
    reaccount(me);
}

void Runtime::Impl::schedule_me_retry(MeConn& me, Time now) {
    me.attempt = detail::next_me_retry_attempt(me.attempt);
    const auto delay = detail::me_retry_delay(me.attempt, detail::random_u32(random_));
    me.next_attempt = now + delay;
    deadlines_.set(me.token, me.next_attempt);
    update_me_interest(me);
}

void Runtime::Impl::defer_me_failure(MeConn& me) {
    if (me.failure_deferred) return;
    me.failure_deferred = true;
    // The token is the stable identity. Token 0 (a synthetic MeConn in a unit
    // test) is simply absent from me_by_token_ and skipped by the processor.
    deferred_me_failures_.push_back(me.token);
}

void Runtime::Impl::fail_me(MeConn& me, Time now) {
    if (me.state == MeConn::State::backoff) return; // already waiting to retry
    if (me.state == MeConn::State::connecting || me.state == MeConn::State::handshaking) {
        if (const auto found = me_pool_.find(me.dc); found != me_pool_.end()) {
            ++found->second.creation_failures_total;
        }
    }
    me.state = MeConn::State::backoff;
    if (me.ping_token != 0) deadlines_.erase(me.ping_token);
    me.pending_pings.clear();
    me.unanswered_pings = 0;
    // Control mirrors fold on every failure (a retried connection must not
    // republish them). Socket bytes stay on the object: it keeps its pool slot
    // across retries, so they are folded once, when the connection is retired.
    fold_me_control(me);
    close_me_clients(me);
    // Every client attached to this connection is gone; drop their queue tokens
    // now instead of walking potentially thousands of stale entries later.
    me.ready_clients.clear();
    me.queued_clients = 0;
    publish_me_queue(me);

    if (me.fd.valid()) {
        if (me.armed != 0) set_interest(me.token, me.fd.get(), me.armed, 0);
        me.fd.close();
    }
    me.armed = 0;
    me.session.reset();
    me.frames.clear();
    me.frame_bytes = 0;
    if (me.out) me.out->clear();
    me.remote_close.clear();
    publish_me_pool(me.dc);
    if (me.draining) {
        // Metadata replacement already moved new clients to a replacement
        // connection. A failed draining connection is retired by reap_me_pool
        // (zero clients after close_me_clients) and must never reconnect.
        deadlines_.erase(me.token);
        me.next_attempt = Time::max();
        reaccount(me);
        return;
    }
    ++me.candidate;
    schedule_me_retry(me, now);
    recompute_ready();
    reaccount(me);
}

void Runtime::Impl::close_me_clients(MeConn& me) {
    std::vector<std::uint64_t> closing;
    for (const auto& [token, client] : clients_) {
        if (client->me == &me) closing.push_back(token);
    }
    for (const std::uint64_t token : closing) close_client(token, control::RelayCloseReason::me_lost);
}

void Runtime::Impl::shutdown_me(MeConn& me) {
    fold_me_counters(me);
    if (me.ping_token != 0) {
        deadlines_.erase(me.ping_token);
        remove_target(me.ping_token);
        me.ping_token = 0;
    }
    me.pending_pings.clear();
    me.unanswered_pings = 0;
    if (me.fd.valid()) {
        if (me.armed != 0) set_interest(me.token, me.fd.get(), me.armed, 0);
        me.fd.close();
    }
    me.armed = 0;
    me.session.reset();
    me.frames.clear();
    me.frame_bytes = 0;
    if (me.out) me.out->clear();
    me.remote_close.clear();
    me.ready_clients.clear();
    me.queued_clients = 0;
    publish_me_queue(me);
    deadlines_.erase(me.token);
    remove_target(me.token);
    if (const auto found = me_by_token_.find(me.token);
        found != me_by_token_.end() && found->second == &me) {
        me_by_token_.erase(found);
    }
    forget_accounting(me.accounted);
    me.accounted = 0;
}

void Runtime::Impl::handle_me(MeConn& me, std::uint32_t events, Time now) {
    if ((events & EPOLLERR) != 0) {
        fail_me(me, now);
        return;
    }
    if (me.state == MeConn::State::connecting) {
        if ((events & (EPOLLOUT | EPOLLHUP)) != 0) on_me_connected(me, now);
        return;
    }
    if ((events & (EPOLLHUP | EPOLLRDHUP)) != 0) {
        if (me.state == MeConn::State::handshaking || me.state == MeConn::State::ready) {
            // A FIN only says no more bytes will arrive. Read what is already
            // queued first (read_me calls fail_me itself on recv()==0); failing
            // immediately would discard the readable tail of a frame.
            const std::uint64_t rx_before = me.rx_bytes;
            read_me(me, now);
            if (me.state == MeConn::State::handshaking || me.state == MeConn::State::ready) {
                // One read event consumes at most kReadBatch. A larger tail is
                // not drained yet, and EPOLLIN/EPOLLRDHUP are level-triggered,
                // so the next event continues the drain and the eventual
                // recv()==0 fails the session from inside read_me.
                // Two cases must not wait for that event:
                //   * EPOLLHUP, which is reported even when absent from the
                //     interest mask, so waiting would leave the connection open
                //     with an unread tail;
                //   * budget_paused, where EPOLLIN is disarmed and no read will
                //     ever happen, so waiting would only spin.
                const bool batch_exhausted =
                    (me.rx_bytes - rx_before) >= detail::kReadBatch;
                if (batch_exhausted && !me.budget_paused && (events & EPOLLHUP) == 0) return;
                fail_me(me, now);
            }
        }
        return;
    }
    if (me.state == MeConn::State::backoff) return;
    if ((events & EPOLLIN) != 0) {
        read_me(me, now);
        if (me.state != MeConn::State::handshaking && me.state != MeConn::State::ready) return;
    }
    if ((events & EPOLLOUT) != 0) {
        pump_me_out(me);
        if (me.state == MeConn::State::ready) pump_me_ready_queue(me, now);
    }
}

void Runtime::Impl::read_me(MeConn& me, Time now) {
    if (!me.session || !me.fd.valid()) return;
    // Answers decoded below are coalesced per client; write them on every exit
    // path, including a failure of this ME connection.
    struct S2cFlush {
        Impl& impl;
        ~S2cFlush() {
            try {
                impl.flush_s2c_batches();
            } catch (...) {
            }
        }
    } s2c_flush{*this};
    std::size_t total = 0;
    bool became_ready = false;
    while (total < detail::kReadBatch) {
        const std::size_t limit = detail::kReadBatch - total;
        // ME reassembly buffers (ciphertext/plaintext residue) are charged to
        // the global relay budget only after feed(); admit the worst-case
        // growth of this batch plus the shared headroom before touching the
        // socket. Without this an incomplete frame could grow past the hard
        // envelope. Pausing is preferable to failing the shared session.
        if (!budget_allows(limit + detail::kBudgetHeadroom / 2)) {
            // Count only the false -> true transition: level-triggered retries
            // never reach here while paused, and a per-read counter would turn
            // an exhausted worker into a high-rate counter stream.
            if (!me.budget_paused) {
                me.budget_paused = true;
                me.budget_paused_at = now;
                ++me.budget_pauses;
            }
            break;
        }
        const ssize_t received = ::recv(me.fd.get(), read_buffer_.data(), limit, MSG_DONTWAIT);
        if (received > 0) {
            total += static_cast<std::size_t>(received);
            // Charge the bytes as soon as they leave the socket. Every early
            // return below (recv()==0, protocol error, staging failure) must
            // still leave rx_bytes equal to what was actually read; accounting
            // only after the loop silently dropped the current batch.
            me.rx_bytes += static_cast<std::uint64_t>(received);
            to_me_buffer_.clear();
            const auto status = me.session->feed(
                std::span<const std::uint8_t>(read_buffer_).first(static_cast<std::size_t>(received)),
                to_me_buffer_);
            if (!to_me_buffer_.empty() && !push_me_bytes(me, to_me_buffer_)) {
                fail_me(me, now);
                return;
            }
            if (status == protocol::Status::ProtocolError || status == protocol::Status::Closed) {
                stats_.me_request(worker_index_, me.dc, control::MeResult::failure);
                fail_me(me, now);
                return;
            }
            if (me.state == MeConn::State::handshaking &&
                me.session->state() == protocol::MiddleEndSession::State::Ready) {
                became_ready = true;
            }
            // Short read: the socket is drained; the level-triggered EPOLLIN
            // reports further data, so skip the EAGAIN-only recv.
            if (static_cast<std::size_t>(received) < limit) break;
        } else if (received == 0) {
            fail_me(me, now);
            return;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            fail_me(me, now);
            return;
        }
    }
    detail::trim_buffer(to_me_buffer_);
    if (me.session && total != 0) {
        // Publish inbound control-constructor counts so a live node can be
        // classified from metrics instead of guessing which close Telegram uses.
        // The connection keeps its own mirror; the DC gauge sums the mirrors of
        // the live connections plus the base folded from replaced ones.
        const auto& control = me.session->control_counters();
        if (control.close_conn != me.control_close_conn ||
            control.close_ext != me.control_close_ext ||
            control.unknown != me.control_unknown ||
            control.malformed != me.control_malformed) {
            me.control_close_conn = control.close_conn;
            me.control_close_ext = control.close_ext;
            me.control_unknown = control.unknown;
            me.control_malformed = control.malformed;
            // publish_me_control() republishes the cumulative DC aggregate into
            // this reactor's statistics slot.
            publish_me_control(me.dc);
        }
    }
    reaccount_shared();
    reaccount(me);
    if (became_ready) on_me_ready(me, now);
    // Orphan-answer feedback is queued from the decoder callback and encoded
    // only here, after feed() has returned, so the sink never re-enters the
    // shared session that is currently dispatching its callbacks.
    if (me.state == MeConn::State::ready) flush_remote_closes(me);
    if (me.state == MeConn::State::ready) pump_me_ready_queue(me, now);
    update_me_interest(me);
}

void Runtime::Impl::queue_remote_close(MeConn& me, const detail::ConnId& id) {
    if (me.state != MeConn::State::ready || !me.session || !me.session->ready()) return;
    // Pure bookkeeping: safe to call from a decoder callback. Ownership was
    // already validated by the caller (no live client for this id on this ME).
    me.remote_close.request(id, Clock::now());
}

void Runtime::Impl::flush_remote_closes(MeConn& me) {
    if (me.state != MeConn::State::ready || !me.session || !me.session->ready()) {
        me.remote_close.clear();
        return;
    }
    if (me.remote_close.pending_size() == 0) return;
    // RPC_CLOSE_CONN payload is 4 (type) + 8 (conn id) = 12 bytes. With the
    // 8-byte frame header, 4-byte CRC and CBC padding to 16, the encoded frame
    // is exactly 32 bytes. Admitting that size BEFORE encode_close() is what
    // keeps write_seq/CBC atomic: encode_close advances both while encoding.
    std::vector<detail::ConnId> pending;
    me.remote_close.consume(pending);
    for (const auto& id : pending) {
        if (me.frame_bytes + detail::kEncodedCloseFrameBytes > me_frame_capacity()) {
            // No capacity: drop the optional feedback before touching seq/CBC.
            return;
        }
        std::vector<std::uint8_t> frame;
        try {
            if (me.session->encode_close(id, frame) != protocol::Status::Ok) continue;
        } catch (const std::exception&) {
            // seq/CBC may already have advanced; the shared session cannot be
            // kept alive with a gap.
            defer_me_failure(me);
            return;
        }
        // Any post-encode loss also desynchronises seq/CBC: fail the session
        // instead of dropping the frame and continuing.
        if (detail::consume_remote_close_push_failure_for_test() ||
            !push_me_frame(me, std::move(frame))) {
            defer_me_failure(me);
            return;
        }
    }
}

} // namespace mtdd

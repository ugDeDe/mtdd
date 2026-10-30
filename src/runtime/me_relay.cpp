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

void Runtime::Impl::on_me_ready(MeConn& me, Time now) {
    if (me.state == MeConn::State::ready) return;
    me.state = MeConn::State::ready;
    me.candidate = 0;
    me.attempt = 0;
    deadlines_.erase(me.token);
    // Successor-first replacement: publish this generation as the serving one
    // BEFORE any victim starts draining. Readiness and client routing therefore
    // never observe a gap: the previous generation keeps taking clients and
    // counting for /v1/ready until this very moment.
    if (!me.draining) {
        if (const auto found = me_pool_.find(me.dc); found != me_pool_.end()) {
            DcPool& pool = found->second;
            if (me.generation > pool.serving_generation) {
                pool.serving_generation = me.generation;
            }
            if (me.generation < pool.serving_generation) {
                // A superseded generation must never become the serving one.
                me.draining = true;
                me.draining_deadline = now + detail::me_drain_deadline();
            } else {
                drain_me_generations_below(pool, pool.serving_generation, now);
            }
        }
    }
    publish_me_pool(me.dc);
    for (const auto& [token, client] : clients_) {
        if (client->me != &me) continue;
        if (client->deadline_kind == Client::DeadlineKind::wait_me) {
            client->deadline_kind = Client::DeadlineKind::idle;
            deadlines_.set(token, client->last_activity + config_.idle_timeout);
        }
    }
    recompute_ready();
    pump_me_out(me);
    pump_me_ready_queue(me, now);
    update_me_interest(me);
    // Start a fresh keepalive window for this TCP connection.
    me.pending_pings.clear();
    me.unanswered_pings = 0;
    schedule_me_ping(me, now);
}

bool Runtime::Impl::push_me_bytes(MeConn& me, std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return true;
    try {
        std::vector<std::uint8_t> frame(bytes.begin(), bytes.end());
        return push_me_frame(me, std::move(frame));
    } catch (const std::bad_alloc&) {
        // Same treatment as a full writer: this ME connection cannot accept the
        // frame, but the reactor itself must not see an exception.
        return false;
    }
}

bool Runtime::Impl::push_me_frame(MeConn& me, std::vector<std::uint8_t>&& frame) {
    if (frame.empty()) return true;
    if (me.frame_bytes + frame.size() > me_frame_capacity()) return false;
    const std::size_t size = frame.size();
    // Stage first, then charge: a bad_alloc from the deque must surface as an
    // admission failure of this ME connection (the caller defers a failure or
    // fails the session), never as an exception escaping into run().
    try {
        me.frames.push_back(StagedFrame{std::move(frame), 0});
    } catch (const std::bad_alloc&) {
        return false;
    }
    me.frame_bytes += size;
    reaccount(me);
    pump_me_out(me);
    return true;
}

void Runtime::Impl::pump_me_out(MeConn& me) {
    if (!me.out) return;
    while (!me.frames.empty()) {
        StagedFrame& frame = me.frames.front();
        const std::size_t space = me.out->max_bytes() - me.out->bytes();
        if (space == 0) break;
        const std::size_t remaining = frame.bytes.size() - frame.offset;
        const std::size_t take = std::min(space, remaining);
        const auto status = me.out->append(
            std::span<const std::uint8_t>(frame.bytes).subspan(frame.offset, take));
        if (status != io::AppendStatus::ok) {
            if (status == io::AppendStatus::allocation_failure) defer_me_failure(me);
            return;
        }
        frame.offset += take;
        if (frame.offset == frame.bytes.size()) {
            me.frame_bytes -= frame.bytes.size();
            me.frames.pop_front();
        } else {
            break;
        }
    }
    if (me.fd.valid() && !me.out->empty()) {
        const auto result = me.out->flush_to(me.fd.get(), detail::kWriteBatch);
        if (result.status == io::FlushStatus::error) {
            defer_me_failure(me);
            return;
        }
        me.tx_bytes += result.bytes_written;
    }
    reaccount(me);
    update_me_interest(me);
}

void Runtime::Impl::publish_me_queue(MeConn& me) {
    // The public gauges are per signed DC, so aggregate every connection in
    // this reactor's pool. A MeConn created directly by a unit test (absent
    // from the pool) is reported on its own so the audit tests keep their old
    // semantics. snapshot() sums the reactors, so the DC total is the sum of
    // the per-reactor pool aggregates.
    std::uint64_t depth = 0;
    std::uint64_t clients = 0;
    std::uint64_t frames = 0;
    std::uint64_t out_bytes = 0;
    bool pooled = false;
    if (const auto found = me_pool_.find(me.dc); found != me_pool_.end()) {
        for (const auto& connection : found->second.conns) {
            if (!connection) continue;
            pooled = true;
            depth += static_cast<std::uint64_t>(connection->ready_clients.size());
            clients += static_cast<std::uint64_t>(connection->queued_clients);
            frames += static_cast<std::uint64_t>(connection->frame_bytes);
            if (connection->out) {
                out_bytes += static_cast<std::uint64_t>(connection->out->bytes());
            }
        }
    }
    if (!pooled) {
        depth = static_cast<std::uint64_t>(me.ready_clients.size());
        clients = static_cast<std::uint64_t>(me.queued_clients);
        frames = static_cast<std::uint64_t>(me.frame_bytes);
        out_bytes = me.out ? static_cast<std::uint64_t>(me.out->bytes()) : 0;
    }
    stats_.me_queue(worker_index_, me.dc, depth, clients, frames, out_bytes);
}

void Runtime::Impl::pump_me_ready_queue(MeConn& me, Time now) {
    if (me.state != MeConn::State::ready || !me.session) return;
    std::size_t processed = 0;
    while (!me.ready_clients.empty() && processed < detail::kMeReadyBatch) {
        const std::uint64_t token = me.ready_clients.front();
        me.ready_clients.pop_front();
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue; // closed client: lazy drop
        Client& client = *found->second;
        if (client.me != &me) {
            // A live client can only be a member of its own signed-DC queue.
            // Never touch its flag here: its owning queue still owns it.
            continue;
        }
        if (client.in_me_queue) {
            client.in_me_queue = false;
            if (me.queued_clients > 0) --me.queued_clients;
        }
        pump_c2s(client, now);
        if (clients_.find(token) == clients_.end()) continue;
        // Exactly one re-enqueue, through the single owner. No second push.
        enqueue_ready(client);
        ++processed;
        if (me.failure_deferred) break;
        if (!me.frames.empty()) break;
        if (me.out && me.out->bytes() >= me.out->max_bytes()) break;
    }
    publish_me_queue(me);
    arm_me_ready_wake(me, now);
}

void Runtime::Impl::arm_me_ready_wake(MeConn& me, Time now) {
    if (me.state != MeConn::State::ready || !me.session || me.failure_deferred) return;
    if (me.ready_clients.empty()) return;
    // While a frame is staged or the output queue is full, EPOLLOUT is the
    // readiness source: arming a timer here would poll a non-writable socket
    // and burn CPU. Wake only when the writer can actually make progress.
    if (!me.frames.empty()) return;
    if (me.out && me.out->bytes() >= me.out->max_bytes()) return;
    deadlines_.set(me.token, now + detail::kMeReadyWakeDelay);
}

void Runtime::Impl::schedule_me_ping(MeConn& me, Time now) {
    if (me.ping_token == 0 || me.state != MeConn::State::ready) return;
    const auto interval = std::max<std::int64_t>(ping_tuning_.interval.count(), 1);
    const auto jitter = std::max<std::int64_t>(ping_tuning_.jitter.count(), 0);
    std::int64_t offset = 0;
    if (jitter != 0) {
        // 64-bit modulus: a test hook may pass a jitter above 2^31 and must not
        // be truncated into a smaller window than requested.
        const std::uint64_t span = static_cast<std::uint64_t>(2 * jitter) + 1ULL;
        offset = static_cast<std::int64_t>(static_cast<std::uint64_t>(detail::random_u32(random_)) % span) -
                 jitter;
    }
    const auto delay = std::max<std::int64_t>(interval + offset, 1);
    deadlines_.set(me.ping_token, now + std::chrono::milliseconds{delay});
}

void Runtime::Impl::on_me_ping_deadline(MeConn& me, Time now) {
    if (me.state != MeConn::State::ready || !me.session || !me.session->ready()) {
        // L1: the deadline token is single-shot. Re-arming (instead of dropping
        // the wake) keeps keepalive alive for a connection whose session is
        // still converging instead of losing the ping forever.
        if (me.ping_token != 0 && me.state == MeConn::State::ready) {
            deadlines_.set(me.ping_token, now + detail::kPingBusyRetry);
        }
        return;
    }
    if (me.unanswered_pings >= std::max<std::size_t>(ping_tuning_.max_unanswered, 1)) {
        if (me.budget_paused) {
            // Inbound silence is self-inflicted: EPOLLIN is disarmed by the
            // buffer budget, so the peer's PONG could not have been read. Failing
            // the shared session here would drop every client bound to it for a
            // local resource shortage. Restart the window; it is judged again
            // once reads resume.
            me.unanswered_pings = 0;
            me.pending_pings.clear();
            me.ping_window_rx = me.rx_bytes;
            schedule_me_ping(me, now);
            return;
        }
        if (me.rx_bytes != me.ping_window_rx) {
            // The peer kept sending inbound traffic during the whole window:
            // it is alive even though it ignored or delayed PONG. A missing
            // PONG alone is a metric, never a reason to close live clients.
            stats_.me_ping_stall(me.dc);
            me.unanswered_pings = 0;
            me.pending_pings.clear();
            me.ping_window_rx = me.rx_bytes;
            schedule_me_ping(me, now);
            return;
        }
        // Not a single inbound byte over K ping intervals: the connection is
        // dead. Its clients cannot receive anything either, so failing it is the
        // honest outcome; the reason is visible as ping_timeouts_total.
        stats_.me_ping_timeout(me.dc);
        fail_me(me, now);
        return;
    }
    send_me_ping(me, now);
}

void Runtime::Impl::send_me_ping(MeConn& me, Time now) {
    if (me.state != MeConn::State::ready || !me.session || !me.session->ready()) return;
    // Never encode a ping that cannot be staged: encode_ping advances
    // write_seq/CBC, so a rejected frame would desynchronise the shared stream.
    const bool writer_full =
        me.frame_bytes + detail::kEncodedPingFrameBytes > me_frame_capacity() ||
        (me.out && me.out->bytes() >= me.out->max_bytes());
    if (writer_full) {
        // Retry shortly instead of polling aggressively while the writer drains.
        deadlines_.set(me.ping_token, now + detail::kPingBusyRetry);
        return;
    }
    std::vector<std::uint8_t> frame;
    try {
        if (me.session->encode_ping(me.next_ping_id, frame) != protocol::Status::Ok) {
            if (me.session->state() == protocol::MiddleEndSession::State::Failed) {
                defer_me_failure(me);
            }
            return;
        }
    } catch (const std::exception&) {
        defer_me_failure(me);
        return;
    }
    // Pre-admission above makes this failure only possible after state has
    // advanced, so it must fail the whole shared session rather than be dropped.
    if (!push_me_frame(me, std::move(frame))) {
        defer_me_failure(me);
        return;
    }
    if (me.unanswered_pings == 0) {
        // A new liveness window starts here: remember how many inbound bytes
        // this connection had seen so far.
        me.ping_window_rx = me.rx_bytes;
    }
    me.pending_pings.emplace_back(me.next_ping_id, now);
    ++me.next_ping_id;
    ++me.unanswered_pings;
    stats_.me_ping_sent(me.dc);
    schedule_me_ping(me, now);
}

void Runtime::Impl::handle_me_pong(MeConn& me, std::int64_t ping_id, Time now) {
    if (me.pending_pings.empty()) return;
    // Ping ids are monotonically increasing. A PONG for id N also proves that
    // the peer processed every earlier ping, so drop the whole prefix.
    bool matched = false;
    double sample_us = 0.0;
    while (!me.pending_pings.empty() && me.pending_pings.front().first <= ping_id) {
        const auto [id, sent] = me.pending_pings.front();
        me.pending_pings.pop_front();
        if (id == ping_id) {
            matched = true;
            sample_us = std::chrono::duration<double, std::micro>(now - sent).count();
        }
    }
    if (!matched) return;
    me.unanswered_pings = 0;
    me.rtt_last_us = static_cast<std::uint64_t>(sample_us < 0.0 ? 0.0 : sample_us);
    if (!me.rtt_valid) {
        me.rtt_valid = true;
        me.rtt_ema_us = sample_us;
    } else {
        me.rtt_ema_us = (me.rtt_ema_us * 7.0 + sample_us) / 8.0;
    }
    const auto rtt_us = static_cast<std::uint64_t>(me.rtt_ema_us < 0.0 ? 0.0 : me.rtt_ema_us);
    stats_.me_ping_pong(me.dc, rtt_us);
    // The DC gauge is the aggregate of the ready pool members, not the last
    // connection that happened to answer.
    publish_me_rtt(me.dc);
}

void Runtime::Impl::deliver_payload(MeConn& me, const detail::ConnId& id,
                                    std::span<const std::uint8_t> payload, Time now) {
    ++me.ans_received;
    me.unanswered_since = Time{};
    me.last_answer_at = now;
    me.answer_seen = true;
    stats_.me_answer(worker_index_, me.dc, control::MeAnswerResult::received);
    if (!me.session || !me.session->ready()) {
        ++me.ans_dropped_other;
        stats_.me_answer(worker_index_, me.dc, control::MeAnswerResult::dropped_other);
        return;
    }
    const auto found = clients_by_conn_.find(id);
    if (found == clients_by_conn_.end()) {
        ++me.ans_dropped_unknown;
        stats_.me_answer(worker_index_, me.dc, control::MeAnswerResult::dropped_unknown);
        // The conn id is unknown to this proxy, so the remote mapping is
        // orphaned: release it with a bounded RPC_CLOSE_CONN (queued, flushed
        // after the decoder callback returns).
        queue_remote_close(me, id);
        return;
    }
    const auto client_found = clients_.find(found->second);
    if (client_found == clients_.end()) {
        ++me.ans_dropped_unknown;
        stats_.me_answer(worker_index_, me.dc, control::MeAnswerResult::dropped_unknown);
        queue_remote_close(me, id);
        return;
    }
    Client& client = *client_found->second;
    if (client.me != &me || client.phase != Client::Phase::relay || !client.tls ||
        client.close_requested) {
        // A live id owned by another writer (or already closing locally) must
        // never be closed through this ME connection.
        ++me.ans_dropped_other;
        stats_.me_answer(worker_index_, me.dc, control::MeAnswerResult::dropped_other);
        return;
    }

    // Cheap admission check before allocating the transient framed wire copy.
    const std::size_t required = payload.size() * 2 + 64U * 1024U;
    if (!budget_allows(required)) {
        stats_.add_backpressure(control::Direction::server_to_client);
        note_close(client, control::RelayCloseReason::backpressure);
        defer_close(client.token);
        return;
    }
    try {
        // Fused transport framing + TLS record encoding: the intermediate
        // transport header/padding is written directly into the TLS record body
        // (byte-identical wire for the same random stream), so no separate
        // frame buffer and no second full-payload copy are needed.
        // Answers decoded in the same ME read are appended to one open TLS
        // record per client and written once by flush_s2c_batches().
        if (client.tls->send_transport_message(client.tls->proto_tag(), payload,
                                               client.s2c_batch, random_,
                                               &client.s2c_open_record) !=
            protocol::Status::Ok) {
            defer_close(client.token);
            return;
        }
        if (!client.in_s2c_batch) {
            client.in_s2c_batch = true;
            s2c_batch_tokens_.push_back(client.token);
        }
        if (client.s2c_batch.size() >= detail::kS2cBatchFlushBytes &&
            !finish_s2c_batch(client, false)) {
            return;
        }
    } catch (const std::bad_alloc&) {
        // R4: allocation/framing failure for ONE logical client must not tear
        // down the shared DC. Close that conn id and let the session continue.
        defer_close(client.token);
        detail::trim_scratch(wire_buffer_);
        reaccount_shared();
        return;
    } catch (const std::exception&) {
        // A malformed payload rejected by the shared framing layer is a
        // session-level protocol fault, not a per-client failure.
        defer_me_failure(me);
        detail::trim_scratch(wire_buffer_);
        reaccount_shared();
        return;
    } catch (...) {
        defer_me_failure(me);
        detail::trim_scratch(wire_buffer_);
        reaccount_shared();
        return;
    }
    client.metrics->add_payload(control::Direction::server_to_client, payload.size());
    media_account(client, payload.size(), now);
    client.awaiting_reply = false;
    ++me.ans_delivered;
    stats_.me_answer(worker_index_, me.dc, control::MeAnswerResult::delivered);
}

void Runtime::Impl::deliver_quick_ack(MeConn& me, const detail::ConnId& id,
                                      std::array<std::uint8_t, 4> confirm, Time now) {
    me.unanswered_since = Time{};
    (void)now;
    if (!me.session || !me.session->ready()) return;
    const auto found = clients_by_conn_.find(id);
    if (found == clients_by_conn_.end()) {
        queue_remote_close(me, id);
        return;
    }
    const auto client_found = clients_.find(found->second);
    if (client_found == clients_.end()) {
        queue_remote_close(me, id);
        return;
    }
    Client& client = *client_found->second;
    if (client.me != &me || client.phase != Client::Phase::relay || !client.tls ||
        client.close_requested) {
        // Ownership mismatch: never close another writer's logical connection.
        return;
    }
    try {
        frame_buffer_.clear();
        protocol::encode_quick_ack(client.tls->proto_tag(), confirm, frame_buffer_);
        // Same ordered stream as payload answers of this ME read.
        if (client.tls->send(frame_buffer_, client.s2c_batch, &client.s2c_open_record) !=
            protocol::Status::Ok) {
            defer_close(client.token);
            detail::trim_scratch(frame_buffer_);
            return;
        }
        if (!client.in_s2c_batch) {
            client.in_s2c_batch = true;
            s2c_batch_tokens_.push_back(client.token);
        }
    } catch (const std::bad_alloc&) {
        defer_close(client.token);
    } catch (const std::exception&) {
        defer_me_failure(me);
    } catch (...) {
        defer_me_failure(me);
    }
    detail::trim_scratch(frame_buffer_);
}

void Runtime::Impl::MeSink::on_proxy_payload(const detail::ConnId& id,
                                             std::span<const std::uint8_t> payload) {
    try {
        impl->deliver_payload(*me, id, payload, Clock::now());
    } catch (const std::bad_alloc&) {
        impl->defer_close_conn(id);
    } catch (...) {
        impl->defer_me_failure(*me);
    }
}

void Runtime::Impl::MeSink::on_quick_ack(const detail::ConnId& id,
                                         std::array<std::uint8_t, 4> confirm) {
    try {
        impl->deliver_quick_ack(*me, id, confirm, Clock::now());
    } catch (const std::bad_alloc&) {
        impl->defer_close_conn(id);
    } catch (...) {
        impl->defer_me_failure(*me);
    }
}

void Runtime::Impl::MeSink::on_remote_close(const detail::ConnId& id) {
    try {
        const auto found = impl->clients_by_conn_.find(id);
        if (found == impl->clients_by_conn_.end()) return;
        const auto client = impl->clients_.find(found->second);
        if (client != impl->clients_.end()) {
            note_close(*client->second, control::RelayCloseReason::remote_close);
        }
        impl->defer_close(found->second);
    } catch (...) {
    }
}

void Runtime::Impl::MeSink::on_pong(std::int64_t ping_id) {
    // Pure bookkeeping (deque + atomics); no allocation and no re-entry into the
    // shared session. A failure here cannot invalidate the transport.
    impl->handle_me_pong(*me, ping_id, Clock::now());
}

} // namespace mtdd

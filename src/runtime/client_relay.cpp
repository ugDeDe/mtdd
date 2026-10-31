#include "internal.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mtdd {

void Runtime::Impl::attach_to_me(Client& client, MeConn& me) {
    detail::ConnId id{};
    bool unique = false;
    for (int attempt = 0; attempt < 8 && !unique; ++attempt) {
        random_(id);
        unique = clients_by_conn_.find(id) == clients_by_conn_.end();
    }
    if (!unique) {
        // Deterministic fallback with a per-process counter, still checked for
        // collision. Random collisions are already astronomically unlikely.
        std::uint64_t counter = next_token_;
        ++next_token_;
        for (std::size_t i = 0; i < id.size(); ++i) {
            id[i] = static_cast<std::uint8_t>(counter >> (8 * (7 - i)));
        }
        while (clients_by_conn_.find(id) != clients_by_conn_.end()) {
            ++counter;
            for (std::size_t i = 0; i < id.size(); ++i) {
                id[i] = static_cast<std::uint8_t>(counter >> (8 * (7 - i)));
            }
        }
    }
    client.conn_id = id;
    clients_by_conn_.emplace(id, client.token);
    client.conn_registered = true;
    client.me = &me;
    ++me.clients;
    client.deadline_kind = Client::DeadlineKind::idle;
    deadlines_.set(client.token, client.last_activity + config_.idle_timeout);
}

bool Runtime::Impl::client_wants_write(const Client& client) const noexcept {
    if (client.s2c_offset < client.s2c_wire.size()) return true;
    return client.out && !client.out->empty();
}

bool Runtime::Impl::push_client_wire(Client& client, std::span<const std::uint8_t> wire,
                                     bool rearm_interest) {
    if (wire.empty()) return true;
    if (!client.out) return false;
    const std::size_t staged = client.s2c_wire.size() - client.s2c_offset;
    const std::size_t cap_limit =
        std::max(config_.connection_queue_bytes, config_.max_frame_bytes + 4096);
    if (staged + wire.size() > cap_limit) return false;

    if (staged == 0) {
        const std::size_t space = client.out->max_bytes() - client.out->bytes();
        std::size_t taken = 0;
        if (space > 0) {
            taken = std::min(space, wire.size());
            const auto status = client.out->append(wire.first(taken));
            if (status == io::AppendStatus::allocation_failure) return false;
            if (status != io::AppendStatus::ok) taken = 0;
        }
        if (taken < wire.size()) {
            client.s2c_wire.assign(wire.begin() + static_cast<std::ptrdiff_t>(taken),
                                   wire.end());
            client.s2c_offset = 0;
        }
    } else {
        // Drop the prefix already copied into `out` before appending, so the
        // retained wire stays bounded by logically pending bytes instead of
        // growing with every insert.
        if (client.s2c_offset > 0) {
            client.s2c_wire.erase(
                client.s2c_wire.begin(),
                client.s2c_wire.begin() + static_cast<std::ptrdiff_t>(client.s2c_offset));
            client.s2c_offset = 0;
        }
        client.s2c_wire.insert(client.s2c_wire.end(), wire.begin(), wire.end());
    }
    reaccount(client);
    if (rearm_interest) update_client_interest(client);
    return true;
}

void Runtime::Impl::pump_client_out(Client& client) {
    if (!client.out) return;
    while (client.s2c_offset < client.s2c_wire.size()) {
        const std::size_t space = client.out->max_bytes() - client.out->bytes();
        if (space == 0) break;
        const std::size_t remaining = client.s2c_wire.size() - client.s2c_offset;
        const std::size_t take = std::min(space, remaining);
        const auto status =
            client.out->append(std::span<const std::uint8_t>(client.s2c_wire)
                                   .subspan(client.s2c_offset, take));
        if (status != io::AppendStatus::ok) {
            if (status == io::AppendStatus::allocation_failure) {
                close_client(client.token);
            }
            return;
        }
        client.s2c_offset += take;
    }
    if (client.s2c_offset == client.s2c_wire.size()) {
        if (client.s2c_wire.capacity() != 0) {
            if (client.s2c_wire.capacity() > detail::kIdleRetainedBytes) {
                std::vector<std::uint8_t>().swap(client.s2c_wire);
            } else {
                client.s2c_wire.clear();
            }
        }
        client.s2c_offset = 0;
    }
    if (!client.out->empty()) {
        const auto result = client.out->flush_to(client.fd.get(), detail::kWriteBatch);
        if (result.status == io::FlushStatus::error) {
            close_client(client.token, result.error == ETIMEDOUT
                                           ? control::RelayCloseReason::client_timeout
                                           : control::RelayCloseReason::client_error);
            return;
        }
        if (result.bytes_written > 0) touch(client, Clock::now());
    }
    reaccount(client);
    update_client_interest(client);
}

bool Runtime::Impl::finish_s2c_batch(Client& client, bool write_now) {
    // A mid-read hand-off keeps the client listed so the end-of-read flush
    // still writes what was queued here.
    if (write_now) client.in_s2c_batch = false;
    client.s2c_open_record = protocol::FakeTlsConnection::kNoOpenRecord;
    const std::uint64_t token = client.token;
    if (!client.s2c_batch.empty()) {
        const auto release = [&client] {
            // Small batches keep their block for the next read; a large media
            // batch returns its memory instead of pinning it per idle client.
            if (client.s2c_batch.capacity() > 4096U) {
                std::vector<std::uint8_t>().swap(client.s2c_batch);
            } else {
                client.s2c_batch.clear();
            }
        };
        if (client.close_requested || !client.out) {
            release();
            reaccount(client);
            return false;
        }
        std::span<const std::uint8_t> pending(client.s2c_batch);
        if (write_now && client.out->empty() && client.s2c_offset >= client.s2c_wire.size()) {
            // Nothing queued ahead: send straight from the batch instead of
            // copying every byte into the queue first. Only the unsent tail
            // (EAGAIN/partial write) is queued, and EPOLLOUT covers it.
            const ssize_t sent = ::send(client.fd.get(), pending.data(), pending.size(),
                                        MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent > 0) {
                pending = pending.subspan(static_cast<std::size_t>(sent));
                touch(client, Clock::now());
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EINTR) {
                const int error = errno;
                release();
                close_client(token, error == ETIMEDOUT
                                        ? control::RelayCloseReason::client_timeout
                                        : control::RelayCloseReason::client_error);
                return false;
            }
        }
        const bool queued = pending.empty() || push_client_wire(client, pending, false);
        release();
        if (!queued) {
            stats_.add_backpressure(control::Direction::server_to_client);
            note_close(client, control::RelayCloseReason::backpressure);
            defer_close(token);
            reaccount(client);
            return false;
        }
    }
    if (!write_now || client.close_requested) {
        reaccount(client);
        return !client.close_requested;
    }
    // Write now instead of arming EPOLLOUT and waiting for the next epoll
    // round: the socket is normally writable, so this saves two epoll_ctl
    // transitions and a wakeup per answered client. EPOLLOUT is armed by
    // pump_client_out() only when the kernel buffer is full.
    pump_client_out(client);
    return clients_.find(token) != clients_.end();
}

void Runtime::Impl::flush_s2c_batches() {
    if (s2c_batch_tokens_.empty()) return;
    // Swap out first: a flush can close clients but never appends answers, so
    // the list cannot grow while it is being processed.
    std::vector<std::uint64_t> tokens;
    tokens.swap(s2c_batch_tokens_);
    for (const std::uint64_t token : tokens) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        (void)finish_s2c_batch(*found->second);
    }
    tokens.clear();
    if (s2c_batch_tokens_.empty()) s2c_batch_tokens_.swap(tokens);
    reaccount_shared();
}

void Runtime::Impl::enqueue_ready(Client& client) {
    // Single owner of queue membership: flag, unique counter and push happen
    // together and only here. A client may therefore appear at most once in its
    // own signed-DC ready queue.
    if (client.me == nullptr || client.c2s.empty() || client.in_me_queue ||
        client.close_requested || client.rate_pause_s2c) {
        return;
    }
    MeConn& me = *client.me;
    // Work may arrive before the ME session is ready (connecting/handshaking or
    // retry backoff). It must stay queued and is drained by on_me_ready or the
    // next retry; only a deferred failure means this DC is about to be torn
    // down and no membership should be created.
    if (me.failure_deferred) return;
    client.in_me_queue = true;
    ++me.queued_clients;
    me.ready_clients.push_back(client.token);
    // Membership changed: publish the queue gauges now, not only on the next
    // pump/tick, so a pre-ready backlog is visible (and testable) immediately.
    publish_me_queue(me);
}

void Runtime::Impl::pump_c2s(Client& client, Time now) {
    if (client.route == Client::Route::direct) {
        pump_direct_c2s(client);
        return;
    }
    if (client.c2s.empty() || client.me == nullptr) return;
    // Rate limit (per-connection share): hold the client's next requests while
    // its download share is overdrawn. Downloads are request-driven, so answers
    // slow down without any data being buffered here.
    if (client.rate_pause_s2c) return;
    MeConn& me = *client.me;
    if (me.state != MeConn::State::ready || me.session == nullptr) return;
    const std::uint64_t token = client.token;
    while (!client.c2s.empty()) {
        if (me.state != MeConn::State::ready || me.failure_deferred || !me.frames.empty()) break;
        const auto& message = client.c2s.front();
        const std::size_t estimate = message.data.size() + detail::kMeEncodeOverhead;
        if (me.frame_bytes + estimate > me_frame_capacity()) break;
        if (!budget_allows(estimate)) {
            // Documented fail-closed policy: an already-decoded message that no
            // longer fits the relay budget closes only this logical client
            // instead of sitting silently in a queue.
            stats_.add_backpressure(control::Direction::client_to_server);
            close_client(token, control::RelayCloseReason::backpressure);
            return;
        }
        try {
            me.frames.emplace_back();
            const auto status = me.session->encode_client_message(
                client.conn_id, message.data, client.peer, protocol::ProtoTag::Secure,
                message.quick_ack, me.frames.back().bytes);
            if (status != protocol::Status::Ok) {
                me.frames.pop_back();
                if (me.session->state() == protocol::MiddleEndSession::State::Failed) {
                    fail_me(me, now);
                } else {
                    close_client(token);
                }
                return;
            }
        } catch (const std::exception&) {
            if (!me.frames.empty()) me.frames.pop_back();
            fail_me(me, now);
            return;
        }
        me.frame_bytes += me.frames.back().bytes.size();
        stats_.me_request(worker_index_, me.dc, control::MeResult::success);
        client.awaiting_reply = true;
        client.last_forward_at = now;
        if (me.unanswered_since == Time{}) me.unanswered_since = now;
        client.c2s_capacity -= message.data.capacity();
        client.c2s.pop_front();
        reaccount(client);
        reaccount(me);
        pump_me_out(me);
        if (clients_.find(token) == clients_.end()) return;
    }
    // Queue membership is the caller's job (enqueue_ready). pump_c2s only
    // drains; this is what removed the base tree's double re-enqueue.
}

void Runtime::Impl::schedule_client_deadline(Client& client, Time now) {
    if (client.route == Client::Route::direct) {
        client.deadline_kind = Client::DeadlineKind::idle;
        deadlines_.set(client.token, client.last_activity + config_.idle_timeout);
        return;
    }
    if (client.phase != Client::Phase::relay) {
        client.deadline_kind = Client::DeadlineKind::handshake;
        deadlines_.set(client.token, now + config_.handshake_timeout);
    } else if (client.me == nullptr || client.me->state != MeConn::State::ready) {
        client.deadline_kind = Client::DeadlineKind::wait_me;
        deadlines_.set(client.token, now + config_.handshake_timeout);
    } else {
        client.deadline_kind = Client::DeadlineKind::idle;
        deadlines_.set(client.token, client.last_activity + config_.idle_timeout);
    }
}

void Runtime::Impl::on_client_deadline(Client& client, Time now) {
    const std::uint64_t token = client.token;
    if (client.deadline_kind == Client::DeadlineKind::fallback_idle) {
        on_fallback_deadline(client, now);
        return;
    }
    if (client.deadline_kind == Client::DeadlineKind::handshake) {
        if (client.phase != Client::Phase::relay) {
            reject_close(client, control::RejectReason::handshake_timeout,
                         control::HandshakeResult::timeout);
        } else {
            reject_close(client, control::RejectReason::other, std::nullopt);
        }
        return;
    }
    if (client.deadline_kind == Client::DeadlineKind::wait_me) {
        if (client.me != nullptr && client.me->state == MeConn::State::ready) {
            client.deadline_kind = Client::DeadlineKind::idle;
            deadlines_.set(token, client.last_activity + config_.idle_timeout);
        } else {
            reject_close(client, control::RejectReason::other, std::nullopt);
        }
        return;
    }
    const auto idle = config_.idle_timeout;
    if (now - client.last_activity >= idle) {
        close_client(token, control::RelayCloseReason::idle_timeout);
    } else {
        deadlines_.set(token, client.last_activity + idle);
    }
}

void Runtime::Impl::record_handshake(Client& client, control::HandshakeResult result) {
    if (!client.handshake_pending) return;
    client.handshake_pending = false;
    if (handshake_count_ > 0) --handshake_count_;
    shared_->release_handshake();
    stats_.handshake(result);
}

void Runtime::Impl::reject_close(Client& client, control::RejectReason reason,
                                 std::optional<control::HandshakeResult> handshake) {
    if (handshake && client.handshake_pending) record_handshake(client, *handshake);
    stats_.connection_rejected(reason);
    if (client.watched) watch_log(client, "reject", std::string("reason=") + control::to_string(reason));
    close_client(client.token);
}

void Runtime::Impl::close_client(std::uint64_t token, control::RelayCloseReason reason) {
    const auto found = clients_.find(token);
    if (found == clients_.end()) return;
    note_close(*found->second, reason);
    close_client(token);
}

void Runtime::Impl::close_client(std::uint64_t token, bool record_pending_handshake) {
    const auto found = clients_.find(token);
    if (found == clients_.end()) return;
    Client& client = *found->second;
    suspect_close(client, Clock::now());
    if (client.watched) watch_close(client);
    if (client.phase == Client::Phase::relay) stats_.relay_closed(client.close_reason);

    if (client.handshake_pending) {
        if (record_pending_handshake) {
            record_handshake(client, control::HandshakeResult::failure);
        } else {
            client.handshake_pending = false;
            if (handshake_count_ > 0) --handshake_count_;
            shared_->release_handshake();
        }
    }

    MeConn* const bound_me = client.me;
    if (bound_me != nullptr && bound_me->session &&
        bound_me->state == MeConn::State::ready) {
        // Best-effort per-logical close. It must not close the shared transport.
        // encode_close() advances write_seq/CBC, so the frame size is admitted
        // BEFORE encoding: a frame that cannot be staged is skipped instead of
        // desynchronising the shared ME stream.
        if (bound_me->frame_bytes + detail::kEncodedCloseFrameBytes <=
            me_frame_capacity()) {
            std::vector<std::uint8_t> frame;
            try {
                if (bound_me->session->encode_close(client.conn_id, frame) ==
                    protocol::Status::Ok) {
                    // Any post-encode loss desynchronises seq/CBC.
                    if (!push_me_frame(*bound_me, std::move(frame))) {
                        defer_me_failure(*bound_me);
                    }
                }
            } catch (const std::exception&) {
                defer_me_failure(*bound_me);
            }
        }
    }
    release_device(client, Clock::now());
    if (client.conn_registered) {
        clients_by_conn_.erase(client.conn_id);
        client.conn_registered = false;
    }
    if (client.backend_token != 0) close_fallback_backend(client);

    deadlines_.erase(token);
    // No EPOLL_CTL_DEL: close() below removes the descriptor from the epoll
    // set (it is never dup'ed), and stale events of this batch are dropped by
    // the targets_ lookup once remove_target() ran. Saves one syscall per close.
    client.armed = 0;
    if (client.in_me_queue) {
        // Lazy removal: the token stays in the deque and is dropped by the next
        // pump. Clearing the flag keeps the unique-client gauge truthful and
        // stops a recycled Client object from inheriting membership.
        client.in_me_queue = false;
        if (bound_me != nullptr) {
            if (bound_me->queued_clients > 0) --bound_me->queued_clients;
            publish_me_queue(*bound_me);
        }
    }
    if (bound_me != nullptr) {
        // The client set belongs to exactly one connection. Decrement before
        // clearing the pointer so draining/retirement sees the true load.
        if (bound_me->clients > 0) --bound_me->clients;
        client.me = nullptr;
    }
    if (client.direct_token != 0) {
        deadlines_.erase(client.direct_token);
        remove_target(client.direct_token);
        client.direct_token = 0;
    }
    client.direct_fd.close();
    remove_target(token);
    // TCP_USER_TIMEOUT also governs the orphaned socket after close(): with
    // 90 s a client that never ACKs our FIN kept FIN_WAIT1 for 90 s instead of
    // the host's tcp_orphan_retries bound. Restore the kernel default first.
    // A peer that sent its own FIN (read_eof) is alive and ACKs ours promptly,
    // so the reset is only needed for the remaining (dead/aborted) closes.
    if (client.fd.valid() && config_.client_ack_timeout.count() > 0 && !client.read_eof) {
        (void)io::set_tcp_user_timeout(client.fd.get(), 0);
    }
    client.fd.close();
    if (client.ip_counted) decrement_client_unique_ip(client);
    set_counted_active(client, false);
    if (client.metrics_counted && client.metrics) client.metrics->connection_closed();
    if (client.connection_counted) {
        stats_.connection_closed();
        shared_->release_connection();
    }
    forget_accounting(client.accounted);
    if (client_count_ > 0) --client_count_;
    // Detach ownership first: the recycle path may delete or pool the object,
    // and it must run after every external reference (targets_, clients_by_conn_,
    // deadlines_, ip sets, metrics) has been removed above.
    std::unique_ptr<Client> retired = std::move(found->second);
    clients_.erase(found);
    recycle_client(std::move(retired));
    update_listener_interest();
}

void Runtime::Impl::trim_idle_client(Client& client) {
    if (client.out) client.out->release_idle();
    // The Direct upstream queue holds one retained 16 KiB block after its first
    // append (the 64-byte obfuscated2 header). Without this it would stay
    // charged to the global budget for every idle Direct connection.
    if (client.direct_out) client.direct_out->release_idle();
    if (client.c2b) client.c2b->release_idle();
    if (client.tls) client.tls->release_idle();
    if (client.decoder) client.decoder->release_idle();
    // Staged TLS wire is only releasable when every staged byte was already
    // moved into `out`; a partial stage is real pending output.
    if (client.s2c_offset >= client.s2c_wire.size()) {
        client.s2c_wire.clear();
        if (client.s2c_wire.capacity() != 0) {
            std::vector<std::uint8_t>().swap(client.s2c_wire);
        }
        client.s2c_offset = 0;
    }
    reaccount(client);
}

} // namespace mtdd

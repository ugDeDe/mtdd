// Unit tests for mtdd::io socket/buffer primitives.
//
// Build:
//   g++ -std=c++20 -Wall -Wextra -Wpedantic -Iinclude src/io/*.cpp
//       tests/unit/io_test.cpp -lgtest -lgtest_main -pthread
//       -o build/mtdd-io-tests

#include "mtdd/io.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace {

using mtdd::io::AppendStatus;
using mtdd::io::ByteQueue;
using mtdd::io::connect_tcp;
using mtdd::io::Endpoint;
using mtdd::io::FlushStatus;
using mtdd::io::listen_tcp;
using mtdd::io::local_endpoint;
using mtdd::io::peer_endpoint;
using mtdd::io::UniqueFd;

constexpr std::size_t kChunk = ByteQueue::kChunkBytes;

std::vector<std::uint8_t> pattern(std::size_t size, unsigned seed = 0) {
    std::vector<std::uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>((i * 37U + seed * 11U + 5U) & 0xFFU);
    }
    return out;
}

// Creates a non-blocking CLOEXEC socketpair. Optionally shrinks the send buffer
// so that partial writes and EAGAIN are deterministic.
bool make_socketpair(int fds[2], int send_buffer = 0) {
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) != 0) {
        return false;
    }
    if (send_buffer > 0) {
        if (::setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) != 0) {
            ::close(fds[0]);
            ::close(fds[1]);
            return false;
        }
    }
    return true;
}

// Reads everything currently available without blocking.
std::vector<std::uint8_t> drain_fd(int fd) {
    std::vector<std::uint8_t> out;
    std::uint8_t buf[8192];
    for (;;) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            out.insert(out.end(), buf, buf + n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    return out;
}

std::vector<std::uint8_t> concat(std::vector<std::uint8_t> a, std::vector<std::uint8_t> b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// Flushes until drained, consuming the receiver side in between. Fails the test
// on error or on a stalled queue.
void flush_until_drained(ByteQueue& queue, int writer, int reader,
                         std::vector<std::uint8_t>& received, std::size_t budget = 64 * 1024) {
    for (int spin = 0; spin < 10000 && !queue.empty(); ++spin) {
        const auto result = queue.flush_to(writer, budget);
        ASSERT_NE(result.status, FlushStatus::error)
            << "errno=" << result.error << " (" << std::strerror(result.error) << ")";
        received = concat(std::move(received), drain_fd(reader));
        if (result.status == FlushStatus::would_block) {
            continue;
        }
    }
    received = concat(std::move(received), drain_fd(reader));
    ASSERT_TRUE(queue.empty());
}

// ---------------------------------------------------------------------------
// UniqueFd
// ---------------------------------------------------------------------------

TEST(UniqueFdTest, DefaultIsInvalid) {
    const UniqueFd fd;
    EXPECT_FALSE(fd.valid());
    EXPECT_EQ(fd.get(), -1);
    EXPECT_FALSE(static_cast<bool>(fd));
}

TEST(UniqueFdTest, AdoptsAndClosesDescriptor) {
    const int raw = ::dup(STDIN_FILENO);
    ASSERT_GE(raw, 0);
    {
        UniqueFd owned(raw);
        EXPECT_TRUE(owned.valid());
        EXPECT_EQ(owned.get(), raw);
        EXPECT_TRUE(static_cast<bool>(owned));
    }
    errno = 0;
    EXPECT_EQ(::fcntl(raw, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST(UniqueFdTest, MoveConstructionTransfersOwnership) {
    const int raw = ::dup(STDIN_FILENO);
    ASSERT_GE(raw, 0);
    UniqueFd source(raw);
    UniqueFd target(std::move(source));
    EXPECT_FALSE(source.valid());
    EXPECT_EQ(target.get(), raw);
    source.reset();
}

TEST(UniqueFdTest, MoveAssignmentClosesPreviousTarget) {
    const int first = ::dup(STDIN_FILENO);
    const int second = ::dup(STDIN_FILENO);
    ASSERT_GE(first, 0);
    ASSERT_GE(second, 0);
    UniqueFd target(first);
    UniqueFd source(second);
    target = std::move(source);
    EXPECT_EQ(target.get(), second);
    errno = 0;
    EXPECT_EQ(::fcntl(first, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST(UniqueFdTest, ReleaseAndResetDoNotClose) {
    const int raw = ::dup(STDIN_FILENO);
    ASSERT_GE(raw, 0);
    UniqueFd owned(raw);
    const int released = owned.release();
    EXPECT_EQ(released, raw);
    EXPECT_FALSE(owned.valid());
    EXPECT_NE(::fcntl(raw, F_GETFD), -1);
    EXPECT_EQ(::close(raw), 0);

    const int again = ::dup(STDIN_FILENO);
    ASSERT_GE(again, 0);
    owned.reset(again);
    EXPECT_EQ(owned.get(), again);
    owned.close();
    EXPECT_FALSE(owned.valid());
    owned.close();  // idempotent
}

// ---------------------------------------------------------------------------
// ByteQueue: accounting and append
// ---------------------------------------------------------------------------

TEST(ByteQueueTest, StartsEmptyAndLazilyAllocated) {
    ByteQueue queue(1024);
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.bytes(), 0U);
    EXPECT_EQ(queue.capacity_bytes(), 0U);
    EXPECT_EQ(queue.max_bytes(), 1024U);
}

TEST(ByteQueueTest, EmptyAppendIsAccepted) {
    ByteQueue queue(16);
    EXPECT_EQ(queue.append({}), AppendStatus::ok);
    EXPECT_EQ(queue.bytes(), 0U);
}

TEST(ByteQueueTest, AppendThenDrainPreservesBytesExactly) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    ByteQueue queue(64 * 1024);
    const auto payload = pattern(5000, 1);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    EXPECT_EQ(queue.bytes(), payload.size());

    const auto result = queue.flush_to(writer.get());
    EXPECT_EQ(result.status, FlushStatus::drained);
    EXPECT_EQ(result.bytes_written, payload.size());
    EXPECT_EQ(result.error, 0);
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(drain_fd(reader.get()), payload);
}

TEST(ByteQueueTest, RejectedAppendLeavesQueueUnchanged) {
    ByteQueue queue(100);
    const auto payload = pattern(60, 2);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    const std::size_t capacity_before = queue.capacity_bytes();

    const auto too_much = pattern(41, 3);
    EXPECT_EQ(queue.append(too_much), AppendStatus::exceeds_capacity);
    EXPECT_EQ(queue.bytes(), payload.size());
    EXPECT_EQ(queue.capacity_bytes(), capacity_before);

    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);
    EXPECT_EQ(queue.flush_to(writer.get(), 100).status, FlushStatus::drained);
    EXPECT_EQ(drain_fd(reader.get()), payload);
}

TEST(ByteQueueTest, OversizedAppendToEmptyQueueAllocatesNothing) {
    ByteQueue queue(1024);
    const auto payload = pattern(1025, 4);
    EXPECT_EQ(queue.append(payload), AppendStatus::exceeds_capacity);
    EXPECT_EQ(queue.bytes(), 0U);
    EXPECT_EQ(queue.capacity_bytes(), 0U);
}

TEST(ByteQueueTest, AcceptsExactlyCapacityAndRejectsOneMoreByte) {
    constexpr std::size_t kCap = 3 * kChunk;
    ByteQueue queue(kCap);
    const auto payload = pattern(kCap, 5);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    EXPECT_EQ(queue.bytes(), kCap);
    EXPECT_EQ(queue.append(std::span<const std::uint8_t>(payload).first(1)),
              AppendStatus::exceeds_capacity);
    EXPECT_EQ(queue.bytes(), kCap);
}

TEST(ByteQueueTest, AppendAcrossManyChunkBoundariesPreservesOrder) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    ByteQueue queue(256 * 1024);
    std::vector<std::uint8_t> expected;
    for (std::size_t i = 0; i < 60; ++i) {
        auto piece = pattern(997 + i * 13, static_cast<unsigned>(i));
        expected = concat(std::move(expected), piece);
        ASSERT_EQ(queue.append(piece), AppendStatus::ok);
        EXPECT_EQ(queue.bytes(), expected.size());
        // Retention must stay proportional to pending bytes, not to history.
        EXPECT_LE(queue.capacity_bytes(), queue.bytes() + 2 * kChunk);
    }

    std::vector<std::uint8_t> received;
    flush_until_drained(queue, writer.get(), reader.get(), received, 8192);
    EXPECT_EQ(received, expected);
}

TEST(ByteQueueTest, CoalescedSmallAppendsFlushAsOneOrderedBatch) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    ByteQueue queue(64 * 1024);
    const std::vector<std::uint8_t> first{1, 2};
    const std::vector<std::uint8_t> second{3};
    const std::vector<std::uint8_t> third{4, 5, 6};
    ASSERT_EQ(queue.append(first), AppendStatus::ok);
    ASSERT_EQ(queue.append(second), AppendStatus::ok);
    ASSERT_EQ(queue.append(third), AppendStatus::ok);

    const auto result = queue.flush_to(writer.get(), 64 * 1024);
    EXPECT_EQ(result.status, FlushStatus::drained);
    EXPECT_EQ(result.bytes_written, first.size() + second.size() + third.size());
    EXPECT_TRUE(queue.empty());

    const std::vector<std::uint8_t> expected{1, 2, 3, 4, 5, 6};
    EXPECT_EQ(drain_fd(reader.get()), expected);
}

// ---------------------------------------------------------------------------
// ByteQueue: flush semantics
// ---------------------------------------------------------------------------

TEST(ByteQueueTest, FlushEmptyQueueIsDrained) {
    ByteQueue queue(64);
    EXPECT_EQ(queue.flush_to(-1, 0).status, FlushStatus::drained);
}

TEST(ByteQueueTest, ZeroBudgetWithPendingBytesIsBudgetExhausted) {
    ByteQueue queue(64);
    const auto payload = pattern(10, 6);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    const auto result = queue.flush_to(-1, 0);
    EXPECT_EQ(result.status, FlushStatus::budget_exhausted);
    EXPECT_EQ(result.bytes_written, 0U);
    EXPECT_EQ(queue.bytes(), payload.size());
}

TEST(ByteQueueTest, BudgetLimitsBytesAcceptedByKernel) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    ByteQueue queue(4096);
    const auto payload = pattern(300, 7);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);

    const auto first = queue.flush_to(writer.get(), 120);
    EXPECT_EQ(first.status, FlushStatus::budget_exhausted);
    EXPECT_EQ(first.bytes_written, 120U);
    EXPECT_EQ(queue.bytes(), payload.size() - 120);

    std::vector<std::uint8_t> received = drain_fd(reader.get());
    EXPECT_EQ(received.size(), 120U);
    EXPECT_TRUE(std::equal(received.begin(), received.end(), payload.begin()));

    const auto second = queue.flush_to(writer.get(), 4096);
    EXPECT_EQ(second.status, FlushStatus::drained);
    EXPECT_EQ(second.bytes_written, payload.size() - 120);
    received = concat(std::move(received), drain_fd(reader.get()));
    EXPECT_EQ(received, payload);
}

TEST(ByteQueueTest, InvalidDescriptorReportsErrorAndKeepsBytes) {
    ByteQueue queue(64);
    const auto payload = pattern(12, 8);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    const auto result = queue.flush_to(-1, 64);
    EXPECT_EQ(result.status, FlushStatus::error);
    EXPECT_EQ(result.error, EBADF);
    EXPECT_EQ(result.bytes_written, 0U);
    EXPECT_EQ(queue.bytes(), payload.size());
}

TEST(ByteQueueTest, PartialWriteThenEagainThenLaterFlushWithoutNewData) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds, 4096));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    ByteQueue queue(256 * 1024);
    const auto payload = pattern(64 * 1024, 9);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);

    // The kernel send buffer is far smaller than the payload.
    const auto first = queue.flush_to(writer.get(), 64 * 1024);
    ASSERT_EQ(first.status, FlushStatus::would_block);
    ASSERT_GT(first.bytes_written, 0U);
    ASSERT_LT(first.bytes_written, payload.size());
    EXPECT_EQ(queue.bytes(), payload.size() - first.bytes_written);

    // Source is idle: no new appends. A second attempt must not lose data.
    const auto second = queue.flush_to(writer.get(), 64 * 1024);
    ASSERT_EQ(second.status, FlushStatus::would_block);
    EXPECT_EQ(second.bytes_written, 0U);
    EXPECT_EQ(queue.bytes(), payload.size() - first.bytes_written);

    std::vector<std::uint8_t> received = drain_fd(reader.get());
    EXPECT_EQ(received.size(), first.bytes_written);
    EXPECT_TRUE(std::equal(received.begin(), received.end(), payload.begin()));

    // Later flush, still without new source data, drains the remainder.
    flush_until_drained(queue, writer.get(), reader.get(), received);
    EXPECT_EQ(received, payload);
}

TEST(ByteQueueTest, SlowReceiverKeepsRetentionBounded) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds, 4096));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    constexpr std::size_t kCap = 96 * 1024;
    ByteQueue queue(kCap);
    const auto payload = pattern(kCap, 10);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    EXPECT_EQ(queue.append(std::span<const std::uint8_t>(payload).first(1)),
              AppendStatus::exceeds_capacity);

    // Receiver never reads: repeated flush attempts must not grow memory.
    for (int i = 0; i < 50; ++i) {
        const auto result = queue.flush_to(writer.get(), kCap);
        ASSERT_NE(result.status, FlushStatus::error);
        EXPECT_LE(queue.bytes(), kCap);
        EXPECT_LE(queue.capacity_bytes(), kCap + 2 * kChunk);
        if (result.status == FlushStatus::would_block) {
            continue;
        }
        break;
    }

    std::vector<std::uint8_t> received;
    flush_until_drained(queue, writer.get(), reader.get(), received);
    EXPECT_EQ(received, payload);
    EXPECT_LE(queue.capacity_bytes(), 2 * kChunk);
}

TEST(ByteQueueTest, IdleQueueRetainsNoLargeAllocation) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);

    ByteQueue queue(1024 * 1024);
    const auto payload = pattern(1024 * 1024, 11);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);

    std::vector<std::uint8_t> received;
    flush_until_drained(queue, writer.get(), reader.get(), received, 256 * 1024);
    EXPECT_EQ(received, payload);
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.bytes(), 0U);
    // Bounded idle retention: one reusable 16 KiB chunk, not the 1 MiB peak.
    EXPECT_LE(queue.capacity_bytes(), 2 * kChunk);
}

TEST(ByteQueueTest, ReleaseIdleDropsRetainedBlockButKeepsPendingBytes) {
    ByteQueue pending(256 * 1024);
    ASSERT_EQ(pending.append(pattern(1000, 21)), AppendStatus::ok);
    const std::size_t pending_capacity = pending.capacity_bytes();
    pending.release_idle();
    EXPECT_EQ(pending.bytes(), 1000U);
    EXPECT_EQ(pending.capacity_bytes(), pending_capacity);

    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);
    ByteQueue queue(256 * 1024);
    ASSERT_EQ(queue.append(pattern(1000, 22)), AppendStatus::ok);
    ASSERT_EQ(queue.flush_to(writer.get()).status, FlushStatus::drained);
    EXPECT_TRUE(queue.empty());
    EXPECT_GT(queue.capacity_bytes(), 0U);  // one retained idle block
    queue.release_idle();
    EXPECT_EQ(queue.capacity_bytes(), 0U);
    EXPECT_EQ(queue.bytes(), 0U);
}

TEST(ByteQueueTest, ClearDropsPendingBytesAndKeepsRetentionBounded) {
    ByteQueue queue(256 * 1024);
    ASSERT_EQ(queue.append(pattern(200 * 1024, 12)), AppendStatus::ok);
    queue.clear();
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.bytes(), 0U);
    EXPECT_LE(queue.capacity_bytes(), 2 * kChunk);

    const auto payload = pattern(100, 13);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);
    EXPECT_EQ(queue.bytes(), payload.size());
}

TEST(ByteQueueTest, MoveTransfersPendingBytesAndAccountedLimit) {
    ByteQueue source(1024);
    const auto payload = pattern(777, 15);
    ASSERT_EQ(source.append(payload), AppendStatus::ok);

    ByteQueue moved(std::move(source));
    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.max_bytes(), 0U);
    EXPECT_EQ(moved.bytes(), payload.size());
    EXPECT_EQ(moved.max_bytes(), 1024U);

    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    UniqueFd reader(fds[0]);
    EXPECT_EQ(moved.flush_to(writer.get()).status, FlushStatus::drained);
    EXPECT_EQ(drain_fd(reader.get()), payload);
}

TEST(ByteQueueTest, MovedFromQueueRejectsAppends) {
    ByteQueue source(64);
    ASSERT_EQ(source.append(pattern(8, 16)), AppendStatus::ok);

    ByteQueue moved(std::move(source));
    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.bytes(), 0U);
    EXPECT_EQ(source.max_bytes(), 0U);

    // Documented contract: a moved-from queue has a zero limit, so producers
    // must not keep appending to it after a move.
    const std::size_t capacity_before = source.capacity_bytes();
    EXPECT_EQ(source.append(pattern(1, 17)), AppendStatus::exceeds_capacity);
    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.capacity_bytes(), capacity_before);

    // The destination retained the original limit and pending bytes.
    EXPECT_EQ(moved.append(pattern(56, 18)), AppendStatus::ok);
    EXPECT_EQ(moved.append(pattern(1, 19)), AppendStatus::exceeds_capacity);
    EXPECT_EQ(moved.bytes(), 64U);
}

TEST(ByteQueueTest, PeerCloseReportsErrorWithoutSigpipe) {
    int fds[2];
    ASSERT_TRUE(make_socketpair(fds));
    UniqueFd writer(fds[1]);
    {
        UniqueFd reader(fds[0]);
    }  // peer closed

    ByteQueue queue(1024);
    const auto payload = pattern(16, 14);
    ASSERT_EQ(queue.append(payload), AppendStatus::ok);

    const auto result = queue.flush_to(writer.get(), 1024);
    EXPECT_EQ(result.status, FlushStatus::error);
    EXPECT_TRUE(result.error == EPIPE || result.error == ECONNRESET)
        << "unexpected errno " << result.error;
    // Data is retained: the write failed, nothing was acknowledged.
    EXPECT_EQ(queue.bytes(), payload.size());
    EXPECT_EQ(result.bytes_written, 0U);
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

TEST(SocketTest, ListenerIsNonBlockingCloexecAndReusable) {
    auto listener = listen_tcp("127.0.0.1", 0, 4);
    ASSERT_TRUE(listener.ok()) << std::strerror(listener.error);

    const int fd = listener.fd.get();
    const int status_flags = ::fcntl(fd, F_GETFL);
    ASSERT_NE(status_flags, -1);
    EXPECT_NE(status_flags & O_NONBLOCK, 0);

    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    ASSERT_NE(descriptor_flags, -1);
    EXPECT_NE(descriptor_flags & FD_CLOEXEC, 0);

    int reuse = 0;
    socklen_t len = sizeof(reuse);
    ASSERT_EQ(::getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &len), 0);
    EXPECT_NE(reuse, 0);

    const auto local = local_endpoint(fd);
    ASSERT_TRUE(local.has_value());
    EXPECT_EQ(local->address, "127.0.0.1");
    EXPECT_NE(local->port, 0);
    EXPECT_FALSE(peer_endpoint(fd).has_value());
}

TEST(SocketTest, NonBlockingConnectAndEndpointTuples) {
    auto listener = listen_tcp("127.0.0.1", 0, 8);
    ASSERT_TRUE(listener.ok()) << std::strerror(listener.error);
    const auto bound = local_endpoint(listener.fd.get());
    ASSERT_TRUE(bound.has_value());

    auto client = connect_tcp("127.0.0.1", bound->port);
    ASSERT_TRUE(client.ok()) << std::strerror(client.error);

    if (client.in_progress) {
        pollfd pfd{};
        pfd.fd = client.fd.get();
        pfd.events = POLLOUT;
        ASSERT_EQ(::poll(&pfd, 1, 2000), 1);
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        ASSERT_EQ(::getsockopt(client.fd.get(), SOL_SOCKET, SO_ERROR, &so_error, &len), 0);
        ASSERT_EQ(so_error, 0) << std::strerror(so_error);
    }

    pollfd accept_pfd{};
    accept_pfd.fd = listener.fd.get();
    accept_pfd.events = POLLIN;
    ASSERT_EQ(::poll(&accept_pfd, 1, 2000), 1);
    UniqueFd server(
        ::accept4(listener.fd.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
    ASSERT_TRUE(server.valid()) << std::strerror(errno);

    const auto server_local = local_endpoint(server.get());
    ASSERT_TRUE(server_local.has_value());
    EXPECT_EQ(server_local->address, "127.0.0.1");
    EXPECT_EQ(server_local->port, bound->port);

    const auto server_peer = peer_endpoint(server.get());
    ASSERT_TRUE(server_peer.has_value());
    EXPECT_EQ(server_peer->address, "127.0.0.1");

    const auto client_local = local_endpoint(client.fd.get());
    ASSERT_TRUE(client_local.has_value());
    EXPECT_EQ(client_local->address, "127.0.0.1");
    EXPECT_EQ(client_local->port, server_peer->port);

    const auto client_peer = peer_endpoint(client.fd.get());
    ASSERT_TRUE(client_peer.has_value());
    EXPECT_EQ(*client_peer, *bound);
}

TEST(SocketTest, ReusePortAllowsSecondListenerOnSamePort) {
    auto first = listen_tcp("127.0.0.1", 0, 8, true);
    if (!first.ok()) {
        GTEST_SKIP() << "SO_REUSEPORT unavailable: " << std::strerror(first.error);
    }
    const auto bound = local_endpoint(first.fd.get());
    ASSERT_TRUE(bound.has_value());

    auto second = listen_tcp("127.0.0.1", bound->port, 8, true);
    EXPECT_TRUE(second.ok()) << std::strerror(second.error);

    auto conflicting = listen_tcp("127.0.0.1", bound->port, 8, false);
    EXPECT_FALSE(conflicting.ok());
    EXPECT_TRUE(conflicting.error == EADDRINUSE || conflicting.error == EACCES)
        << "unexpected errno " << conflicting.error;
}

TEST(SocketTest, Ipv6LoopbackListenerAndConnect) {
    auto listener = listen_tcp("::1", 0, 4);
    if (!listener.ok()) {
        GTEST_SKIP() << "IPv6 loopback unavailable: " << std::strerror(listener.error);
    }
    const auto bound = local_endpoint(listener.fd.get());
    ASSERT_TRUE(bound.has_value());
    EXPECT_EQ(bound->address, "::1");

    auto client = connect_tcp("::1", bound->port);
    ASSERT_TRUE(client.ok()) << std::strerror(client.error);

    pollfd pfd{};
    pfd.fd = listener.fd.get();
    pfd.events = POLLIN;
    ASSERT_EQ(::poll(&pfd, 1, 2000), 1);
    UniqueFd server(
        ::accept4(listener.fd.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
    ASSERT_TRUE(server.valid()) << std::strerror(errno);

    const auto peer = peer_endpoint(server.get());
    ASSERT_TRUE(peer.has_value());
    EXPECT_EQ(peer->address, "::1");
}

TEST(SocketTest, EndpointHelpersRejectInvalidAndNonIpDescriptors) {
    EXPECT_FALSE(local_endpoint(-1).has_value());
    EXPECT_FALSE(peer_endpoint(-1).has_value());

    int pipe_fds[2];
    ASSERT_EQ(::pipe(pipe_fds), 0);
    UniqueFd read_end(pipe_fds[0]);
    UniqueFd write_end(pipe_fds[1]);
    EXPECT_FALSE(local_endpoint(read_end.get()).has_value());
    EXPECT_FALSE(peer_endpoint(read_end.get()).has_value());

    UniqueFd unconnected(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    ASSERT_TRUE(unconnected.valid()) << std::strerror(errno);
    const auto local = local_endpoint(unconnected.get());
    ASSERT_TRUE(local.has_value());
    EXPECT_EQ(local->address, "0.0.0.0");
    EXPECT_EQ(local->port, 0);
    EXPECT_FALSE(peer_endpoint(unconnected.get()).has_value());
}

TEST(SocketTest, AddressParsingRejectsEmbeddedNulAndOverlongInput) {
    const char raw[] = "127.0.0.1\0evil";
    const std::string_view with_nul(raw, sizeof(raw) - 1);
    ASSERT_GT(with_nul.size(), std::string_view("127.0.0.1").size());

    const auto nul_listener = listen_tcp(with_nul, 0);
    EXPECT_FALSE(nul_listener.ok());
    EXPECT_EQ(nul_listener.error, EINVAL);

    const auto nul_connect = connect_tcp(with_nul, 443);
    EXPECT_FALSE(nul_connect.ok());
    EXPECT_EQ(nul_connect.error, EINVAL);

    // 46 characters exceeds INET6_ADDRSTRLEN's maximum presentation length.
    const std::string overlong(46, 'a');
    const auto long_listener = listen_tcp(overlong, 0);
    EXPECT_FALSE(long_listener.ok());
    EXPECT_EQ(long_listener.error, EINVAL);
}

TEST(SocketTest, InvalidNumericEndpointsAreRejected) {
    const auto bad_v4 = listen_tcp("999.999.999.999", 0);
    EXPECT_FALSE(bad_v4.ok());
    EXPECT_EQ(bad_v4.error, EINVAL);

    const auto bad_v6 = listen_tcp("::gg", 0);
    EXPECT_FALSE(bad_v6.ok());
    EXPECT_EQ(bad_v6.error, EINVAL);

    const auto empty = connect_tcp("", 80);
    EXPECT_FALSE(empty.ok());
    EXPECT_EQ(empty.error, EINVAL);

    // Hostnames are not resolved: numeric endpoints only.
    const auto hostname = connect_tcp("localhost", 80);
    EXPECT_FALSE(hostname.ok());
    EXPECT_EQ(hostname.error, EINVAL);
}

}  // namespace

TEST(SocketTest, NumericAddressHelpersStayOffline) {
    namespace io = mtdd::io;
    EXPECT_TRUE(io::is_numeric_address("127.0.0.1"));
    EXPECT_TRUE(io::is_numeric_address("::1"));
    EXPECT_TRUE(io::is_numeric_address("8.8.8.8"));
    EXPECT_FALSE(io::is_numeric_address("github.com"));
    EXPECT_FALSE(io::is_numeric_address(""));
    EXPECT_FALSE(io::is_numeric_address("999.999.999.999"));

    // Literal addresses pass through without DNS, so this is offline-safe.
    const auto resolved = io::resolve_numeric_host("127.0.0.1");
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, "127.0.0.1");
    const auto v6 = io::resolve_numeric_host("::1");
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(*v6, "::1");
}

TEST(SocketOptionsTest, UserTimeoutAndKeepaliveAreApplied) {
    mtdd::io::UniqueFd fd(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    ASSERT_TRUE(fd.valid());
    ASSERT_TRUE(mtdd::io::set_tcp_user_timeout(fd.get(), 90000));
    unsigned timeout = 0;
    socklen_t length = sizeof(timeout);
    ASSERT_EQ(::getsockopt(fd.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, &length), 0);
    EXPECT_EQ(timeout, 90000U);
    // Zero restores the kernel default before close().
    EXPECT_TRUE(mtdd::io::set_tcp_user_timeout(fd.get(), 0));
    ASSERT_EQ(::getsockopt(fd.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, &length), 0);
    EXPECT_EQ(timeout, 0U);

    ASSERT_TRUE(mtdd::io::set_tcp_keepalive(fd.get(), 60, 15, 4));
    int idle = 0;
    length = sizeof(idle);
    ASSERT_EQ(::getsockopt(fd.get(), IPPROTO_TCP, TCP_KEEPIDLE, &idle, &length), 0);
    EXPECT_EQ(idle, 60);
    EXPECT_FALSE(mtdd::io::set_tcp_user_timeout(-1, 1000));
}

TEST(SocketOptionsTest, EndpointFromAcceptAddressMatchesPeerEndpoint) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(4433);
    ASSERT_EQ(::inet_pton(AF_INET, "203.0.113.7", &address.sin_addr), 1);
    const auto endpoint = mtdd::io::endpoint_from_address(&address, sizeof(address));
    ASSERT_TRUE(endpoint.has_value());
    EXPECT_EQ(endpoint->address, "203.0.113.7");
    EXPECT_EQ(endpoint->port, 4433);
    EXPECT_FALSE(mtdd::io::endpoint_from_address(&address, 2).has_value());
    EXPECT_FALSE(mtdd::io::endpoint_from_address(nullptr, 0).has_value());
}

#pragma once

/// @file io.hpp
/// @brief Linux socket and bounded output-buffer primitives used by the MTDD
///        proxy workers.
///
/// The module deliberately has no dependency on protocol, control, epoll, or
/// configuration code. A worker owns a ByteQueue per connection and drives it
/// from its own event loop; this module never registers events or blocks.

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mtdd::io {

/// Move-only RAII owner for a POSIX file descriptor.
///
/// Closing a descriptor that another thread may be polling is the caller's
/// responsibility: this class only guarantees that the owned number is closed
/// exactly once, on destruction, reset, or move-assignment.
class UniqueFd {
public:
    UniqueFd() noexcept = default;

    /// Adopts an already-open descriptor. The caller must not close it again.
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    ~UniqueFd();

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept;

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    /// Relinquishes ownership and returns the raw descriptor (-1 if invalid).
    [[nodiscard]] int release() noexcept;

    /// Closes the current descriptor (if any) and adopts @p fd.
    void reset(int fd = -1) noexcept;

    /// Closes the current descriptor and becomes invalid. Idempotent.
    void close() noexcept;

private:
    int fd_{-1};
};

/// Result of ByteQueue::append. Appends are all-or-nothing.
enum class AppendStatus : std::uint8_t {
    ok,
    /// @c pending + data.size() would exceed max_bytes(); the queue is untouched.
    exceeds_capacity,
    /// Allocation failed; the queue is rolled back to its previous contents.
    allocation_failure,
};

/// Outcome of ByteQueue::flush_to. Only @c error means data may be stuck for a
/// reason other than normal socket backpressure.
enum class FlushStatus : std::uint8_t {
    /// Every pending byte was accepted by the kernel.
    drained,
    /// The socket is not writable right now (EAGAIN/EWOULDBLOCK or short write).
    would_block,
    /// The byte budget was consumed while bytes remain pending.
    budget_exhausted,
    /// A real I/O error occurred; @c FlushResult::error holds errno.
    error,
};

struct FlushResult {
    FlushStatus status{FlushStatus::drained};
    std::size_t bytes_written{0};
    /// errno for @c FlushStatus::error, otherwise 0.
    int error{0};

    [[nodiscard]] bool drained() const noexcept { return status == FlushStatus::drained; }
    [[nodiscard]] bool ok() const noexcept { return status != FlushStatus::error; }
};

/// Bounded, chunked byte queue for socket output.
///
/// Bytes are stored in ~16 KiB blocks allocated on demand. A short write or
/// EAGAIN never consumes pending bytes: exactly the bytes accepted by the
/// kernel are removed, so a later flush can resume without the producer
/// supplying more data.
///
/// Retention is bounded independently of the logical limit: once drained, the
/// queue keeps at most one reusable 16 KiB block. A queue constructed with a
/// 1 MiB limit allocates nothing until bytes are appended and retains at most
/// one block when idle. A moved-from queue is valid, empty, and has a zero
/// logical limit.
class ByteQueue {
public:
    static constexpr std::size_t kChunkBytes = 16U * 1024U;
    /// Idle blocks retained for reuse after the queue drains.
    static constexpr std::size_t kRetainedIdleChunks = 1U;
    /// Maximum iovecs per sendmsg call.
    static constexpr std::size_t kMaxIovecs = 32U;

    /// @param max_bytes hard upper bound on pending (unsent) payload bytes.
    explicit ByteQueue(std::size_t max_bytes) noexcept : max_bytes_(max_bytes) {}

    ByteQueue(const ByteQueue&) = delete;
    ByteQueue& operator=(const ByteQueue&) = delete;
    ByteQueue(ByteQueue&& other) noexcept;
    ByteQueue& operator=(ByteQueue&& other) noexcept;

    /// Appends @p data atomically. On exceeds_capacity or allocation_failure
    /// the queue contents and capacity are unchanged.
    [[nodiscard]] AppendStatus append(std::span<const std::uint8_t> data);

    /// Writes at most @p byte_budget pending bytes to @p fd using sendmsg with
    /// MSG_NOSIGNAL, so a closed peer never raises SIGPIPE.
    ///
    /// EINTR is retried up to a small internal bound (fairness guard); an
    /// exhausted bound reports would_block with no bytes lost. EAGAIN and
    /// short writes also report would_block with only kernel-accepted bytes
    /// accounted for. @p fd is expected to be a non-blocking stream socket.
    [[nodiscard]] FlushResult flush_to(int fd, std::size_t byte_budget);

    /// Flushes with a budget equal to the currently pending byte count.
    [[nodiscard]] FlushResult flush_to(int fd) { return flush_to(fd, bytes_); }

    [[nodiscard]] std::size_t bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::size_t max_bytes() const noexcept { return max_bytes_; }
    [[nodiscard]] bool empty() const noexcept { return bytes_ == 0; }

    /// Sum of allocated block capacities, including the retained idle block.
    [[nodiscard]] std::size_t capacity_bytes() const noexcept;

    /// Drops all pending bytes, retaining at most one idle block.
    void clear() noexcept;

    /// Releases the retained idle block of an empty queue.
    ///
    /// Pending bytes are never touched: a non-empty queue is unchanged. A
    /// connection that has been idle for a while has no reuse benefit from the
    /// retained block, and with tens of thousands of mostly idle relay
    /// connections that retention is the dominant per-connection memory cost.
    void release_idle() noexcept;

private:
    struct Chunk {
        std::vector<std::uint8_t> data;
        std::size_t offset{0};
    };

    Chunk& tail_chunk();
    /// Removes @p count bytes from the front, recycling at most one block.
    void consume(std::size_t count) noexcept;
    /// Trims pending bytes back to @p target (strong-exception rollback).
    void trim_to(std::size_t target) noexcept;

    std::deque<Chunk> chunks_;
    std::vector<std::uint8_t> spare_;
    std::size_t bytes_{0};
    std::size_t max_bytes_{0};
};

/// A numeric IPv4/IPv6 endpoint. The address is a presentation string such as
/// "127.0.0.1" or "::1" (no brackets, no port, no resolution).
struct Endpoint {
    std::string address;
    std::uint16_t port{0};
};

[[nodiscard]] bool operator==(const Endpoint& lhs, const Endpoint& rhs) noexcept;
[[nodiscard]] bool operator!=(const Endpoint& lhs, const Endpoint& rhs) noexcept;

/// Descriptor-returning operation. On failure @c fd is invalid and @c error is
/// errno (or EINVAL for a malformed numeric endpoint).
struct FdResult {
    UniqueFd fd;
    int error{0};
    /// A non-blocking connect() returned EINPROGRESS: the socket exists and the
    /// caller must wait for writability, then verify SO_ERROR.
    bool in_progress{false};

    [[nodiscard]] bool ok() const noexcept { return fd.valid(); }
    explicit operator bool() const noexcept { return ok(); }
};

/// Creates a non-blocking, close-on-exec TCP listener bound to a numeric
/// address. Enables SO_REUSEADDR and optionally SO_REUSEPORT. @p backlog is
/// clamped to [1, 65535]; the kernel additionally caps the effective backlog
/// at net.core.somaxconn. Port 0 asks the kernel for an ephemeral port.
[[nodiscard]] FdResult listen_tcp(std::string_view address, std::uint16_t port,
                                  int backlog = 128, bool reuse_port = false);

/// Starts a non-blocking connect to a numeric endpoint. Success with
/// @c in_progress set means EINPROGRESS was reported, not that the connection
/// completed.
[[nodiscard]] FdResult connect_tcp(std::string_view address, std::uint16_t port);

/// Returns true when @p address is a literal IPv4/IPv6 address (no DNS).
[[nodiscard]] bool is_numeric_address(std::string_view address) noexcept;

/// Resolves @p host to a numeric IPv4/IPv6 address string. Literal addresses
/// pass through without consulting DNS. Returns nullopt on resolution failure.
[[nodiscard]] std::optional<std::string> resolve_numeric_host(std::string_view host);

/// Enables TCP keepalive probes on a connected stream socket. Returns false
/// when any option could not be applied; callers treat this as advisory.
[[nodiscard]] bool set_tcp_keepalive(int fd, int idle_seconds = 60,
                                     int interval_seconds = 10,
                                     int probes = 6) noexcept;

/// Sets TCP_USER_TIMEOUT: the connection is reset when transmitted data (or a
/// keepalive probe) stays unacknowledged for @p timeout_ms. Zero restores the
/// kernel default (retransmission/orphan retry limits). Returns false when the
/// option could not be applied.
[[nodiscard]] bool set_tcp_user_timeout(int fd, unsigned timeout_ms) noexcept;

/// Disables Nagle's algorithm. MTProto/FakeTLS records are small and
/// latency-sensitive, so coalescing them adds avoidable round-trip delay.
[[nodiscard]] bool set_tcp_nodelay(int fd) noexcept;

/// getsockname()/getpeername() as numeric endpoints. Returns nullopt for
/// non-IP sockets or syscall failure (e.g. ENOTCONN). Building the address
/// string allocates, so these helpers are deliberately not noexcept;
/// std::bad_alloc may propagate to the caller.
[[nodiscard]] std::optional<Endpoint> local_endpoint(int fd);
[[nodiscard]] std::optional<Endpoint> peer_endpoint(int fd);
/// Converts a sockaddr returned by accept4()/recvfrom() (@p length bytes at
/// @p address) without a getpeername() system call.
[[nodiscard]] std::optional<Endpoint> endpoint_from_address(const void* address,
                                                            std::size_t length);

}  // namespace mtdd::io

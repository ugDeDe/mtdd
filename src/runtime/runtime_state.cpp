#include "internal.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <string>
#include <utility>

namespace mtdd {

namespace {

// CPUs the process may run on, in ascending order (empty when unknown).
std::vector<int> allowed_cpus() {
    cpu_set_t set;
    CPU_ZERO(&set);
    if (::sched_getaffinity(0, sizeof(set), &set) != 0) return {};
    std::vector<int> cpus;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &set)) cpus.push_back(cpu);
    }
    return cpus;
}

// Best effort: a refused pin (container policy, CPU hot-unplug) only loses
// the locality gain.
void pin_current_thread(int cpu) noexcept {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    (void)::pthread_setaffinity_np(::pthread_self(), sizeof(set), &set);
}

}  // namespace

Runtime::RuntimeState::RuntimeState(const Config& config,
                                   control::UserStore& users,
                                   control::Statistics& statistics,
                                   MetadataProvider& metadata,
                                   RevisionBarrier& barrier) {
    std::size_t requested = config.workers == 0
                                ? static_cast<std::size_t>(
                                      std::max(std::thread::hardware_concurrency(), 1U))
                                : static_cast<std::size_t>(config.workers);
    if (requested == 0) requested = 1;
    if (requested > detail::kMaxWorkers) requested = detail::kMaxWorkers;

    const std::size_t minimum_per_worker =
        2U * config.max_frame_bytes + 2U * config.connection_queue_bytes +
        64U * 1024U;
    const std::size_t available =
        config.global_buffer_bytes > 0 ? config.global_buffer_bytes : minimum_per_worker;
    if (requested > 1) {
        if (config.global_buffer_bytes / requested < minimum_per_worker) {
            if (config.workers != 0) {
                throw std::invalid_argument(
                    "global_buffer_bytes is too small for the configured workers: "
                    "each reactor needs at least 2*max_frame_bytes + "
                    "2*connection_queue_bytes + 64 KiB; reduce workers or raise "
                    "global_buffer_bytes");
            }
            // Auto-detected worker count: shrink until the budget fits, but
            // never silently accept an impossible single-reactor budget.
            while (requested > 1 &&
                   available / requested < minimum_per_worker) {
                --requested;
            }
        }
    }
    workers = requested;
    cpu_affinity = config.cpu_affinity;
    // A corrupt usage file throws here (fail closed): silently starting from
    // zero would hand every user a fresh quota.
    usage_keeper = std::make_unique<control::UsageStateKeeper>(
        config.usage_state_path, statistics, users);
    usage_keeper->load();
    const std::size_t per_worker_budget = available / requested;
    shared = std::make_shared<detail::SharedState>(workers, per_worker_budget);
    shared->me_clients_per_writer.store(config.me_clients_per_writer, std::memory_order_relaxed);
    shared->me_connections_per_dc.store(config.me_connections_per_dc, std::memory_order_relaxed);
    set_media_limits(config.media_user_rate_kbps, config.media_total_rate_kbps);

    // Prime the process CSPRNG on the constructing thread before any reactor
    // thread exists. OpenSSL 3 performs a one-time DRBG setup on the first
    // RAND_bytes() call; running that setup concurrently from N reactors is
    // both a TSan-visible race inside libcrypto and wasted latency on the first
    // handshake of every reactor. Later draws (session nonces, transport
    // padding) stay lock-protected inside OpenSSL and never take a proxy lock.
    {
        std::array<std::uint8_t, 32> warm{};
        protocol::system_random()(warm);
        protocol::crypto::secure_zero(warm);
    }

    masking_dns = std::make_unique<detail::MaskingResolver>(config, users);
    Config reactor_config = config;
    reactor_config.global_buffer_bytes = per_worker_budget;
    reactors.reserve(workers);
    reactors.push_back(std::make_unique<Impl>(
        reactor_config, users, statistics, metadata, barrier, shared, 0,
        workers > 1, true));
    reactors.back()->masking_dns_ = masking_dns.get();
    const std::uint16_t bound = reactors.front()->port();
    if (config.proxy_port == 0) reactor_config.proxy_port = bound;
    for (std::size_t index = 1; index < workers; ++index) {
        reactors.push_back(std::make_unique<Impl>(
            reactor_config, users, statistics, metadata, barrier, shared, index,
            true, false));
        reactors.back()->masking_dns_ = masking_dns.get();
    }
    // Only publish the worker layout once every reactor exists: a listener-bind
    // failure above must not leave Statistics/RevisionBarrier configured for
    // reactors that were never created (their ack would never arrive).
    statistics.configure_workers(workers);
    barrier.configure_workers(workers);
    statistics_ = &statistics;
    statistics.set_device_lister(
        [weak = std::weak_ptr<detail::SharedState>(shared),
         window = config.device_window](const std::string& user) {
            std::vector<control::Statistics::DeviceInfo> out;
            if (const auto state = weak.lock()) {
                out = state->devices.list(user, std::chrono::steady_clock::now(), window);
            }
            return out;
        });
    if (config.suspects) {
        statistics.set_suspect_lister(
            [weak = std::weak_ptr<detail::SharedState>(shared),
             watch = static_cast<double>(config.suspect_watch_score),
             ban = static_cast<double>(config.suspect_ban_score)]() {
                std::vector<control::Statistics::SuspectInfo> out;
                if (const auto state = weak.lock()) {
                    out = state->suspects.list(
                        std::chrono::steady_clock::now(),
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count(),
                        watch, ban);
                }
                return out;
            });
    }
}

Runtime::RuntimeState::~RuntimeState() {
    if (statistics_) {
        statistics_->set_device_lister({});
        statistics_->set_suspect_lister({});
    }
    request_stop();
    {
        std::unique_lock lock{run_mutex_};
        run_done_.wait(lock, [this] { return !started_ || finished_; });
    }
    for (auto& thread : threads) {
        if (thread.joinable()) thread.join();
    }
    threads.clear();
    reactors.clear();
    if (usage_keeper) {
        usage_keeper->stop();
        // run() already flushed, but the management API outlives it and may
        // have reset a quota since; main() stops the API before this runs.
        usage_keeper->flush();
    }
}

void Runtime::RuntimeState::finish_run() noexcept {
    // Same reasoning as mark_exited(): notify under the mutex so a concurrent
    // destructor cannot destroy the condition variable mid-notification.
    const std::lock_guard lock{run_mutex_};
    finished_ = true;
    run_done_.notify_all();
}

void Runtime::RuntimeState::run() {
    {
        const std::lock_guard lock{run_mutex_};
        if (started_) return;
        started_ = true;
    }
    try {
        run_impl();
    } catch (...) {
        finish_run();
        throw;
    }
    finish_run();
}

void Runtime::RuntimeState::run_impl() {
    std::mutex failure_mutex;
    std::exception_ptr failure;
    const auto record = [&](std::exception_ptr error) {
        const std::lock_guard lock{failure_mutex};
        if (!failure) failure = std::move(error);
    };
    if (usage_keeper) usage_keeper->start();
    masking_dns->start();
    // Reactor i on the i-th allowed CPU, only with one reactor per CPU at
    // most. Every helper thread already exists, so pinning the calling thread
    // (reactor 0) below cannot leak into threads created later.
    std::vector<int> cpus;
    if (cpu_affinity && workers > 1) {
        cpus = allowed_cpus();
        if (cpus.size() < workers) cpus.clear();
    }
    try {
        threads.reserve(workers > 0 ? workers - 1 : 0);
        for (std::size_t index = 1; index < workers; ++index) {
            const int cpu = cpus.empty() ? -1 : cpus[index];
            threads.emplace_back([this, index, cpu, &record] {
                if (cpu >= 0) pin_current_thread(cpu);
                try {
                    reactors[index]->run();
                } catch (...) {
                    record(std::current_exception());
                    shared->stop_all();
                }
            });
        }
    } catch (...) {
        shared->stop_all();
        masking_dns->stop();
        for (auto& thread : threads) {
            if (thread.joinable()) thread.join();
        }
        threads.clear();
        throw;
    }
    if (!cpus.empty()) pin_current_thread(cpus.front());
    try {
        reactors.front()->run();
    } catch (...) {
        record(std::current_exception());
        shared->stop_all();
    }
    // Every reactor is stopping now. Stopping the resolver before joining the
    // others overlaps its one in-flight lookup with their drain; reactors still
    // running only read the cache, which stays valid.
    masking_dns->stop();
    for (auto& thread : threads) {
        if (thread.joinable()) thread.join();
    }
    threads.clear();
    // Final flush on clean shutdown (also on a reactor failure: counters are
    // still the best known values).
    if (usage_keeper) usage_keeper->stop();
    std::exception_ptr result;
    {
        const std::lock_guard lock{failure_mutex};
        result = failure;
    }
    if (result) std::rethrow_exception(result);
}

void Runtime::RuntimeState::request_stop() noexcept {
    if (shared) shared->stop_all();
}

std::uint16_t Runtime::RuntimeState::port() const noexcept {
    return reactors.empty() ? 0 : reactors.front()->port();
}

std::vector<std::uint64_t> Runtime::RuntimeState::accepted_clients_per_worker() const {
    std::vector<std::uint64_t> counts;
    counts.reserve(workers);
    for (std::size_t index = 0; index < workers; ++index) {
        counts.push_back(shared->accepted_per_worker[index].load(std::memory_order_relaxed));
    }
    return counts;
}

std::vector<std::uint64_t> Runtime::RuntimeState::replay_rejections_per_worker() const {
    std::vector<std::uint64_t> counts;
    counts.reserve(workers);
    for (std::size_t index = 0; index < workers; ++index) {
        counts.push_back(
            shared->replay_rejected_per_worker[index].load(std::memory_order_relaxed));
    }
    return counts;
}

void Runtime::RuntimeState::set_tunables(std::uint32_t me_clients_per_writer,
                                         std::uint32_t me_connections_per_dc) {
    if (me_clients_per_writer < 1 || me_clients_per_writer > 1000000) {
        throw std::invalid_argument("me_clients_per_writer must be in 1..1000000");
    }
    if (me_connections_per_dc < 1 || me_connections_per_dc > 24) {
        throw std::invalid_argument("me_connections_per_dc must be in 1..24");
    }
    shared->me_clients_per_writer.store(me_clients_per_writer, std::memory_order_relaxed);
    shared->me_connections_per_dc.store(me_connections_per_dc, std::memory_order_relaxed);
    // Release pairs with the reactors' acquire load of the generation.
    shared->tunables_generation.fetch_add(1, std::memory_order_release);
}

void Runtime::RuntimeState::set_media_limits(std::uint64_t user_kbps,
                                             std::uint64_t total_kbps) noexcept {
    // kbit/s -> bytes/s.
    shared->set_media_rates(user_kbps * 125U, total_kbps * 125U);
}

void Runtime::RuntimeState::set_ad_tag(const std::array<std::uint8_t, 16>& tag) {
    // All-zero clears the ad tag (no sponsored channel); the reactors stop
    // emitting the TL_PROXY_TAG block on their next frames.
    {
        std::lock_guard lock(shared->ad_tag_mutex);
        shared->ad_tag = tag;
    }
    // Release pairs with the reactors' acquire load of the generation.
    shared->ad_tag_generation.fetch_add(1, std::memory_order_release);
}

void Runtime::RuntimeState::on_reload(std::function<void()> hook) {
    shared->reload_hook = std::move(hook);
}

Runtime::Runtime(const Config& config, control::UserStore& users,
                 control::Statistics& statistics, MetadataProvider& metadata,
                 RevisionBarrier& barrier)
    : state_(std::make_unique<RuntimeState>(config, users, statistics, metadata,
                                            barrier)) {}

Runtime::~Runtime() = default;

void Runtime::run() { state_->run(); }

void Runtime::request_stop() noexcept { state_->request_stop(); }

void Runtime::set_tunables(std::uint32_t me_clients_per_writer,
                           std::uint32_t me_connections_per_dc) {
    state_->set_tunables(me_clients_per_writer, me_connections_per_dc);
}

void Runtime::on_reload(std::function<void()> hook) { state_->on_reload(std::move(hook)); }

void Runtime::set_ad_tag(const std::array<std::uint8_t, 16>& tag) { state_->set_ad_tag(tag); }

void Runtime::set_media_limits(std::uint64_t user_kbps, std::uint64_t total_kbps) noexcept {
    state_->set_media_limits(user_kbps, total_kbps);
}

std::uint16_t Runtime::port() const noexcept { return state_->port(); }

std::size_t Runtime::worker_count() const noexcept { return state_->worker_count(); }

std::vector<std::uint64_t> Runtime::accepted_clients_per_worker() const {
    return state_->accepted_clients_per_worker();
}

std::vector<std::uint64_t> Runtime::replay_rejections_per_worker() const {
    return state_->replay_rejections_per_worker();
}

} // namespace mtdd

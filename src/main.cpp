#include "mtdd/config.hpp"
#include "mtdd/control.hpp"
#include "mtdd/metadata.hpp"
#include "mtdd/runtime.hpp"
#include "mtdd/runtime_support.hpp"

#include <pthread.h>
#include <signal.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string_view>

#ifndef MTDD_VERSION
#define MTDD_VERSION "development"
#endif

namespace {
struct Arguments {
    std::string path;
    bool check{};
};

Arguments arguments(int argc, char** argv) {
    Arguments result;
    for (int i{1}; i < argc; ++i) {
        const std::string_view option{argv[i]};
        if (option == "--check-config") result.check = true;
        else if (option == "--config" && i + 1 < argc) {
            if (!result.path.empty()) throw std::invalid_argument("--config was specified twice");
            result.path = argv[++i];
        } else throw std::invalid_argument("usage: mtdd --config CONFIG.json [--check-config]");
    }
    if (result.path.empty()) throw std::invalid_argument("--config CONFIG.json is required");
    return result;
}

std::string api_token(const mtdd::Config& config) {
    const auto* value = std::getenv(config.api_token_env.c_str());
    const std::string token = value ? value : "";
    if (token.size() < 32 || token.size() > 512 ||
        !std::all_of(token.begin(), token.end(), [](unsigned char c) { return c >= 33 && c <= 126; }))
        throw std::invalid_argument("API token environment variable must contain 32..512 printable non-space characters");
    return token;
}

void block_shutdown_signals() {
    sigset_t signals;
    ::sigemptyset(&signals);
    ::sigaddset(&signals, SIGINT);
    ::sigaddset(&signals, SIGTERM);
    // SIGHUP is consumed by the runtime's signalfd as "reload", never as the
    // default terminate action.
    ::sigaddset(&signals, SIGHUP);
    if (::pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0)
        throw std::runtime_error("cannot configure shutdown signals");
}

int serve(const mtdd::Config& config, const std::filesystem::path& config_path) {
    const auto token = api_token(config);
    block_shutdown_signals(); // All background threads inherit this mask.
    mtdd::RevisionBarrier applied;
    mtdd::control::StoreOptions store_options;
    store_options.ack_hook = [&](std::uint64_t revision, std::chrono::milliseconds timeout) {
        return applied.wait(revision, timeout);
    };
    auto opened = mtdd::control::UserStore::open(config.users_path.string(), std::move(store_options));
    if (!opened) throw std::runtime_error("cannot open users store: " + std::string(mtdd::control::to_string(opened.error().code)));
    auto users = std::move(opened).value();
    mtdd::control::Statistics stats;
    stats.set_build_info(MTDD_VERSION);
    stats.enable_ip_history(config.unique_ip_stats_path.string());
    mtdd::MetadataProvider metadata{config};
    mtdd::Runtime runtime{config, users, stats, metadata, applied};
    // systemctl reload mtdd (SIGHUP): re-read the file and apply the settings
    // that can change without dropping clients. Others need a restart.
    runtime.on_reload([&runtime, config_path] {
        try {
            const auto fresh = mtdd::Config::load(config_path);
            runtime.set_tunables(fresh.me_clients_per_writer, fresh.me_connections_per_dc);
            runtime.set_media_limits(fresh.media_user_rate_kbps, fresh.media_total_rate_kbps);
            std::cerr << "mtdd: reloaded me_clients_per_writer=" << fresh.me_clients_per_writer
                      << " me_connections_per_dc=" << fresh.me_connections_per_dc
                      << " media_user_rate_kbps=" << fresh.media_user_rate_kbps
                      << " media_total_rate_kbps=" << fresh.media_total_rate_kbps << '\n';
        } catch (const std::exception& error) {
            std::cerr << "mtdd: reload rejected, keeping current settings: " << error.what()
                      << '\n';
        }
    });
    mtdd::control::HttpOptions http;
    http.bind_address = config.control_host;
    http.port = config.control_port;
    http.bearer_token = token;
    http.public_host = config.public_host;
    http.public_port = config.public_port;
    http.tls_domain = config.tls_domain;
    mtdd::control::ControlServer management{users, stats, std::move(http)};
    const auto listening = management.start();
    if (!listening) throw std::runtime_error("cannot start management listener");
    std::cerr << "mtdd " << MTDD_VERSION << ": proxy=" << config.proxy_host << ':' << runtime.port()
              << " management=" << config.control_host << ':' << listening.value() << '\n';
    try {
        runtime.run();
    } catch (...) {
        stats.set_ready(false);
        applied.stop();
        management.stop();
        throw;
    }
    stats.set_ready(false);
    applied.stop();
    management.stop();
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--version") {
            std::cout << "mtdd " << MTDD_VERSION << '\n';
            return 0;
        }
        const auto args = arguments(argc, argv);
        const auto config = mtdd::Config::load(args.path);
        if (args.check) {
            std::cout << "configuration valid (syntax and static limits only)\n";
            return 0;
        }
        return serve(config, args.path);
    } catch (const std::exception& error) {
        std::cerr << "mtdd: " << error.what() << '\n';
        return 1;
    }
}

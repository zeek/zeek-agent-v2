// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/scheduler.h"
#include "core/signal.h"
#include "core/table.h"
#include "io/console.h"
#include "io/zeek.h"
#include "platform/platform.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <csignal>
#include <iostream>
#include <optional>

#ifdef HAVE_DARWIN
#include "platform/darwin/network-extension.h"
#endif

#define DOCTEST_CONFIG_NO_UNPREFIXED_OPTIONS
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_OPTIONS_PREFIX "test-"
#include "util/testing.h"

namespace zeek::agent {
SignalManager* signal_mgr = nullptr;
signal::Handler* sigint = nullptr;

static void log_termination() { logger()->info("process terminated", VersionLong); }
static int main(const std::vector<std::string>& argv);
} // namespace zeek::agent

using namespace zeek::agent;

int main(int argc, char** argv) {
    // Start with a stateless pass over our command line options to get our
    // mode of operation. This isn't using any OS-specific functionality yet,
    // and hence safe to do on macOS before we go into Network Extension mode
    // (doing that wouldn't work anymore after we've already accessed the OS'
    // `defaults` storage.)

    std::vector<std::string> argv_;
    argv_.reserve(argc);
    for ( auto i = 0; i < argc; ++i )
        argv_.emplace_back(argv[i]);

    auto options = Options::default_();
    if ( auto rc = options.parseArgv(argv_); ! rc ) {
        std::cerr << rc.error() << std::endl;
        return 1;
    }

    switch ( options.mode ) {
        case options::Mode::Standard: {
#ifdef HAVE_DARWIN
            // Our network extension needs to take over the primary thread, so we move
            // our main logic into a new thread. Also note that the network extension
            // needs to start up as early as possible, in particular (it appears)
            // before we start using the configuration system.
            auto _ = std::make_unique<std::thread>([argv_]() { zeek::agent::main(argv_); });
            platform::darwin::enterNetworkExtensionMode(); // won't return
            cannot_be_reached();
#else
            // Can run inside main thread.
            return zeek::agent::main(argv_);
#endif
        }

        case options::Mode::Test: {
#ifndef DOCTEST_CONFIG_DISABLE
            if ( ! options.log_level ) {
                options::default_log_level = options::LogLevel::off;
                logger()->set_level(options::LogLevel::off);
            }

            platform::setenv("TZ", "GMT", 1);
            doctest::Context context(argc, argv);
            return context.run();
#else
            logger::fatalError("unit tests not compiled in");
#endif
        }

        case options::Mode::AutoDoc: {
            std::cout << Database::documentRegisteredTables() << std::endl;
            return 0;
        }
    }
}

// This implements most of the actual top-level main() logic. We separate this
// out so that we can move it into a thread on Darwin, where the main thread
// needs to be the network extension.
int zeek::agent::main(const std::vector<std::string>& argv) {
    logger()->info("Zeek Agent {} starting up", VersionLong);
    atexit(log_termination);

    auto _ = ScopeGuard([]() { platform::done(); });

    try {
        Configuration cfg;
        auto rc = cfg.initFromArgv(argv);
        if ( ! rc ) {
            std::cerr << rc.error() << std::endl;
            return 0;
        }

        assert(cfg.options().mode == options::Mode::Standard); // others are handled earlier already

        if ( ! platform::runningAsAdmin() && ! cfg.options().use_mock_data )
            logger()->warn("not running as root, information may be incomplete");

        platform::init(cfg);

        Scheduler scheduler;
        signal_mgr = new SignalManager({SIGINT});
        sigint = new signal::Handler(signal_mgr, SIGINT, [&]() { scheduler.terminate(); });

        Database db(&cfg, &scheduler);
        for ( const auto& t : Database::registeredTables() )
            db.addTable(t.second.get());

        std::unique_ptr<Console> console;
        if ( cfg.options().interactive || ! cfg.options().execute.empty() ) {
            console = std::make_unique<Console>(&db, &scheduler, signal_mgr);

            if ( ! cfg.options().execute.empty() )
                console->scheduleStatementWithTermination(cfg.options().execute);

            console->start();
        }

        std::unique_ptr<Zeek> zeek;
        if ( ! cfg.options().zeek_destinations.empty() ) {
            zeek = std::make_unique<Zeek>(&db, &scheduler);
            zeek->start(cfg.options().zeek_destinations);
        }

        ZEEK_AGENT_DEBUG("main", "looping until terminated");

        while ( ! scheduler.loop() ) {
            db.poll();

            if ( zeek )
                zeek->poll();

            db.expire();
        }

        platform::done();
        delete sigint;
        delete signal_mgr;

        return 0;
    } catch ( const FatalError& e ) {
        logger()->error("fatal error: {}", e.what());
        delete sigint;
        delete signal_mgr;

        return 1;
    } catch ( const InternalError& e ) {
        logger()->error("internal error: {}", e.what());
        delete sigint;
        delete signal_mgr;

        return 1;
    }
}

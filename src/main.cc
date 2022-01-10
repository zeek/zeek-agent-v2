// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/scheduler.h"
#include "core/signal.h"
#include "io/console.h"
#include "io/zeek.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/threading.h"

#include <iostream>
#include <optional>

#include <signal.h>

using namespace zeek::agent;

static void log_termination() { logger()->info(format("process terminated", VersionLong)); }

int main(int argc, char** argv) {
    try {
        Configuration cfg;
        auto rc = cfg.initFromArgv(argc, argv);
        if ( ! rc ) {
            std::cerr << rc.error() << std::endl;
            return 0;
        }

        logger()->info(format("Zeek Agent {} starting up", VersionLong));
        atexit(log_termination);

        if ( geteuid() != 0 && ! cfg.options().use_mock_data )
            logger()->warn("not running as root, information may be incomplete");

        ConditionVariable main_loop;
        Scheduler scheduler;
        SignalManager signal_mgr({SIGINT});
        signal::Handler sigint(&signal_mgr, SIGINT, [&]() { scheduler.terminate(); });

        Database db(&cfg, &scheduler);
        for ( const auto& t : Database::registeredTables() )
            db.addTable(t.second.get());

        std::unique_ptr<Console> console;
        if ( cfg.options().interactive || cfg.options().execute.size() ) {
            console = std::make_unique<Console>(&db, &scheduler, &signal_mgr);

            if ( cfg.options().execute.size() )
                console->scheduleStatementWithTermination(cfg.options().execute);

            console->start();
        }

        std::unique_ptr<Zeek> zeek;
        if ( ! cfg.options().zeeks.empty() ) {
            zeek = std::make_unique<Zeek>(&db, &scheduler);
            zeek->start(cfg.options().zeeks);
        }

        ZEEK_AGENT_DEBUG("main", "looping until terminated");

        scheduler.registerUpdateCallback([&main_loop]() { main_loop.notify(); });

        while ( ! scheduler.terminating() ) {
            db.poll();

            if ( zeek )
                zeek->poll();

            if ( auto next_timer = scheduler.nextTimer(); next_timer == 0_time ) {
                // TODO: make timeout configurable
                auto t = Interval(15s);
                ZEEK_AGENT_DEBUG("main", "completely idle, sleeping with timeout={}", to_string(t));
                main_loop.wait(t);
            }

            else if ( auto t = next_timer - std::chrono::system_clock().now(); t > 0s ) {
                ZEEK_AGENT_DEBUG("main", "sleeping with timeout={}", to_string(t));
                main_loop.wait(t);
            }

            scheduler.advance(std::chrono::system_clock().now());
            db.expire();
            main_loop.reset(); // clear any updates that were just flagged
        }

        return 0;

    } catch ( const FatalError& e ) {
        logger()->error(format("fatal error: {}", e.what()));
        return 1;

    } catch ( const InternalError& e ) {
        logger()->error(format("internal error: {}", e.what()));
        return 1;
    }
}

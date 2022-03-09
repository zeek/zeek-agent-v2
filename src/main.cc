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
#include "util/fmt.h"
#include "util/helpers.h"

#include <csignal>
#include <iostream>
#include <optional>

#ifdef _WIN32
#include "util/windows-util.h"
#endif

using namespace zeek::agent;

SignalManager* zeek::agent::signal_mgr = nullptr;
signal::Handler* sigint;

static void log_termination() { logger()->info("process terminated", VersionLong); }

static bool running_as_admin() {
#ifdef WIN32
    // Adapted from
    // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
    BOOL is_member;
    PSID administrator_group = nullptr;
    SID_IDENTIFIER_AUTHORITY auth_nt = SECURITY_NT_AUTHORITY;
    is_member = AllocateAndInitializeSid(&auth_nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,
                                         0, 0, &administrator_group);

    if ( ! is_member )
        return false;

    if ( ! CheckTokenMembership(nullptr, administrator_group, &is_member) )
        is_member = false;

    FreeSid(administrator_group);
    return is_member;
#else
    return geteuid() != 0;
#endif
}

int main(int argc, char** argv) {
    try {
        Configuration cfg;
        auto rc = cfg.initFromArgv(argc, argv);
        if ( ! rc ) {
            std::cerr << rc.error() << std::endl;
            return 0;
        }

        if ( cfg.options().mode == options::Mode::AutoDoc ) {
            std::cout << Database::documentRegisteredTables() << std::endl;
            exit(0);
        }

        logger()->info("Zeek Agent {} starting up", VersionLong);
        atexit(log_termination);

        if ( running_as_admin() && ! cfg.options().use_mock_data )
            logger()->warn("not running as root, information may be incomplete");

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

#ifdef _WIN32
        WMIManager::Get().Shutdown();
#endif

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

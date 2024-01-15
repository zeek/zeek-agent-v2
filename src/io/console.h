// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/filesystem.h"
#include "util/pimpl.h"

#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace zeek::agent {

class Database;
class Scheduler;
class SignalManager;

/**
 * Provides an interactive console to execute queries and commands. The console
 * will execute in a separate thread.
 *
 * There should be only one console instance at a time.
 *
 * All public methods are thread-safe.
 */
class ConsoleServer : public Pimpl<ConsoleServer> {
public:
    /**
     * Constructor. TODO: Update
     *
     * @param database database to use for queries; observer only, doesn't take ownership
     * @param scheduler scheduler to use for any timers; observer only, doesn't take ownership
     */
    ConsoleServer(const filesystem::path& socket, Database* db, Scheduler* scheduler);
    ~ConsoleServer();

    /** Starts a console server thread. */
    void start();

    /** Stops the console server thread. */
    void stop();
};

class ConsoleClient : public Pimpl<ConsoleClient> {
public:
    /**
     * Constructor. TODO: Update
     *
     * @param database database to use for queries; observer only, doesn't take ownership
     * @param scheduler scheduler to use for any timers; observer only, doesn't take ownership
     * @param signal_mgr signal manager to install handlers with; observer only, doesn't take ownership; can be left
     * null for testing purposes (will prevent aborting with SIGINT)
     */
    ConsoleClient(const filesystem::path& socket, Scheduler* scheduler, SignalManager* signal_mgr);
    ~ConsoleClient();

    /**
     * Schedule a single statement for execution, to then exit once it has
     * finished. Must be called before `start().
     *
     * @param stmt statement to execute
     * @param echo whether to echo the result to tty
     */
    void scheduleStatementWithTermination(std::string stmt, bool echo = true);

    /**
     * Starts a console server thread.
     *
     * @param run_repl whether to run the REPL loop in the client; only turn
     * off for testing purposes
     */
    void start(bool run_repl = true);

    /** Stops the console server thread. */
    void stop();
};

} // namespace zeek::agent

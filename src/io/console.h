// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/pimpl.h"
#include "util/threading.h"

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
class Console : public Pimpl<Console>, SynchronizedBase {
public:
    /**
     * Constructor.
     *
     * @param database database to use for queries; observer only, doesn't take ownership
     * @param scheduler scheduler to use for any timeers; observer only, doesn't take ownership
     * @param signal_mgr signal manager to install handlers with; observer only, doesn't take ownership
     */
    Console(Database* db, Scheduler* scheduler, SignalManager* signal_mgr);
    ~Console();

    /**
     * Schedule a single statement for execution, to then exit once it has
     * finished. Must be called before `start().
     */
    void scheduleStatementWithTermination(std::string stmt);

    /** Starts a console thread. */
    void start();

    /** Stops the console thread. */
    void stop();
};

} // namespace zeek::agent

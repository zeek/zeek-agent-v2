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

/**
 * Provides the connector to external Zeek instances.
 *
 * There should be only one Zeek connector instance at a time.
 *
 * All public methods are thread-safe.
 */
class Zeek : public Pimpl<Zeek>, SynchronizedBase {
public:
    /**
     * Constructor.
     *
     * @param database database to use for queries; observer only, doesn't take ownership
     * @param scheduler scheduler to use for any timeers; observer only, doesn't take ownership
     */
    Zeek(Database* db, Scheduler* scheduler);
    ~Zeek();

    /**
     * Starts communication with external Zeek instances.
     *
     * @param zeeks Zeek destinations to connect to, in the form of `<address>:[port]`
     */
    void start(const std::vector<std::string>& zeeks);

    /**
     * Terminates all Zeek communication.
     */
    void stop();

    /** Performs maintaince tasks and must be called regularly from the main loop. */
    void poll();
};

} // namespace zeek::agent

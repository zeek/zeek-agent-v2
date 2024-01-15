// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/helpers.h"
#include "util/pimpl.h"

#include <functional>

namespace zeek::agent {

namespace timer {
/** Unique ID for a scheduled timer. */
using ID = uint64_t;

/**
 * Callback triggering when a timer expires. If the callback returns a non-zero interval, the
 * scheduler will automatically reschedule the timer the given amount of time into the future.
 * The reschedule timer will keep its ID.
 */
using Callback = std::function<Interval(ID)>;
} // namespace timer

namespace task {
/** Callback for an operation queued for execution. */
using Callback = std::function<void()>;
} // namespace task

/**
 * Manages a set of scheduled timers with associated callbacks to eventually
 * execute. The scheduler has an internal notion of time and will execute the
 * callback associated with a timer once its expiration time has been reached.
 * Timer and callback will then be deleted afterwards.
 *
 * A scheduler doesn't automatically advances it's time; that must be driven
 * externally by calls to `advance()`. That allows the caller to decide the
 * semantics of time: they can drive it either through a real-time clock, or
 * for example through a deterministic sequence of fixed steps. The latter is
 * particularly useful for unit testing.
 *
 * Note that methods of this class aren't thread-safe unless stated othewise.
 */
class Scheduler : public Pimpl<Scheduler> {
public:
    Scheduler();
    ~Scheduler();

    /**
     * Schedules a new timer to a specific point of time in the future.
     *
     * This method is thread-safe and may be called from any thread. The
     * callback will always be executed on the main thread.
     *
     * @param t time to schedule the timer for
     * @param cb callback to execute when `t` has been reached
     * @returns a unique ID for the scheduled timer, which will remain valid
     * until the timer fires or gets canceled
     */
    timer::ID schedule(Time t, timer::Callback cb);

    /**
     * Enqueues a callback to execute at the next possible opportunity fro the
     * scheduler's thread.
     *
     * This method is thread-safe and may be called from any thread. The
     * callback will always be executed on the main thread.
     *
     * @param cb callback to execute as soon as possible
     */
    void schedule(task::Callback cb);

    /**
     * Cancels a previously installed timer. The timer will be deleted without
     * its callback executing.
     *
     * @param id timer's ID as previously returned by one of the `schedule()`
     * methods; it's ok if the timer already doesn't exist anymore
     */
    void cancel(timer::ID id);

    /**
     * Advances to scheduler's notion of the current time. This will let all
     * timers fire that are currently scheduled for a time <= `now`. Their
     * callbacks will have fully executed before the method returns, and they
     * will run from the same thread as the caller of this method. Advancing
     * will also execute any callbacks scheduled with
     * `registerAdvanceCallback()`.
     *
     * @param t new current time for the scheduler; if `t` is <= `now()`, the
     * method will not do anything
     */
    void advance(Time t);

    /**
     * Returns the scheduler's current time. This is the most recent time
     * passed to `advance().
     */
    Time currentTime() const;

    /**
     * Returns the number of timers/tasks currently scheduled for execution.
     */
    size_t pendingTimers() const;

    /**
     * Request processing to terminate. This will stop
     * `processUntilTerminated()`, but can also act more globally as signal to
     * users of the scheduler to cease operations. They can query the
     * termination state through `terminating()`.
     */
    void terminate();

    /** Returns true if `terminate()` has been called previously. */
    bool terminating() const;

    /**
     * Executes pending activity up to current wall clock. If nothing is
     * pending, blocks for a  little while (with new activity interrupting the
     * block).
     *
     * @return true if processing is to continue; false if the scheduler has
     * been asked to terminate
     */
    bool loop();
};

} // namespace zeek::agent

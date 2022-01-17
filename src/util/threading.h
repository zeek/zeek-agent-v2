// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/helpers.h"

#include <condition_variable>
#include <ctime>
#include <functional>
#include <mutex>

using namespace std::literals::chrono_literals;

namespace zeek::agent {

/**
 * Base class providing a synchronizatun helpers for methods to lock against
 * mutual execution.
 */
class SynchronizedBase {
public:
    /**
     * Class to instantuate to aquire a lock for a given `SynchronizedBase`
     * instance
     **/
    struct Synchronize {
    public:
        Synchronize(const SynchronizedBase* s) : _lock(s->_mutex) {}

    private:
        std::scoped_lock<std::mutex> _lock;
    };

    /** Returns the internal mutex for testing purposes. */
    auto& mutex() const { return _mutex; };

    /** Executes a callable with the mutex unlocked, and then reaquired. */
    template<typename Body>
    auto unlockWhile(Body f) {
        _mutex.unlock();
        ScopeGuard _([&]() { _mutex.lock(); });
        return f();
    }

private:
    mutable std::mutex _mutex;
};

/**
 * Wraps a `std::condition_variable` with built-in protection against spurious
 * wakeups.
 */
class ConditionVariable {
public:
    /**
     * Blocks until a different threat sends a notification, unless a timeout
     * is reached first.
     *
     * @param timeout max. time to block; zero for indefinitly
     */
    void wait(Interval timeout = 0s) {
        std::unique_lock<std::mutex> lock(_mutex);

        if ( _notifications > 0 ) {
            --_notifications;
            return;
        }

        if ( timeout > 0s )
            _cv.wait_for(lock, std::chrono::duration<double>(timeout), [this] { return _notifications > 0; });
        else
            _cv.wait(lock, [this] { return _notifications > 0; });

        --_notifications;
    }

    /**
     * Notifies one waiter. This is "sticky", meaning that if a thread starts
     * waiting after the notifcation was flagged, it will still be unblocked if
     * no other thread has grabbed it in the meantime. Call `reset()` to clear
     * any pending notification.
     */
    void notify() {
        std::lock_guard<std::mutex> lock(_mutex);
        ++_notifications;
        _cv.notify_all();
    }

    /** Clears any pending notification. */
    void reset() {
        std::lock_guard<std::mutex> lock(_mutex);
        _notifications = 0;
    }

private:
    std::mutex _mutex;
    std::condition_variable _cv;
    int _notifications = 0;
};

} // namespace zeek::agent

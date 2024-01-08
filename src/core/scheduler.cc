// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "scheduler.h"

#include "logger.h"
#include "util/fmt.h"
#include "util/testing.h"

#include <algorithm>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace zeek::agent;

struct Timer {
    Time due;
    timer::ID id;
    timer::Callback callback;
    bool canceled = false;
};

// Sort timers by their due time.
struct TimerComparator {
    bool operator()(const Timer* t1, const Timer* t2) { return t1->due > t2->due; };
};

template<>
struct Pimpl<Scheduler>::Implementation {
    // Schedules a new timer with corresponding callback.
    timer::ID schedule(timer::ID id, Time t, timer::Callback cb);

    // Cancels a previously added timer.
    void cancel(timer::ID id);

    // Advances the current time, fireing all timers now expired.
    bool advance(Time now);

    // Signals an externally visible state change..
    void updated();

    // Executes scheduled activity up to current wall clock.
    bool loop();

    timer::ID _next_id = 1;    // counter for creating timer IDs
    Time _now = 0_time;        // current time
    bool _terminating = false; // true once termination has been requested; ok to access wo/ lock

    // Mutex/condition variable to provide interruptable sleep.
    std::mutex _loop_mutex;
    std::condition_variable _loop_cv;

    mutable std::mutex
        _timers_mutex; // mutex protecting access to the current set of timers (_timers_by_id and _timers)
    std::unordered_map<timer::ID, Timer> _timers_by_id;                        // maps IDs to their timers
    std::priority_queue<Timer*, std::vector<Timer*>, TimerComparator> _timers; // timers sorted by time
};

timer::ID Scheduler::Implementation::schedule(timer::ID id, Time t, timer::Callback cb) {
    {
        std::scoped_lock lock(_timers_mutex);
        auto timer = Timer{.due = t, .id = id, .callback = std::move(cb)};
        auto x = _timers_by_id.emplace(id, std::move(timer));
        _timers.push(&x.first->second);
    }

    updated();
    return id;
}

void Scheduler::Implementation::cancel(timer::ID id) {
    std::scoped_lock lock(_timers_mutex);

    if ( auto t = _timers_by_id.find(id); t != _timers_by_id.end() )
        // mark as canceled, expiration will eventually delete it
        t->second.canceled = true;
}

bool Scheduler::Implementation::advance(Time now) {
    if ( now > _now )
        _now = now;

    std::unique_lock lock(_timers_mutex);

    while ( _timers.size() && _timers.top()->due <= _now ) {
        auto t = *_timers.top(); // copy it out so that we can remove it before running the callback
        ZEEK_AGENT_DEBUG("scheduler", "expiring {} timer {} scheduled for t={} at now={}",
                         (t.canceled ? "canceled" : "active"), t.id, to_string(t.due), to_string(_now));

        _timers.pop();
        _timers_by_id.erase(t.id);

        if ( ! t.canceled ) {
            // Release lock before running callback
            lock.unlock();

            if ( auto reschedule = t.callback(t.id); reschedule > 0s ) {
                auto due = _now + reschedule;
                ZEEK_AGENT_DEBUG("scheduler", "rescheduling timer {} for t={}", t.id, to_string(due));
                schedule(t.id, due, t.callback);
            }

            lock.lock();
        }
    }

    return true;
}

void Scheduler::Implementation::updated() {
    std::unique_lock<std::mutex> lock(_loop_mutex);
    _loop_cv.notify_all();
}

bool Scheduler::Implementation::loop() {
    if ( _terminating )
        return false;

    {
        std::unique_lock<std::mutex> lock(_loop_mutex);

        Interval timeout = 5s; // max timeout, TODO: make configurable
        {
            std::scoped_lock lock(_timers_mutex);
            if ( ! _timers.empty() )
                timeout =
                    std::min(timeout, std::max(Interval(0s), _timers.top()->due - std::chrono::system_clock::now()));
        }

        if ( timeout > 0s ) {
            ZEEK_AGENT_DEBUG("scheduler", "sleeping with timeout={}", to_string(timeout));
            _loop_cv.wait_for(lock, std::chrono::duration<double>(timeout));
        }
    }

    advance(std::chrono::system_clock::now());
    return ! _terminating;
}

Scheduler::Scheduler() { ZEEK_AGENT_DEBUG("scheduler", "creating instance"); }

Scheduler::~Scheduler() { ZEEK_AGENT_DEBUG("scheduler", "destroying instance"); }

timer::ID Scheduler::schedule(Time t, timer::Callback cb) {
    auto id = pimpl()->schedule(pimpl()->_next_id++, t, std::move(cb));
    ZEEK_AGENT_DEBUG("scheduler", "scheduling timer {} for t={}", id, to_string(t));
    return id;
}

void Scheduler::schedule(task::Callback cb) {
    auto id = pimpl()->schedule(pimpl()->_next_id++, currentTime(), [cb = std::move(cb)](timer::ID) -> Interval {
        cb();
        return Interval(0);
    });

    ZEEK_AGENT_DEBUG("scheduler", "scheduling task {} for immediate execution", id);
    pimpl()->updated();
}

void Scheduler::cancel(timer::ID id) {
    ZEEK_AGENT_DEBUG("scheduler", "canceling timer {}", id);
    pimpl()->cancel(id);
    pimpl()->updated();
}

bool Scheduler::loop() {
    ZEEK_AGENT_DEBUG("scheduler", "executing pending activity");
    return pimpl()->loop();
}

void Scheduler::advance(Time t) {
    ZEEK_AGENT_DEBUG("scheduler", "advancing time to t={}", to_string(t));
    if ( pimpl()->advance(t) )
        pimpl()->updated();
}

void Scheduler::terminate() {
    ZEEK_AGENT_DEBUG("scheduler", "got request to terminate");
    pimpl()->_terminating = true;
    pimpl()->updated();
}

bool Scheduler::terminating() const { return pimpl()->_terminating; }

Time Scheduler::currentTime() const { return pimpl()->_now; }

size_t Scheduler::pendingTimers() const {
    std::scoped_lock lock(pimpl()->_timers_mutex);
    return pimpl()->_timers_by_id.size();
}

TEST_CASE("timer management") {
    SUBCASE("schedule + callback") {
        Scheduler scheduler;
        int execs = 0;

        CHECK_EQ(scheduler.currentTime(), 0_time);
        CHECK_EQ(scheduler.pendingTimers(), 0);

        scheduler.advance(2_time);
        CHECK_EQ(scheduler.currentTime(), 2_time);

        timer::ID id1 = scheduler.schedule(scheduler.currentTime() + 3s, [&](timer::ID id) {
            ++execs;
            CHECK_EQ(id, id1);
            return 0s;
        });

        timer::ID id2 = scheduler.schedule(20_time, [&](timer::ID id) {
            ++execs;
            CHECK_EQ(id, id2);
            return 0s;
        });

        CHECK_EQ(scheduler.pendingTimers(), 2);

        scheduler.advance(3_time);
        CHECK_EQ(scheduler.currentTime(), 3_time);
        CHECK_EQ(scheduler.pendingTimers(), 2);
        CHECK_EQ(execs, 0);

        scheduler.advance(5_time);
        CHECK_EQ(scheduler.currentTime(), 5_time);
        CHECK_EQ(scheduler.pendingTimers(), 1);
        CHECK_EQ(execs, 1);

        scheduler.advance(25_time);
        CHECK_EQ(scheduler.currentTime(), 25_time);
        CHECK_EQ(scheduler.pendingTimers(), 0);
        CHECK_EQ(execs, 2);
    }

    SUBCASE("schedule + callback + reschedule") {
        Scheduler scheduler;
        int execs = 0;

        scheduler.schedule(1_time, [&](timer::ID id) {
            ++execs;
            return execs < 3 ? 2s : 0s;
        });

        CHECK_EQ(scheduler.pendingTimers(), 1);

        scheduler.advance(2_time);
        CHECK_EQ(execs, 1);
        CHECK_EQ(scheduler.pendingTimers(), 1);

        scheduler.advance(4_time);
        CHECK_EQ(execs, 2);
        CHECK_EQ(scheduler.pendingTimers(), 1);

        scheduler.advance(6_time);
        CHECK_EQ(execs, 3);
        CHECK_EQ(scheduler.pendingTimers(), 0);
    }

    SUBCASE("schedule + cancel") {
        Scheduler scheduler;
        int execs = 0;

        timer::ID id1 = scheduler.schedule(5_time, [&](timer::ID /* id */) {
            ++execs;
            return 0s;
        });

        timer::ID id2 = scheduler.schedule(10_time, [&](timer::ID /* id */) {
            ++execs;
            return 0s;
        });

        scheduler.schedule(15_time, [&](timer::ID /* id */) {
            ++execs;
            return 0s;
        });

        scheduler.cancel(id1);
        scheduler.cancel(id2);
        CHECK_EQ(scheduler.pendingTimers(), 3); // not deleted, just marked as cancelled

        scheduler.advance(20_time);
        CHECK_EQ(scheduler.pendingTimers(), 0);
        CHECK_EQ(execs, 1);
    }

    SUBCASE("advance backwards") {
        Scheduler scheduler;
        scheduler.advance(20_time);
        CHECK_EQ(scheduler.currentTime(), 20_time);
        scheduler.advance(10_time);
        CHECK_EQ(scheduler.currentTime(), 20_time);
    }

    SUBCASE("termination") {
        Scheduler scheduler;
        CHECK(! scheduler.terminating());
        scheduler.terminate();
        CHECK(scheduler.terminating());
    }
}

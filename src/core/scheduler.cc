// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "scheduler.h"

#include "logger.h"
#include "util/fmt.h"
#include "util/testing.h"
#include "util/threading.h"

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

    // Runs all update hooks.
    void updated();

    SynchronizedBase* _synchronized =
        nullptr;            // scheduler's synchronizer, so that we can release it for callback execution
    timer::ID _next_id = 1; // counter for creating timer IDs
    Time _now = 0_time;     // current time
    std::unordered_map<timer::ID, Timer> _timers_by_id;                        // maps IDs to their timers
    std::priority_queue<Timer*, std::vector<Timer*>, TimerComparator> _timers; // timers sorted by time
    std::vector<std::function<void()>> _update_callbacks;                      // registered update callbacks
    std::atomic<bool> _terminating; // true once termination has been requested; ok to access wo/ lock
};

timer::ID Scheduler::Implementation::schedule(timer::ID id, Time t, timer::Callback cb) {
    auto timer = Timer{.due = t, .id = id, .callback = std::move(cb)};
    auto x = _timers_by_id.emplace(id, std::move(timer));
    _timers.push(&x.first->second);
    return id;
}

void Scheduler::Implementation::cancel(timer::ID id) {
    if ( auto t = _timers_by_id.find(id); t != _timers_by_id.end() )
        // mark as canceled, expiration will eventually delete it
        t->second.canceled = true;
}

bool Scheduler::Implementation::advance(Time now) {
    if ( now <= _now )
        return false;

    _now = now;

    while ( _timers.size() && _timers.top()->due <= _now ) {
        auto t = std::move(*_timers.top()); // copy it out so that we can remove it before running the callback
        ZEEK_AGENT_DEBUG("scheduler", "expiring {} timer {} scheduled for t={} at now={}",
                         (t.canceled ? "canceled" : "active"), t.id, to_string(t.due), to_string(_now));

        _timers.pop();
        _timers_by_id.erase(t.id);

        if ( ! t.canceled ) {
            // Release lock before running callback, so that that can access the scheduler.
            if ( auto reschedule = _synchronized->unlockWhile([&]() { return t.callback(t.id); }); reschedule > 0s ) {
                auto due = _now + reschedule;
                ZEEK_AGENT_DEBUG("scheduler", "rescheduling timer {} for t={}", t.id, to_string(due));
                schedule(t.id, due, t.callback);
            }
        }
    }

    return true;
}

void Scheduler::Implementation::updated() {
    _synchronized->unlockWhile([&]() {
        for ( const auto& cb : _update_callbacks )
            cb();
    });
}

Scheduler::Scheduler() {
    ZEEK_AGENT_DEBUG("scheduler", "creating instance");
    pimpl()->_synchronized = this;
}

Scheduler::~Scheduler() { ZEEK_AGENT_DEBUG("scheduler", "destroying instance"); }

timer::ID Scheduler::schedule(Time t, timer::Callback cb) {
    Synchronize _(this);
    auto id = pimpl()->schedule(pimpl()->_next_id++, t, std::move(cb));
    ZEEK_AGENT_DEBUG("scheduler", "scheduled timer {} for t={}", id, to_string(t));
    pimpl()->updated();
    return id;
}

void Scheduler::cancel(timer::ID id) {
    Synchronize _(this);
    ZEEK_AGENT_DEBUG("scheduler", "canceling timer {}", id);
    pimpl()->cancel(id);
    pimpl()->updated();
}

void Scheduler::advance(Time t) {
    Synchronize _(this);
    ZEEK_AGENT_DEBUG("scheduler", "advancing time to t={}", to_string(t));
    if ( pimpl()->advance(t) )
        pimpl()->updated();
}

void Scheduler::registerUpdateCallback(std::function<void()> cb) {
    Synchronize _(this);
    pimpl()->_update_callbacks.push_back(std::move(cb));
}

void Scheduler::terminate() {
    Synchronize _(this);
    ZEEK_AGENT_DEBUG("scheduler", "got request to terminate");
    pimpl()->_terminating = true;
    pimpl()->updated();
}

bool Scheduler::terminating() const {
    Synchronize _(this);
    return pimpl()->_terminating;
}

Time Scheduler::currentTime() const {
    Synchronize _(this);
    return pimpl()->_now;
}

Time Scheduler::nextTimer() const {
    Synchronize _(this);
    if ( pimpl()->_timers.empty() )
        return 0_time;
    else
        return pimpl()->_timers.top()->due;
}

size_t Scheduler::pendingTimers() const {
    Synchronize _(this);
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

        CHECK_EQ(scheduler.nextTimer(), 5_time);
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

    SUBCASE("update callback") {
        // Checking all non-const methods here (except callback registration)
        Scheduler scheduler;
        uint64_t counter = 0;
        scheduler.registerUpdateCallback([&]() { counter += 1; });

        scheduler.advance(20_time);
        scheduler.advance(40_time);
        CHECK_EQ(counter, 2);

        auto id = scheduler.schedule(50_time, [](timer::ID) { return 0s; });
        CHECK_EQ(counter, 3);

        scheduler.cancel(id);
        CHECK_EQ(counter, 4);

        scheduler.terminate();
        CHECK_EQ(counter, 5);
    }
}

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "threading.h"

#include "testing.h"

#include <thread>

using namespace zeek::agent;

TEST_SUITE("Threading") {
    TEST_CASE("synchronized") {
        SynchronizedBase sync;
        {
            SynchronizedBase::Synchronize _(&sync);
            CHECK_FALSE(sync.mutex().try_lock());
        }
        CHECK(sync.mutex().try_lock());
    }

    TEST_CASE("condition variable") {
        ConditionVariable cv;

        auto t1 = std::thread([&cv]() { cv.wait(); });
        auto t2 = std::thread([&cv]() { cv.wait(); });
        auto t3 = std::thread([&cv]() { cv.notify(); });
        auto t4 = std::thread([&cv]() { cv.notify(); });
        auto t5 = std::thread([&cv]() { cv.notify(); });
        auto t6 = std::thread([&cv]() { cv.wait(); });
        t1.join();
        t2.join();
        t3.join();
        t4.join();
        t5.join();
        t6.join();

        // can't easily test wating timeout.
    }
}

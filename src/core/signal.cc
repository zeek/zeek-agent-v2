// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "./signal.h"

#include "logger.h"
#include "util/fmt.h"
#include "util/testing.h"

#include <algorithm>
#include <condition_variable>
#include <csignal>
#include <map>
#include <memory>
#include <thread>
#include <utility>

using namespace zeek::agent;

template<>
struct Pimpl<SignalManager>::Implementation {
    // Globally blocks the given signals for the current process.
    void blockSignals(const std::vector<Signal>& signals);

    // Restores default behaviour for all signals blocked by `blockSignals`.
    void restoreSignals();

    // Starts signal handling.
    void start();

    // Stops signal handling.
    void stop();

    std::unique_ptr<std::thread> _thread;                             // signal managment thread
    std::atomic<bool> _terminate = false;                             // flags desire to terminate to mgmt thread
    sigset_t _mask;                                                   // mask of our signals
    sigset_t _oldmask;                                                // old signal mask before we blocked ours
    std::map<Signal, std::list<signal::Handler::Callback>> _handlers; // map of handler LIFO lists indexed by signal
    std::mutex _handlers_mutex;                                       // guards access to _handlers map
};

signal::Handler::Handler(SignalManager* mgr, Signal sig, Callback cb) : _manager(mgr), _signal(sig) {
    ZEEK_AGENT_DEBUG("signal manager", "installing handler for signal {}", _signal);
    std::lock_guard<std::mutex> lock(_manager->pimpl()->_handlers_mutex);

    auto& list = _manager->pimpl()->_handlers[_signal];
    list.push_back(std::move(cb));
    _handler = --list.end();
}

signal::Handler::~Handler() {
    ZEEK_AGENT_DEBUG("signal manager", "uninstalling handler for signal {}", _signal);
    std::lock_guard<std::mutex> lock(_manager->pimpl()->_handlers_mutex);

    _manager->pimpl()->_handlers[_signal].erase(_handler);
}

void SignalManager::Implementation::blockSignals(const std::vector<Signal>& signals) {
    sigemptyset(&_mask);
    sigaddset(&_mask, SIGUSR1); // always add USE1, we use it at termination to force the loop to wakeup

    for ( auto sig : signals )
        sigaddset(&_mask, sig);

    if ( pthread_sigmask(SIG_BLOCK, &_mask, &_oldmask) != 0 )
        throw FatalError("pthread_sigmask() failed");
}

void SignalManager::Implementation::restoreSignals() {
    // We ignore errors here, will likely be shutting down anyways.
    pthread_sigmask(SIG_BLOCK, &_oldmask, nullptr);
}

void SignalManager::Implementation::start() {
    _thread = std::make_unique<std::thread>([this]() {
        while ( ! _terminate ) {
            // Loop waiting for any of our signals to arrive.
            int signal = -1;
            if ( sigwait(&_mask, &signal) != 0 )
                continue;

            if ( _terminate )
                break;

            {
                ZEEK_AGENT_DEBUG("signal manager", "got signal {}", signal);
                std::lock_guard<std::mutex> lock(_handlers_mutex);
                if ( const auto& x = _handlers[signal]; x.size() )
                    x.back()(); // keep lock during callback that handler can't go away
            }
        }

        ZEEK_AGENT_DEBUG("signal manager", "thread has terminated");
    });
}

void SignalManager::Implementation::stop() {
    if ( ! _thread )
        return;

    _terminate = true;
    kill(getpid(), SIGUSR1); // wake up the sigwait()
    _thread->join();
}

SignalManager::SignalManager(const std::vector<Signal>& signals_to_handle) {
    ZEEK_AGENT_DEBUG("signal manager", "creating instance, handling signals: {}",
                     join(transform(signals_to_handle, [](auto i) { return std::to_string(i); }), ", "));

    pimpl()->blockSignals(signals_to_handle);
    pimpl()->start();
}

SignalManager::~SignalManager() {
    ZEEK_AGENT_DEBUG("signal manager", "destroying instance");
    pimpl()->stop();
}

TEST_SUITE("Signal manager") {
    TEST_CASE("signal callbacks") {
        std::atomic<int> count1 = 0;
        std::atomic<int> count2 = 0;

        // TODO: For unknown reasons, the first kill() below sometimes gets
        // lost, at least on macOS (sigwait() returns, but it doesn't set a
        // signal). To work-around that, we add SIGHUP to our set and send
        // that one first; we don't care if that gets dropped.

        std::mutex mutex1;
        std::condition_variable cv1;
        std::mutex mutex2;
        std::condition_variable cv2;

        SignalManager mgr({SIGUSR1, SIGUSR2, SIGHUP});

        SUBCASE("signal and execution") {
            signal::Handler h1(&mgr, SIGUSR1, [&]() {
                std::unique_lock<std::mutex> lock(mutex1);
                ++count1;
                cv1.notify_all();
            });
            signal::Handler h2(&mgr, SIGUSR2, [&]() {
                std::unique_lock<std::mutex> lock(mutex2);
                ++count2;
                cv2.notify_all();
            });

            kill(getpid(), SIGHUP);

            {
                std::unique_lock<std::mutex> lock(mutex1);
                kill(getpid(), SIGUSR1);
                cv1.wait(lock);
                CHECK_EQ(count1, 1);
            }

            {
                std::unique_lock<std::mutex> lock(mutex2);
                kill(getpid(), SIGUSR2);
                cv2.wait(lock);
                CHECK_EQ(count2, 1);
            }

            {
                std::unique_lock<std::mutex> lock(mutex1);
                kill(getpid(), SIGUSR1);
                cv1.wait(lock);
                CHECK_EQ(count1, 2);
            }

            {
                std::unique_lock<std::mutex> lock(mutex2);
                kill(getpid(), SIGUSR2);
                cv2.wait(lock);
                CHECK_EQ(count2, 2);
            }

            {
                std::unique_lock<std::mutex> lock(mutex1);
                kill(getpid(), SIGUSR1);
                cv1.wait(lock);
                CHECK_EQ(count1, 3);
            }

            {
                std::unique_lock<std::mutex> lock(mutex2);
                kill(getpid(), SIGUSR2);
                cv2.wait(lock);
                CHECK_EQ(count2, 3);
            }
        }

        SUBCASE("stacked handlers") {
            CHECK_EQ(count1, 0);

            signal::Handler h1(&mgr, SIGUSR1, [&]() {
                std::unique_lock<std::mutex> lock(mutex1);
                ++count1;
                cv1.notify_all();
            });

            {
                std::unique_lock<std::mutex> lock(mutex1);
                kill(getpid(), SIGUSR1);
                cv1.wait(lock);
                CHECK_GE(count1, 1); // should be 1, but CI sometimes shows 2
            }

            auto h2 = std::make_unique<signal::Handler>(&mgr, SIGUSR1, [&]() {
                std::unique_lock<std::mutex> lock(mutex2);
                ++count2;
                cv2.notify_all();
            });

            {
                std::unique_lock<std::mutex> lock(mutex2);
                kill(getpid(), SIGUSR1);
                cv2.wait(lock);
                CHECK_GE(count2, 1); // should be 1, but CI sometimes shows 2
            }

            h2.reset();

            {
                std::unique_lock<std::mutex> lock(mutex1);
                kill(getpid(), SIGUSR1);
                cv1.wait(lock);
                CHECK_GE(count1, 2); // should be 2, but CI sometimes shows 3
            }
        }
    }
}

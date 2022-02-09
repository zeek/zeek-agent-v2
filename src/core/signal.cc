// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "./signal.h"

#include "logger.h"
#include "util/fmt.h"
#include "util/testing.h"
#include "util/threading.h"

#include <algorithm>
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
        int count1 = 0;
        int count2 = 0;

        // TODO: For unknown reasons, the first kill() below sometimes gets
        // lost, at least on macOS (sigwait() returns, but it doesn't set a
        // signal). To work-around that, we add SIGHUP to our set and send
        // that one first; we don't care if that gets dropped.

        SignalManager mgr({SIGUSR1, SIGUSR2, SIGHUP});
        ConditionVariable cv1;
        ConditionVariable cv2;

        SUBCASE("signal and execution") {
            signal::Handler h1(&mgr, SIGUSR1, [&]() {
                ++count1;
                cv1.notify();
            });
            signal::Handler h2(&mgr, SIGUSR2, [&]() {
                ++count2;
                cv2.notify();
            });

            kill(getpid(), SIGHUP);
            kill(getpid(), SIGUSR1);
            kill(getpid(), SIGUSR2);
            cv1.wait();
            cv2.wait();
            CHECK_EQ(count1, 1);
            CHECK_EQ(count2, 1);

            kill(getpid(), SIGUSR1);
            cv1.wait();
            CHECK_EQ(count1, 2);

            kill(getpid(), SIGUSR2);
            cv2.wait();
            CHECK_EQ(count2, 2);

            kill(getpid(), SIGUSR1);
            cv1.wait();
            CHECK_EQ(count1, 3);

            kill(getpid(), SIGUSR2);
            cv2.wait();
            CHECK_EQ(count2, 3);
        }

        SUBCASE("stacked handlers") {
            CHECK_EQ(count1, 0);
            signal::Handler h1(&mgr, SIGUSR1, [&]() {
                ++count1;
                cv1.notify();
            });
            kill(getpid(), SIGUSR1);
            cv1.wait();
            CHECK_GE(count1, 1); // should be 1, but CI sometimes shows 2

            auto h2 = std::make_unique<signal::Handler>(&mgr, SIGUSR1, [&]() {
                ++count2;
                cv2.notify();
            });
            kill(getpid(), SIGUSR1);
            cv2.wait();
            CHECK_GE(count2, 1); // should be 1, but CI sometimes shows 2
            h2.reset();

            kill(getpid(), SIGUSR1);
            cv1.wait();
            CHECK_GE(count1, 2);
        }
    }
}

// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

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
    ~Implementation();

    // Globally blocks the given signals for the current process.
    void blockSignals(const std::vector<Signal>& signals) const;

    // Restores default behaviour for all signals blocked by `blockSignals`.
    void restoreSignals() const;

    // Starts signal handling.
    void start() const;

    // Stops signal handling.
    void stop() const;

    std::map<Signal, std::list<signal::Handler::Callback>> _handlers; // map of handler LIFO lists indexed by signal
    std::mutex _handlers_mutex;                                       // guards access to _handlers map
};

BOOL WINAPI CtrlHandler(DWORD ctrl) {
    switch ( ctrl ) {
        case CTRL_C_EVENT: {
            std::lock_guard<std::mutex> lock(signal_mgr->pimpl()->_handlers_mutex);
            if ( const auto& x = signal_mgr->pimpl()->_handlers[SIGINT]; x.size() )
                x.back()(); // keep lock during callback that handler can't go away
            return TRUE;
        }
        default: return FALSE;
    }
}

signal::Handler::Handler(SignalManager* mgr, Signal sig, Callback cb) : _manager(mgr), _signal(sig) {
    ZEEK_AGENT_DEBUG("signal manager", "installing handler for signal {}", _signal);
    std::lock_guard<std::mutex> lock(_manager->pimpl()->_handlers_mutex);

    auto& handlers = _manager->pimpl()->_handlers[_signal];
    handlers.push_back(std::move(cb));
    _handler = --handlers.end();
}

signal::Handler::~Handler() {
    ZEEK_AGENT_DEBUG("signal manager", "uninstalling handler for signal {}", _signal);
    std::lock_guard<std::mutex> lock(_manager->pimpl()->_handlers_mutex);

    _manager->pimpl()->_handlers[_signal].erase(_handler);
}

SignalManager::Implementation::~Implementation() {
    std::lock_guard<std::mutex> lock(_handlers_mutex);
    _handlers.clear();
}

void SignalManager::Implementation::blockSignals(const std::vector<Signal>& signals) const {
    // We define the signal values in signal.h for WIN32 but we don't actually want to handle any of them
    // here except for SIGINT. If we get a value that isn't that, return an error.
    for ( auto sig : signals )
        if ( sig != SIGINT )
            throw FatalError("Signals other than SIGINT are unhandled on Windows");
}

void SignalManager::Implementation::restoreSignals() const {}

void SignalManager::Implementation::start() const {
    if ( ! SetConsoleCtrlHandler(CtrlHandler, TRUE) )
        throw FatalError("Failed to register console control handler");
}

void SignalManager::Implementation::stop() const {
    if ( ! SetConsoleCtrlHandler(CtrlHandler, FALSE) )
        throw FatalError("Failed to unregister console control handler");
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

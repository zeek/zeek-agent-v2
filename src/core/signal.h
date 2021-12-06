// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/pimpl.h"

#include <functional>
#include <list>
#include <vector>

namespace zeek::agent {
// Signal number, specified through the standard `SIGxxx` macros
using Signal = int;

class SignalManager;

namespace signal {

class Handler {
public:
    using Callback = std::function<void()>;

    /**
     * Constructor. Instantiates a handler and registers it with a manager for
     * handling a specified signal. The handler will remain active during its
     * entire life-time and unregster itself at destruction time.
     *
     * @param mgr manager to register the handler with
     * @param signal signal number, which must be part of the set the manager was asked to handle
     * @param cb callback to execute when manager receives signal
     */
    Handler(SignalManager* mgr, Signal sig, Callback cb);
    ~Handler();

private:
    SignalManager* _manager;
    Signal _signal;
    std::list<Callback>::iterator _handler; // position of handler in manager's list
};
} // namespace signal

/**
 * Manages Unix signal handling by keeping a registry of signal handlers to
 * dispatch to when receiving a signal. To register a handler, instantiate it
 * with the manager as an argument. If multiple handlers are registered for the
 * same signal, the most recent one will receive control when the signal fires.
 *
 * A manager assumes that it's the only one manipulating signal behaviour for
 * the current process. That implies that no two managers should exist at the
 * same time.
 **/
class SignalManager : public Pimpl<SignalManager> {
public:
    /**
     * Constructor.
     *
     * @param set of signals that this manager is to (exclusively) handle
     */
    SignalManager(std::vector<Signal> signals_to_handle);
    ~SignalManager();
};

} // namespace zeek::agent

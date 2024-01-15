// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"
#include "platform/darwin/platform.h"
#include "util/pimpl.h"
#include "util/result.h"

#include <list>
#include <memory>
#include <string>
#include <utility>

namespace zeek::agent::platform::darwin {

class NetworkExtension;

namespace ne {

struct Flow {
    pid_t pid;
    ProcessInfo process;

    Value local_addr;
    Value local_port;
    Value remote_addr;
    Value remote_port;
    Value protocol;
    Value family;
    Value state;
};

/**
 * State for an active subscription to NetworkExtension events. An instance of
 * this class is creating when subscribing to NE events, and the subscription
 * is kept active as long as the instance exists.
 */
class Subscriber {
public:
    using Callback = std::function<void(const Flow& flow)>;

    ~Subscriber();

private:
    friend class darwin::NetworkExtension;
    Subscriber(NetworkExtension* ne, std::string tag, Callback cb)
        : _ne(ne), _tag(std::move(tag)), _callback(std::move(cb)) {}

    NetworkExtension* _ne;
    std::string _tag;
    Callback _callback;
};

} // namespace ne

/**
 * Wrapper around macOS's Network Extension API. This encapsulates API state
 * across multiple clients, maintaining just a single internal copy.
 */
class NetworkExtension : public Pimpl<NetworkExtension> {
public:
    using Callback = ne::Subscriber::Callback;

    ~NetworkExtension();

    /**
     * Returns success if the Network Extension has been initialized
     * successfully, or an error otherwise.
     *
     * @returns success or an appropriate error message if NE isn't
     * available; then no functionality must be used
     */
    Result<Nothing> isAvailable();

    /**
     * Creates a subscription to EndpointSecurity events.
     *
     * @param tag descriptive tag identifying the subscription in log messages
     *
     * @param callback callback to invoke when an event is received
     *
     * @returns a subscription object that keeps the subscription active as long as it exists
     */
    std::unique_ptr<ne::Subscriber> subscribe(std::string tag, Callback callback);

    void newFlow(const ne::Flow& flow);

private:
    friend ne::Subscriber;
    friend NetworkExtension* networkExtension();

    NetworkExtension();

    std::list<ne::Subscriber*> _subscribers;
};

/** Returns the global `NetworkExtension` singleton. */
NetworkExtension* networkExtension();

/**
 * Start operating as a macOS network extension. Must be called from the main
 * thread as early as possible, and will not return.
 */
[[noreturn]] extern void enterNetworkExtensionMode();

} // namespace zeek::agent::platform::darwin

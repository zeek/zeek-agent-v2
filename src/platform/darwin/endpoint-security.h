// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/result.h"

#include <memory>
#include <string>
#include <vector>

#include <EndpointSecurity/EndpointSecurity.h>

namespace zeek::agent::platform::darwin {

class EndpointSecurity;

namespace es {

/**
 * State for an active subscription to EndpointSecurity events. An instance of
 * this class is creating when subscribing to ES events, and the subscription
 * is kept active as long as the instance exists.
 */
class Subscriber {
public:
    ~Subscriber();

private:
    friend class darwin::EndpointSecurity;
    Subscriber(std::string tag, es_client_t* client);

    std::string _tag;
    es_client_t* _client = nullptr;
};

} // namespace es

/**
 * Wrapper around macOS's Endpoint Security API. This encapsulates API state
 * across multiple clients, maintaining just a single internal copy.
 */
class EndpointSecurity {
public:
    using Events = std::vector<es_event_type_t>;
    using Callback = std::function<void(const es_message_t*)>;

    ~EndpointSecurity();

    /**
     * Returns success if EndpointSecurity is available for use, or a error
     * otherwise describibing why it's not.
     *
     * @returns success or an appropiate error message if ES isn't available;
     * then no functionlity must be used
     */
    Result<Nothing> isAvailable() { return _init_result; }

    /**
     * Creates a subscription to EndpointSecurity events.
     *
     * @param tag descriptive tag identifying the subscription in log messages
     *
     * @param events set of events to subscribe to; see
     * https://developer.apple.com/documentation/endpointsecurity/es_event_type_t for the list
     *
     * @param callback callback to invoke when an event is received
     *
     * @returns a subscription objects that keeps the subscription active as long as it exists, or an error if the
     * subscription could not be created
     */
    Result<std::unique_ptr<es::Subscriber>> subscribe(std::string tag, const Events& events, Callback callback);

private:
    friend EndpointSecurity* endpointSecurity();

    EndpointSecurity();

    Result<Nothing> _init_result; // caches result of `isAvailable()`
};

/** Returns the global `EndpointSecurity` singleton. */
EndpointSecurity* endpointSecurity();

} // namespace zeek::agent::platform::darwin

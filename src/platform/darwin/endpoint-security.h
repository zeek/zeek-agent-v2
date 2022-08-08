// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/pimpl.h"
#include "util/result.h"

namespace zeek::agent::platform::darwin {

/**
 * Wrapper around macOS's Endpoint Security API. This encapsulates API state
 * across multiple clients, maintaining just a single internal copy.
 */
class EndpointSecurity : public Pimpl<EndpointSecurity> {
public:
    ~EndpointSecurity();

    /**
     * Returns success if EndpointSecurity has been initialized successfully,
     * or an error otherwise.
     *
     * @returns success or an appropiate error message if ES isn't available;
     * then no functionlity must be used
     */
    Result<Nothing> isAvailable();

private:
    friend EndpointSecurity* endpointSecurity();
    EndpointSecurity();
};

/** Returns the global `EndpointSecurity` singleton. */
EndpointSecurity* endpointSecurity();

} // namespace zeek::agent::platform::darwin

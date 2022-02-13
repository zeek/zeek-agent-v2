// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "pimpl.h"
#include "result.h"

namespace zeek::agent::platform::darwin {

/**
 * Wrapper around macOS's Endpoint Security API. This encapsulates API state
 * across multiple clients, maintaining just single internal copy.
 */
class EndpointSecurity : public Pimpl<EndpointSecurity> {
public:
    EndpointSecurity();
    ~EndpointSecurity();

    /**
     * Initializes the OS-side EndpointSecurity system. Must be called before
     * any other functionality. This is safe against multiple invocations,
     * it'll be a noop if already initialized.
     *
     * @returns appropiate error message if ES isn't available; then no
     * functionlity must be used
     */
    Result<Nothing> init();

    /**
     * Shuts down the OS-side EndpointSecurity system. This is safe against
     * multiple invocations, it'll be a noop if not yet (and not anymore) initializes.
     */
    void done();
};

} // namespace zeek::agent::platform::darwin

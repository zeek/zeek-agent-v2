// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/pimpl.h"
#include "util/result.h"

namespace zeek::agent::platform::darwin {

/**
 * Wrapper around macOS's Network Extension API. This encapsulates API state
 * across multiple clients, maintaining just a single internal copy.
 */
class NetworkExtension : public Pimpl<NetworkExtension> {
public:
    ~NetworkExtension();

    /**
     * Returns success if the Network Extension has been initialized
     * successfully, or an error otherwise.
     *
     * @returns success or an appropiate error message if NE isn't available;
     * then no functionlity must be used
     */
    Result<Nothing> isAvailable();

private:
    friend NetworkExtension* networkExtension();
    NetworkExtension();
};

/** Returns the global `NetworkExtension` singleton. */
NetworkExtension* networkExtension();

/**
 * Start operating as a macOS network extension. Must be called from the main
 * thread as early as possible, and will not return.
 */
[[noreturn]] extern void enterNetworkExtensionMode();

} // namespace zeek::agent::platform::darwin

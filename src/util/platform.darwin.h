// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "pimpl.h"
#include "result.h"

#include <mutex>

#include <os/log.h>
#include <spdlog/sinks/base_sink.h>
#include <util/filesystem.h>

namespace zeek::agent::platform::darwin {

/**
 * Start operating as a macOS network extension. Must be called from the main
 * thread as early as possible, and will not return.
 */
[[noreturn]] extern void enterSystemExtensionMode();

/**
 * Returns the path to the `App[lication Support` directory appropiate for the
 * user running the agent (which might be the system-wide one for root).
 */
extern std::optional<filesystem::path> getApplicationSupport();

/** Custom spdlog sink writing is OSLog. */
class OSLogSink : public spdlog::sinks::base_sink<std::mutex> {
public:
    OSLogSink();
    ~OSLogSink() final;

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override;
    void flush_() override;

private:
    os_log_t _oslog = nullptr;
};

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

/** Returns global `EndpointSecurity` singleton. */
EndpointSecurity* endpointSecurity();


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

/** Returns global `NetworkExtension` singleton. */
NetworkExtension* networkExtension();


} // namespace zeek::agent::platform::darwin

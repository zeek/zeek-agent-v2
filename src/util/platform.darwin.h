// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "pimpl.h"
#include "result.h"

#include <mutex>

#include <os/log.h>
#include <spdlog/sinks/base_sink.h>
#include <util/filesystem.h>

namespace zeek::agent::platform::darwin {

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

class EndpointSecurity;

/** Returns global ES singleton */
EndpointSecurity* endpointSecurity();

/**
 * Wrapper around macOS's Endpoint Security API. This encapsulates API state
 * across multiple clients, maintaining just single internal copy.
 */
class EndpointSecurity : public Pimpl<EndpointSecurity> {
public:
    ~EndpointSecurity();

    /**
     * Returns success after `init()` has been eable to initialize
     * EndpointSecurity successfully, or an error otherwise.
     *
     * @returns success or an appropiate error message if ES isn't available;
     * then no functionlity must be used
     */
    Result<Nothing> isAvailable();

private:
    friend EndpointSecurity* endpointSecurity();
    EndpointSecurity();
};


} // namespace zeek::agent::platform::darwin

// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include <mutex>

#include <os/log.h>
#include <spdlog/sinks/base_sink.h>

namespace zeek::agent::platform::darwin {

/** Custom spdlog sink writing to OSLog. */
class OSLogSink final : public spdlog::sinks::base_sink<std::mutex> {
public:
    OSLogSink();
    ~OSLogSink() override;

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override;
    void flush_() override;

private:
    os_log_t _oslog = nullptr;
};

} // namespace zeek::agent::platform::darwin

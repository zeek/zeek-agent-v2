// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "os-log-sink.h"

#include "autogen/config.h"
#include "core/logger.h"

#include <Foundation/Foundation.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

OSLogSink::OSLogSink() { _oslog = os_log_create("org.zeek.zeek-agent", "agent"); }

OSLogSink::~OSLogSink() {
    if ( _oslog )
        CFRelease(_oslog);
}

void OSLogSink::sink_it_(const spdlog::details::log_msg& msg) {
    std::string formatted = std::string(msg.payload.data(), msg.payload.size());
    os_log_type_t level;

    switch ( msg.level ) {
        case spdlog::level::critical: level = OS_LOG_TYPE_ERROR; break;
        case spdlog::level::debug: level = OS_LOG_TYPE_DEBUG; break;
        case spdlog::level::err: level = OS_LOG_TYPE_ERROR; break;
        case spdlog::level::info: level = OS_LOG_TYPE_INFO; break;
        case spdlog::level::n_levels: cannot_be_reached();
        case spdlog::level::off: return;
        case spdlog::level::trace: level = OS_LOG_TYPE_DEBUG; break;
        case spdlog::level::warn: level = OS_LOG_TYPE_INFO; break;
    }

    auto log_msg = std::string(msg.payload.data(), msg.payload.size());
    auto log_level = std::string(to_string_view(msg.level).data(), to_string_view(msg.level).size());
    os_log_with_type(_oslog, level, "[%{public}s] %{public}s", log_level.c_str(), log_msg.c_str());
}

void OSLogSink::flush_() {}

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "logger.h"

#include "autogen/config.h"
#include "core/configuration.h"

#include <memory>
#include <utility>

#include <spdlog/common.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/stdout_sinks-inl.h>
#include <spdlog/sinks/syslog_sink.h>

using namespace zeek::agent;

namespace {
std::shared_ptr<spdlog::logger> global_logger = {};
}

Result<Nothing> zeek::agent::setGlobalLogger(options::LogType type, options::LogLevel level,
                                             const std::optional<filesystem::path>& path) {
    spdlog::sink_ptr sink{};

    // Note we are creating thread-safe logger here (`*_mt`).
    switch ( type ) {
        case options::LogType::Stdout:
            if ( isatty(STDOUT_FILENO) )
                sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            else
                sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();

            break;

        case options::LogType::System:
#ifdef HAVE_LINUX
            sink = std::make_shared<spdlog::sinks::syslog_sink_mt>("zeek-agent", 0, LOG_USER, false);
#else
#ifdef HAVE_DARWIN
            // TODO: Should log directly to oslog here. Use
            // https://github.com/L1MeN9Yu/Senna? Roll our own sink?
            sink = std::make_shared<spdlog::sinks::syslog_sink_mt>("zeek-agent", 0, LOG_USER, false);
#else
#error "Unsupported platform in setGlobalLogger()"
#endif
#endif
            break;

        case options::LogType::File:
            if ( ! path )
                return result::Error("file logging requires a path");

            sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->native());
    }

    global_logger = std::make_shared<spdlog::logger>("Zeek Agent", std::move(sink));
    global_logger->set_level(level);

    return Nothing();
}

spdlog::logger* zeek::agent::logger() {
    if ( ! global_logger )
        // Default until something else is set.
        setGlobalLogger(options::LogType::Stdout, options::default_log_level);

    return global_logger.get();
}

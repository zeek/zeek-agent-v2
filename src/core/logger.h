// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/configuration.h"

#include <spdlog/spdlog.h>

namespace zeek::agent {

Result<Nothing> setGlobalLogger(options::LogType type, options::LogLevel level,
                                const std::optional<filesystem::path>& path = {});

/** Returns the global logger instance. Use of the logger is thread-safe. */
extern spdlog::logger* logger();

#define __ZEEK_AGENT_LOG(level, component, ...) /* NOLINT */                                                           \
    logger()->debug(::zeek::agent::format("[{}] ", component) + ::zeek::agent::format(__VA_ARGS__))

#ifndef NDEBUG
#define ZEEK_AGENT_DEBUG(component, ...) __ZEEK_AGENT_LOG(debug, component, __VA_ARGS__)
#define ZEEK_AGENT_TRACE(component, ...)
#else
#define ZEEK_AGENT_DEBUG(component, ...) __ZEEK_AGENT_LOG(debug, component, __VA_ARGS__)
#define ZEEK_AGENT_TRACE(component, ...) __ZEEK_AGENT_LOG(trace, component, __VA_ARGS__)
#endif

} // namespace zeek::agent

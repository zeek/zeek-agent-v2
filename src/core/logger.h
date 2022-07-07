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
    logger()->log(level, frmt("[{}] ", component) + frmt(__VA_ARGS__))

#ifndef NDEBUG
#define ZEEK_AGENT_DEBUG(component, ...) __ZEEK_AGENT_LOG(spdlog::level::debug, component, __VA_ARGS__)
#define ZEEK_AGENT_TRACE(component, ...) __ZEEK_AGENT_LOG(spdlog::level::trace, component, __VA_ARGS__)
#else
#define ZEEK_AGENT_DEBUG(component, ...) __ZEEK_AGENT_LOG(spdlog::level::debug, component, __VA_ARGS__)
#define ZEEK_AGENT_TRACE(component, ...)
#endif

} // namespace zeek::agent

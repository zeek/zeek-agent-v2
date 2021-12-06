// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "logger.h"

#include "core/configuration.h"

#include <memory>

#include <spdlog/common.h>
#include <spdlog/sinks/stdout_color_sinks.h>

using namespace zeek::agent;

spdlog::logger* zeek::agent::logger() {
    static std::shared_ptr<spdlog::logger> _logger;

    if ( ! _logger ) {
        _logger = spdlog::stdout_color_mt("Zeek Agent"); // thread-safe version
        _logger->set_level(options::default_log_level);  // default level, configuration may reconfigure
    }

    return _logger.get();
}

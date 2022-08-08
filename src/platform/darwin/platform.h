// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>

#include <util/filesystem.h>

namespace zeek::agent::platform::darwin {

/**
 * Returns the path to the `App[lication Support` directory appropiate for the
 * user running the agent (which might be the system-wide one for root).
 */
extern std::optional<filesystem::path> getApplicationSupport();

} // namespace zeek::agent::platform::darwin

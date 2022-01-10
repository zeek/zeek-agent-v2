// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "filesystem.h"

#include <optional>
#include <string>
#include <vector>

namespace zeek::agent::platform {

/** Returns a name for the current platform. */
extern std::string name();

/** Returns the path to the default configuration file. */
extern filesystem::path configurationFile();

/** Returns the directory path where to store dynamic, persistent state. */
extern filesystem::path dataDirectory();

/** Returns true if stdin is a terminal. */
extern bool isTTY();

/**
 * Expands shell-style globs to return all existing paths mattern any of a set
 * of globs, up to a given maximum number.
 */
extern std::vector<filesystem::path> glob(const std::vector<filesystem::path>& patterns, size_t max = 100);

} // namespace zeek::agent::platform

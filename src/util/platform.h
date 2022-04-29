// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/configuration.h"
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
 * Expands a shell-style glob to return all existing paths matching it, up to a
 * given maximum number.
 */
extern std::vector<filesystem::path> glob(const filesystem::path& pattern, size_t max = 100);

/**
 * Platform specific-implementation of setenv(). Follows the same semantics as
 * POSIX's setenv() on all platforms.
 */
extern int setenv(const char* name, const char* value, int overwrite);

/**
 * Gets a variable from the environment, returning an unset optional if the
 * variable isn't set.
 */
extern std::optional<std::string> getenv(const std::string& name);

/**
 * Checks for whether the process is running with administrator rights.
 */
extern bool runningAsAdmin();

/**
 * Prepopulates an option object with defaults derived from platform-specific
 * mechanisms.
 */
extern void initializeOptions(Options* options);

/**
 * Retrieves the value of an option through platform-specific means. For array
 * values, the expectation is that the elements are returned as comma-separated
 * string.
 *
 * @param path option's key path as in the TOML file
 * @returns the option's value, if set
 */
extern std::optional<std::string> retrieveConfigurationOption(const std::string& path);

} // namespace zeek::agent::platform

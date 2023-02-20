// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/configuration.h"
#include "util/filesystem.h"

#ifdef HAVE_DARWIN
#include "darwin/platform.h"
#endif

#ifdef HAVE_LINUX
#include "linux/platform.h"
#endif

#ifdef HAVE_WINDOWS
#include "windows/platform.h"
#endif

#include <optional>
#include <string>
#include <vector>

namespace zeek::agent::platform {

/** Performs one-time initialization at startup. */
extern void init(Configuration* cfg);

/** Performs one-time cleanup at shutdown. */
extern void done();

/** Returns a name for the current platform. */
extern std::string name();

/** Returns the path to the default configuration file. */
extern std::optional<filesystem::path> configurationFile();

/** Returns the directory path where to store dynamic, persistent state. */
extern std::optional<filesystem::path> dataDirectory();

/** Returns true if stdin is a terminal. */
extern bool isTTY();

/**
 * Platform specific-implementation of setenv(). Follows the same semantics as
 * POSIX's setenv() on all platforms.
 */
extern Result<Nothing> setenv(const char* name, const char* value, int overwrite);

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

} // namespace zeek::agent::platform

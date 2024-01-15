// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>

#include <util/filesystem.h>

namespace zeek::agent::platform::linux {

/** Returns the kernel version as "major * 100 + minor". */
extern unsigned int kernelVersion();

} // namespace zeek::agent::platform::linux

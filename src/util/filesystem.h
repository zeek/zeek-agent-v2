// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "autogen/config.h"

#include <string>

#include <ghc/filesystem.hpp>

/** Type alias. */
namespace filesystem = ghc::filesystem;

namespace zeek::agent {

#ifdef HAVE_WINDOWS
namespace platform::windows {
std::string narrowWstring(const std::wstring& wstr); // provided by platform.cc
} // namespace platform::windows
inline std::string path_to_string(const filesystem::path& p) { return platform::windows::narrowWstring(p.native()); }
#else
inline std::string path_to_string(const filesystem::path& p) { return p.native(); }
#endif

} // namespace zeek::agent

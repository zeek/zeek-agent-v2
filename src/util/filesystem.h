// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "autogen/config.h"

#include <string>

#include <ghc/filesystem.hpp>
#include <spdlog/common.h>

/** Type alias. */
namespace filesystem = ghc::filesystem;

namespace zeek::agent {

#ifdef HAVE_WINDOWS
namespace platform::windows {
std::string narrowWstring(const std::wstring& wstr); // provided by platform.cc
} // namespace platform::windows
inline std::string path_to_string(const filesystem::path& p) { return platform::windows::narrowWstring(p.native()); }
inline spdlog::filename_t path_to_spdlog_filename(const filesystem::path& p) { return p.wstring(); }
#else
inline std::string path_to_string(const filesystem::path& p) { return p.native(); }
inline spdlog::filename_t path_to_spdlog_filename(const filesystem::path& p) { return p.string(); }
#endif

} // namespace zeek::agent

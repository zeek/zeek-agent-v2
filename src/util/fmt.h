// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <type_traits>
#include <utility>

#include <fmt/core.h>
#include <fmt/xchar.h>

namespace zeek::agent {

/** Forwards to `fmt::format()`. */
template<typename... Args>
auto frmt(fmt::format_string<Args...> format, Args&&... args) {
    return ::fmt::format(format, std::forward<Args>(args)...);
}

/** Forwards to `fmt::format()`. */
template<typename... Args>
auto frmt(const wchar_t* format, Args&&... args) {
    return ::fmt::format(format, std::forward<Args>(args)...);
}

/** Renders class instances through their `str()` method. */
template<class T>
std::string to_string(const T& t) {
    return t.str();
}

/** Fallback for strings. */
inline std::string to_string(const std::string& s) { return s; }

} // namespace zeek::agent

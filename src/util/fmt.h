// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <type_traits>

#include <fmt/core.h>

namespace zeek::agent {

/** Forwards to `fmt::format()`. */
template<typename... Args>
auto format(const Args&... args) {
    return ::fmt::format(args...);
}

/** Renders class instances through their `str()` method. */
template<class T>
std::string to_string(const T& t) {
    return t.str();
}

} // namespace zeek::agent

// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "util/filesystem.h"

#include <string>
#include <type_traits>
#include <utility>

#include <fmt/core.h>
#include <fmt/xchar.h>
#include <nlohmann/json.hpp>

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

/** Renders class instances through their `str()` method. */
template<>
inline std::string to_string(const filesystem::path& t) {
    return zeek::agent::path_to_string(t);
}

/** Fallback for strings. */
inline std::string to_string(const std::string& s) { return s; }

} // namespace zeek::agent

template<>
struct fmt::formatter<nlohmann::json> : fmt::formatter<std::string> {
    auto format(const nlohmann::json& json, format_context& ctx) const -> decltype(ctx.out()) {
        return fmt::format_to(ctx.out(), "{}", json.dump());
    }
};

template<>
struct fmt::formatter<filesystem::path> : fmt::formatter<std::string> {
    auto format(const filesystem::path& p, format_context& ctx) const -> decltype(ctx.out()) {
        return fmt::format_to(ctx.out(), "{}", zeek::agent::path_to_string(p));
    }
};

template<>
struct fmt::formatter<wchar_t> : fmt::formatter<std::string> {
    auto format(const wchar_t& c, format_context& ctx) const -> decltype(ctx.out()) {
        return fmt::format_to(ctx.out(), L"{}", c);
    }
};

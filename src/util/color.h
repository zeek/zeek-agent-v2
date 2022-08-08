// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "platform/platform.h"

#include <string>
#include <utility>

namespace zeek::agent {

namespace detail {
// Helper to insert escape sequence only if connection to terminal.
inline std::string ansi(const char* escape, std::string x) {
    if ( platform::isTTY() )
        return std::string(escape) + std::move(x) + std::string("\033[0m");
    else
        return x;
}
} // namespace detail

namespace color {
/**< Returns ANSI escape sequence to print text in gray, if connected to terminal. */
inline std::string gray(std::string txt) { return detail::ansi("\033[30m", std::move(txt)); }

/**< Returns ANSI escape sequence to print text in green, if connected to terminal. */
inline std::string green(std::string txt) { return detail::ansi("\033[32m", std::move(txt)); }

/**< Returns ANSI escape sequence to print text in standard color, if connected to terminal. */
inline std::string normal(std::string txt) { return txt; }

/**< Returns ANSI escape sequence to print text in red, if connected to terminal. */
inline std::string red(std::string txt) { return detail::ansi("\033[31m", std::move(txt)); }

/**< Returns ANSI escape sequence to print text in yellow, if connected to terminal. */
inline std::string yellow(std::string txt) { return detail::ansi("\033[33m", std::move(txt)); }

}; // namespace color

} // namespace zeek::agent

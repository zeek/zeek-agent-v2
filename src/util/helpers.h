// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "autogen/config.h"
#include "util/fmt.h"
#include "util/result.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <iomanip>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std::literals::chrono_literals;

namespace zeek::agent {

/**
 * Helper class providing a scope-guard that will execute a lambda function on
 * destruction.
 */
class ScopeGuard {
public:
    using Callback = std::function<void()>;
    ScopeGuard(Callback cb) : _callback(std::move(cb)) {}
    ~ScopeGuard() { _callback(); } // NOLINT(bugprone-exception-escape)

    ScopeGuard(const ScopeGuard& other) = delete;
    ScopeGuard(ScopeGuard&& other) = delete;
    ScopeGuard& operator=(const ScopeGuard& other) = delete;
    ScopeGuard& operator=(ScopeGuard&& other) = delete;

private:
    Callback _callback;
};

/** Exception to signal an internal logic error. */
class InternalError : public std::logic_error {
public:
    using std::logic_error::logic_error;
};

/** Exception to signal a fatal error that requires process termination. */
class FatalError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/** Typedef defining out notion of time. */
using Time = std::chrono::time_point<std::chrono::system_clock>;

/** Typedef defining out notion of a time interval. */
using Interval = Time::duration;

/** Converts an seconds-since-epoch timestamp into our time type. */
constexpr Time to_time(uint64_t t) { return std::chrono::system_clock::time_point(std::chrono::seconds(t)); }

/** Converts an seconds value into our interval type. */
constexpr Interval to_interval(double t) {
    return std::chrono::duration_cast<Interval>(std::chrono::duration<double>(t));
};

/** Converts a secs value into our interval type. */
constexpr Interval to_interval_from_secs(uint64_t t) {
    return std::chrono::duration_cast<Interval>(std::chrono::seconds(t));
};

/** Converts a ms value into our interval type. */
constexpr Interval to_interval_from_ms(uint64_t t) {
    return std::chrono::duration_cast<Interval>(std::chrono::milliseconds(t));
};

/** Converts a ns value into our interval type. */
constexpr Interval to_interval_from_ns(uint64_t t) {
    return std::chrono::duration_cast<Interval>(std::chrono::nanoseconds(t));
};

/** Converts an seconds-since-epoch timestamp into our time type. */
constexpr Time operator"" _time(unsigned long long int t) { return to_time(t); }

/** Render a time value as a readable string. */
inline std::string to_string(Time t) {
    std::time_t teatime = std::chrono::system_clock::to_time_t(t);
    auto tm = std::localtime(&teatime);

    std::stringstream b;
    b << std::put_time(tm, "%Y-%m-%d-%H-%M-%S");
    return std::string(b.str());
}

/** Render a time value as a readable string in ISO 8601 format. */
inline std::string to_string_iso(Time t) {
    auto teatime = std::chrono::system_clock::to_time_t(t);
    auto tm = std::localtime(&teatime);

    std::stringstream b;
    b << std::put_time(tm, "%FT%T%z");
    return std::string(b.str());
}

/** Render an interval value as a readable string. */
inline std::string to_string(Interval t) {
    std::stringstream b;
    b << std::chrono::duration_cast<std::chrono::seconds>(t).count() << "s";
    return std::string(b.str());
}

/** Aborts with an internal error saying we should not be where we are. */
#ifdef HAVE_MSVC
__declspec(noreturn) extern void cannot_be_reached();
#else
extern void cannot_be_reached() __attribute__((noreturn));
#endif

/**
 * Joins elements of a container into a string, using a specified delimiter
 * to separate them.
 */
template<typename T>
std::string join(const T& l, const std::string& delim = "") {
    std::string result;
    bool first = true;

    for ( const auto& i : l ) {
        if ( ! first )
            result += delim;
        result += std::string(i);
        first = false;
    }

    return result;
}

namespace detail {
/**
 * Helper which given some container `C` of `X` returns a default constructed
 * container of the same type class as `C` but with element type `Y`. */
template<typename C, typename Y>
constexpr auto transform_result_value(const C&) {
    using X = typename C::value_type;

    if constexpr ( std::is_same_v<C, std::vector<X>> ) {
        return std::vector<Y>();
    }
    else if constexpr ( std::is_same_v<C, std::set<X>> ) {
        return std::set<Y>();
    }

    // No default value defined for type.
    cannot_be_reached();
}

} // namespace detail

/** Applies a function to each element of container. */
template<typename C, typename F>
auto transform(const C& x, F f) {
    using Y = std::invoke_result_t<F, typename C::value_type>;

    auto y = detail::transform_result_value<C, Y>(x);
    std::transform(std::begin(x), std::end(x), std::inserter(y, std::end(y)), f);

    return y;
}

/** Returns a lower-case version of a string. */
extern std::string tolower(const std::string& s);

/** Returns a upper-case version of a string. */
extern std::string toupper(const std::string& s);

/**
 * Returns a string view with all trailing characters of a given set removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string rtrim(const std::string& s, const std::string& chars) noexcept {
    auto p = [](size_t pos) { return pos != std::string::npos ? pos + 1 : 0; }(s.find_last_not_of(chars));
    return s.substr(0, p);
}

/**
 * Returns a string view with all leading characters of a given set removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string ltrim(const std::string& s, const std::string& chars) noexcept {
    return s.substr(std::min(s.find_first_not_of(chars), s.size()));
    return s;
}

/**
 * Returns a string view with all leading & trailing characters of a given
 * set removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string trim(const std::string& s, const std::string& chars) noexcept {
    return ltrim(rtrim(s, chars), chars);
}

namespace detail {
constexpr char whitespace_chars[] = " \t\f\v\n\r";
} // namespace detail

/**
 * Returns a string view with all trailing white space removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string rtrim(const std::string& s) noexcept { return rtrim(s, detail::whitespace_chars); }

/**
 * Returns a string view with all leading white space removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string ltrim(const std::string& s) noexcept { return ltrim(s, detail::whitespace_chars); }

/**
 * Returns a string view with all leading & trailing white space removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string trim(const std::string& s) noexcept { return trim(s, detail::whitespace_chars); }

/**
 * Splits a string at all occurrences of a delimiter. Successive occurrences
 * of the delimiter will be split into multiple pieces.
 *
 * \note This function is not UTF8-aware.
 */
template<typename T>
std::vector<T> split(T s, const T& delim) {
    // If there's no delimiter, return a copy of the existing string.
    if ( delim.empty() )
        return {T(s)};

    // If the delimiter won't fit in the string, just return a copy as well.
    if ( s.size() < delim.size() )
        return {T(s)};

    std::vector<T> l;

    const bool ends_in_delim = (s.substr(s.size() - delim.size()) == delim);

    do {
        size_t p = s.find(delim);
        l.push_back(s.substr(0, p));
        if ( p == std::string::npos )
            break;

        s = s.substr(p + delim.size());
    } while ( ! s.empty() );

    if ( ends_in_delim )
        l.emplace_back(T{});

    return l;
}

template<typename T, typename U = typename T::value_type*>
std::vector<T> split(T s, const U delim) {
    return split(s, T(delim));
}

inline std::vector<std::string> split(const char* s, const char* delim) {
    return split(std::move(std::string(s)), std::string(delim));
}

inline std::vector<std::wstring> split(const wchar_t* s, const wchar_t* delim) {
    return split(std::move(std::wstring(s)), std::wstring(delim));
}

/**
 * Splits a string at all occurrences of successive white space.
 *
 * \note This function is not UTF8-aware.
 */
std::vector<std::string> split(std::string s);

/**
 * Splits a string once at the 1st occurrence of successive whitespace. Leaves
 * the 2nd element of the result pair unset if whitespace does not occur.
 *
 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> split1(std::string s);

/**
 * Splits a string once at the last occurrence of successive whitespace. Leaves
 * the 2nd element of the result pair unset if whitespace does not occur.

 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> rsplit1(std::string s);

/**
 * Splits a string once at the 1st occurrence of a delimiter. Leaves the 2nd
 * element of the result pair unset if the delimiter does not occur.
 *
 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> split1(std::string s, const std::string& delim);

/**
 * Splits a string once at the last occurrence of a delimiter. Leaves the 1st
 * element of the result pair unset if the delimiter does not occur.
 *
 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> rsplit1(std::string s, const std::string& delim);

/**
 * Replaces all occurrences of one string with another.
 *
 * \note This function is not UTF8-aware.
 */
std::string replace(std::string s, std::string o, std::string n);

/**
 * Returns true if a string begins with another.
 *
 * \note This function is not UTF8-aware.
 */
inline bool startsWith(const std::string& s, const std::string& prefix) { return s.find(prefix) == 0; }

/**
 * Returns true if a string ends with another.
 *
 * \note This function is not UTF8-aware.
 */
inline bool endsWith(const std::string& s, const std::string& suffix) {
    return s.rfind(suffix) == s.size() - suffix.size();
}

/**
 * Makes a unique_ptr containing an array. Useful for RAII on dynamically-allocated arrays. There's no
 * need to include a custom deleter here, as unique_ptr handles that on its own.
 *
 * @param len the length of the array to build. If this is zero, the array is created set to
 * nullptr. It does not create a zero-length array in this instance.
 * @param init whether or not to initialize the memory stored in the array to zeros after creation.
 */
template<typename C>
auto makeUniqueArray(size_t len = 0, bool init = true) {
    if ( len == 0 )
        return std::unique_ptr<C[]>{nullptr};

    auto arr = std::unique_ptr<C[]>{new C[len]};
    if ( init )
        memset(arr.get(), 0, sizeof(C) * len);
    return arr;
}

} // namespace zeek::agent

/** Renders an integer in base62 ASCII. */
std::string base62_encode(uint64_t i);

/** Parsed a version string of the form `x.y.z-<N>` into a numerical number suitable for ordering. */
zeek::agent::Result<int64_t> parseVersion(std::string v);

/** Creates a new random UUID, encoded in base62 ASCII. */
std::string randomUUID();

namespace std::chrono { // NOLINT(cert-dcl58-cpp)

inline std::ostream& operator<<(std::ostream& out, const zeek::agent::Time& t) {
    out << zeek::agent::to_string(t);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const zeek::agent::Interval& i) {
    out << zeek::agent::to_string(i);
    return out;
}

} // namespace std::chrono

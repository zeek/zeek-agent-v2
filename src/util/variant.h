// Copyrights (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <variant>

namespace zeek::agent {

// A variant that won't map `const char*` to bool. See
// https://stackoverflow.com/a/31009102. Note that we need to cast instance to
// the base for std::visit() becasue of this GCC bug:
// https://stackoverflow.com/a/68441460. *sigh*
template<typename... Types>
struct BetterVariant : public std::variant<Types...> {
    using Base = std::variant<Types...>;
    using Base::variant;

    BetterVariant(char* s) : Base(std::string(s)) {}
    BetterVariant(const char* s) : Base(std::string(s)) {}

    auto& operator=(const char* s) {
        Base::operator=(std::string(s));
        return *this;
    }

    auto& operator=(char* s) {
        Base::operator=(std::string(s));
        return *this;
    }
};

} // namespace zeek::agent

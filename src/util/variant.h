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

    bool operator<(const BetterVariant& other) const {
        return std::visit(
            [](const auto& a, const auto& b) -> bool {
                using AType = std::decay_t<decltype(a)>;
                using BType = std::decay_t<decltype(b)>;

                if constexpr ( std::is_same_v<AType, BType> ) {
                    return a < b;
                }
                else {
                    return typeid(AType).before(typeid(BType));
                }
            },
            static_cast<const Base&>(*this), static_cast<const Base&>(other));
    }
};

} // namespace zeek::agent

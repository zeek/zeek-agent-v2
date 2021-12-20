// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "helpers.h"

#include "autogen/config.h"
#include "testing.h"

#include <chrono>

#ifdef HAVE_POSIX
#include <unistd.h>

#include <sys/time.h>
#else
#error "Non-Unix platforms not supported yet"
#endif

using namespace zeek::agent;

std::optional<std::string> zeek::agent::getenv(const std::string& name) {
    if ( auto x = ::getenv(name.c_str()) )
        return {x};
    else
        return {};
}

void zeek::agent::cannot_be_reached() { throw InternalError("code is executing that should not be reachable"); }

std::vector<std::string> zeek::agent::split(std::string s, std::string delim) {
    if ( delim.empty() )
        return {std::string(s)};

    if ( s.size() < delim.size() )
        return {std::string(s)};

    std::vector<std::string> l;

    const bool ends_in_delim = (s.substr(s.size() - delim.size()) == delim);

    do {
        size_t p = s.find(delim);
        l.push_back(s.substr(0, p));
        if ( p == std::string::npos )
            break;

        s = s.substr(p + delim.size());
    } while ( ! s.empty() );

    if ( ends_in_delim )
        l.push_back("");

    return l;
}

std::vector<std::string> zeek::agent::split(std::string s) {
    std::vector<std::string> l;

    s = trim(s);

    while ( ! s.empty() ) {
        size_t p = s.find_first_of(detail::whitespace_chars);
        l.push_back(s.substr(0, p));
        if ( p == std::string::npos )
            break;

        s = s.substr(p);
        s = ltrim(s);
    }

    return l;
}

std::pair<std::string, std::string> zeek::agent::split1(std::string s) {
    if ( auto i = s.find_first_of(detail::whitespace_chars); i != std::string::npos )
        return std::make_pair(s.substr(0, i), std::string(ltrim(s.substr(i + 1))));

    return std::make_pair(std::move(s), "");
}

std::pair<std::string, std::string> zeek::agent::rsplit1(std::string s) {
    if ( auto i = s.find_last_of(detail::whitespace_chars); i != std::string::npos )
        return std::make_pair(s.substr(0, i), std::string(rtrim(s.substr(i + 1))));

    return std::make_pair("", std::move(s));
}

std::pair<std::string, std::string> zeek::agent::split1(std::string s, const std::string& delim) {
    if ( auto i = s.find(delim); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + delim.size()));

    return std::make_pair(std::move(s), "");
}

std::pair<std::string, std::string> zeek::agent::rsplit1(std::string s, const std::string& delim) {
    if ( auto i = s.rfind(delim); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + delim.size()));

    return std::make_pair("", std::move(s));
}

TEST_SUITE("Helpers") {
    TEST_CASE("scope guard") {
        int i = 0;
        {
            ScopeGuard _([&i]() { ++i; });
            CHECK_EQ(i, 0);
        }
        CHECK_EQ(i, 1);
    }

    TEST_CASE("getenv") {
        CHECK_EQ(::zeek::agent::getenv(""), std::nullopt);

        const auto home = ::zeek::agent::getenv("HOME");
        REQUIRE(home);
        CHECK_FALSE(home->empty());

        CHECK_EQ(::zeek::agent::getenv("TEST_ENV_DOES_NOT_EXIST"), std::nullopt);
    }


    TEST_CASE("time") { CHECK_EQ(to_string(42_time), "1970-01-01-00-00-42"); }

    TEST_CASE("interval") {
        auto x = Interval(42s);
        CHECK_EQ(to_string(x), "42s");
    }

    TEST_CASE("join") {
        using str_list = std::initializer_list<std::string>;

        CHECK_EQ(join(str_list{}, ""), "");
        CHECK_EQ(join(str_list{"a"}, ""), "a");
        CHECK_EQ(join(str_list{"a"}, "1"), "a");
        CHECK_EQ(join(str_list{"a", "b"}, "1"), "a1b");
        CHECK_EQ(join(str_list{"a", "b", "c"}, "\b1"), "a\b1b\b1c");

        const auto null = std::string(1u, '\0');
        CHECK_EQ(join(str_list{null, null}, null), null + null + null);
    }

    TEST_CASE("transform") {
        CHECK_EQ(transform(std::set<int>(), [](auto&& x) { return x + x; }), std::set<int>());
        CHECK_EQ(transform(std::set({1, 2, 3}), [](auto&& x) { return x + x; }), std::set({2, 4, 6}));
    }

    TEST_CASE("trim") {
        CHECK_EQ(trim("", ""), "");
        CHECK_EQ(trim("aa123a", ""), "aa123a");
        CHECK_EQ(trim("aa123a", "abc"), "123");
        CHECK_EQ(trim("aa123a", "XYZ"), "aa123a");

        const auto null = std::string(1u, '\0');
        CHECK_EQ(trim(null + null + "123" + null + "abc" + null, null), "123" + null + "abc");
    }

    TEST_CASE("ltrim") {
        CHECK_EQ(ltrim("", ""), "");
        CHECK_EQ(ltrim("", "abc"), "");
        CHECK_EQ(ltrim("a1b2c3d4", "abc"), "1b2c3d4");
        CHECK_EQ(ltrim("ab1b2c3d4", "abc"), "1b2c3d4");
        CHECK_EQ(ltrim("abc1b2c3d4", "abc"), "1b2c3d4");

        const auto null = std::string(1u, '\0');
        CHECK_EQ(ltrim(null + null + "abc", "a" + null), "bc");
    }

    TEST_CASE("rtrim") {
        CHECK_EQ(rtrim("", ""), "");
        CHECK_EQ(rtrim("", "abc"), "");
        CHECK_EQ(rtrim("4d3c2b1a", "abc"), "4d3c2b1");
        CHECK_EQ(rtrim("4d3c2b1ba", "abc"), "4d3c2b1");
        CHECK_EQ(rtrim("4d3c2b1cba", "abc"), "4d3c2b1");

        const auto null = std::string(1u, '\0');
        CHECK_EQ(rtrim("cba" + null + null, "a" + null), "cb");
    }

    TEST_CASE("rsplit1") {
        auto str_pair = std::make_pair<std::string, std::string>;

        SUBCASE("w/ delim") {
            CHECK_EQ(rsplit1("", ""), str_pair("", ""));
            CHECK_EQ(rsplit1(" a", " "), str_pair("", "a"));
            CHECK_EQ(rsplit1(" a b", " "), str_pair(" a", "b"));
            CHECK_EQ(rsplit1("a  b", " "), str_pair("a ", "b"));
            CHECK_EQ(rsplit1("a   b", " "), str_pair("a  ", "b"));
            CHECK_EQ(rsplit1("a b c", " "), str_pair("a b", "c"));
            CHECK_EQ(rsplit1("a b c ", " "), str_pair("a b c", ""));
            CHECK_EQ(rsplit1("abc", " "), str_pair("", "abc"));
        }

        SUBCASE("w/o delim") {
            CHECK_EQ(rsplit1(""), str_pair("", ""));
            CHECK_EQ(rsplit1("\ta"), str_pair("", "a"));
            CHECK_EQ(rsplit1("\ta\vb"), str_pair("\ta", "b"));
            CHECK_EQ(rsplit1("a  b"), str_pair("a ", "b"));
            CHECK_EQ(rsplit1("a   b"), str_pair("a  ", "b"));
            CHECK_EQ(rsplit1("a b c"), str_pair("a b", "c"));
            CHECK_EQ(rsplit1("a b c "), str_pair("a b c", ""));
            CHECK_EQ(rsplit1("abc"), str_pair("", "abc"));
        }
    }

    TEST_CASE("split") {
        using str_vec = std::vector<std::string>;

        SUBCASE("w/ delim") {
            CHECK_EQ(split("a:b:c", ""), str_vec({"a:b:c"}));
            CHECK_EQ(split("", ""), str_vec({""}));
            CHECK_EQ(split("a:b:c", ":"), str_vec({"a", "b", "c"}));
            CHECK_EQ(split("a:b::c", ":"), str_vec({"a", "b", "", "c"}));
            CHECK_EQ(split("a:b:::c", ":"), str_vec({"a", "b", "", "", "c"}));
            CHECK_EQ(split(":a:b:c", ":"), str_vec({"", "a", "b", "c"}));
            CHECK_EQ(split("::a:b:c", ":"), str_vec({"", "", "a", "b", "c"}));
            CHECK_EQ(split("a:b:c:", ":"), str_vec({"a", "b", "c", ""}));
            CHECK_EQ(split("a:b:c::", ":"), str_vec({"a", "b", "c", "", ""}));
            CHECK_EQ(split("", ":"), str_vec({""}));

            CHECK_EQ(split("12345", "1"), str_vec({"", "2345"}));
            CHECK_EQ(split("12345", "23"), str_vec{"1", "45"});
            CHECK_EQ(split("12345", "a"), str_vec{"12345"});
            CHECK_EQ(split("12345", ""), str_vec{"12345"});
        }

        SUBCASE("w/o delim") {
            CHECK_EQ(split("a b c"), str_vec({"a", "b", "c"}));
            CHECK_EQ(split("a\t b c"), str_vec({"a", "b", "c"}));
            CHECK_EQ(split("a    b       c"), str_vec({"a", "b", "c"}));
            CHECK_EQ(split("   a    b \t \n c"), str_vec({"a", "b", "c"}));
            CHECK_EQ(split("\n   a    b       c\t "), str_vec({"a", "b", "c"}));
            CHECK_EQ(split(""), str_vec{});
            CHECK_EQ(split("\t\v\n\r"), str_vec{});
            CHECK_EQ(split(" \n "), str_vec{});
        }
    }

    TEST_CASE("split1") {
        auto str_pair = std::make_pair<std::string, std::string>;

        SUBCASE("w/ delim") {
            CHECK_EQ(split1("", " "), str_pair("", ""));
            CHECK_EQ(split1(" a", " "), str_pair("", "a"));
            CHECK_EQ(split1(" a b", " "), str_pair("", "a b"));
            CHECK_EQ(split1("a  b", " "), str_pair("a", " b"));
            CHECK_EQ(split1("a   b", " "), str_pair("a", "  b"));
            CHECK_EQ(split1("a b c", " "), str_pair("a", "b c"));
        }

        SUBCASE("w/o delim") {
            CHECK_EQ(split1(""), str_pair("", ""));
            CHECK_EQ(split1("\ta"), str_pair("", "a"));
            CHECK_EQ(split1("\ta b"), str_pair("", "a b"));
            CHECK_EQ(split1("a  b"), str_pair("a", "b"));
            CHECK_EQ(split1("a   b"), str_pair("a", "b"));
            CHECK_EQ(split1("a b c"), str_pair("a", "b c"));
        }
    }
}

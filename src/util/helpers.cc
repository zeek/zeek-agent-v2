// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "helpers.h"

#include "autogen/config.h"
#include "testing.h"

#include <chrono>

#include <uuid.h>

#include <glob/glob.h>

#ifdef HAVE_POSIX
#include <unistd.h>

#include <sys/time.h>
#endif

using namespace zeek::agent;

void zeek::agent::cannot_be_reached() { throw InternalError("code is executing that should not be reachable"); }

std::string zeek::agent::tolower(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    return t;
}

std::string zeek::agent::toupper(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::toupper);
    return t;
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

std::string zeek::agent::replace(const std::string& s, const std::string& o, const std::string& n) {
    if ( o.empty() )
        return s;

    auto x = s;

    size_t i = 0;
    while ( (i = x.find(o, i)) != std::string::npos ) {
        x.replace(i, o.length(), n);
        i += n.length();
    }

    return x;
}

static std::string base62_encode(uint64_t i) {
    static const char* alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    std::string x;

    do {
        x.insert(0, std::string(1, alphabet[i % 62]));
        i /= 62;
    } while ( i > 0 );

    return x;
}

zeek::agent::Result<int64_t> zeek::agent::parseVersion(std::string v) {
    unsigned long major = 0;
    unsigned long minor = 0;
    unsigned long patch = 0;
    unsigned long commit = 0;

    if ( startsWith(v, "v") )
        // ignore leading 'v'
        v = v.substr(1);

    try {
        auto m = split(v, "-");
        if ( m.empty() )
            return result::Error("empty version string");

        auto n = split(m[0], ".");
        if ( n.size() != 3 )
            return result::Error("not a valid version string");

        major = std::stoul(n[0]);
        minor = std::stoul(n[1]);
        patch = std::stoul(n[2]);

        if ( m.size() > 1 ) {
            try {
                commit = std::stoul(m[m.size() - 1]);
            } catch ( ... ) {
                // ignore errors
            }
        }

        return static_cast<int64_t>(major * 100000000 + minor * 1000000 + patch * 10000 + commit);
    } catch ( ... ) {
        return result::Error("trouble parsing version string");
    }
}

std::string zeek::agent::randomUUID() {
    std::random_device rd;
    auto seed_data = std::array<int, std::mt19937::state_size>{};
    std::generate(std::begin(seed_data), std::end(seed_data), std::ref(rd));
    std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
    std::mt19937 generator(seq);
    auto uuid = uuids::uuid_random_generator(generator)();

    // We represent the UUID in base62 for compactness.
    auto* p = reinterpret_cast<const uint64_t*>(uuid.as_bytes().data());
    return frmt("{}{}", base62_encode(p[0]), base62_encode(p[1]));
}

std::vector<filesystem::path> zeek::agent::glob(const filesystem::path& pattern, size_t max) {
    // glob::glob returns std::filesystem::path, but we're using ghc::filesystem for compatibility
    // reasons. this means we need to copy the paths from one vector type to another here.
    auto paths = glob::glob(pattern.string());
    if ( paths.size() > max )
        paths.resize(max);

    return paths;
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

        const auto null = std::string(1U, '\0');
        CHECK_EQ(join(str_list{null, null}, null), null + null + null);
    }

    TEST_CASE("transform") {
        CHECK_EQ(transform(std::set<int>(), [](auto&& x) { return x + x; }), std::set<int>());
        CHECK_EQ(transform(std::set({1, 2, 3}), [](auto&& x) { return x + x; }), std::set({2, 4, 6}));
    }

    TEST_CASE("tolower") { CHECK_EQ(tolower("AbCd"), "abcd"); }

    TEST_CASE("tolower") { CHECK_EQ(toupper("AbCd"), "ABCD"); }

    TEST_CASE("trim") {
        CHECK_EQ(trim("", ""), "");
        CHECK_EQ(trim("aa123a", ""), "aa123a");
        CHECK_EQ(trim("aa123a", "abc"), "123");
        CHECK_EQ(trim("aa123a", "XYZ"), "aa123a");

        const auto null = std::string(1U, '\0');
        CHECK_EQ(trim(null + null + "123" + null + "abc" + null, null), "123" + null + "abc");
    }

    TEST_CASE("ltrim") {
        CHECK_EQ(ltrim("", ""), "");
        CHECK_EQ(ltrim("", "abc"), "");
        CHECK_EQ(ltrim("a1b2c3d4", "abc"), "1b2c3d4");
        CHECK_EQ(ltrim("ab1b2c3d4", "abc"), "1b2c3d4");
        CHECK_EQ(ltrim("abc1b2c3d4", "abc"), "1b2c3d4");

        const auto null = std::string(1U, '\0');
        CHECK_EQ(ltrim(null + null + "abc", "a" + null), "bc");
    }

    TEST_CASE("rtrim") {
        CHECK_EQ(rtrim("", ""), "");
        CHECK_EQ(rtrim("", "abc"), "");
        CHECK_EQ(rtrim("4d3c2b1a", "abc"), "4d3c2b1");
        CHECK_EQ(rtrim("4d3c2b1ba", "abc"), "4d3c2b1");
        CHECK_EQ(rtrim("4d3c2b1cba", "abc"), "4d3c2b1");

        const auto null = std::string(1U, '\0');
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
        using wstr_vec = std::vector<std::wstring>;

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

        SUBCASE("wchar_t w/ delim") {
            CHECK_EQ(split(L"a:b:c", L""), wstr_vec({L"a:b:c"}));
            CHECK_EQ(split(L"", L""), wstr_vec({L""}));
            CHECK_EQ(split(L"a:b:c", L":"), wstr_vec({L"a", L"b", L"c"}));
            CHECK_EQ(split(L"a:b::c", L":"), wstr_vec({L"a", L"b", L"", L"c"}));
            CHECK_EQ(split(L"a:b:::c", L":"), wstr_vec({L"a", L"b", L"", L"", L"c"}));
            CHECK_EQ(split(L":a:b:c", L":"), wstr_vec({L"", L"a", L"b", L"c"}));
            CHECK_EQ(split(L"::a:b:c", L":"), wstr_vec({L"", L"", L"a", L"b", L"c"}));
            CHECK_EQ(split(L"a:b:c:", L":"), wstr_vec({L"a", L"b", L"c", L""}));
            CHECK_EQ(split(L"a:b:c::", L":"), wstr_vec({L"a", L"b", L"c", L"", L""}));
            CHECK_EQ(split(L"", L":"), wstr_vec({L""}));

            CHECK_EQ(split(L"12345", L"1"), wstr_vec({L"", L"2345"}));
            CHECK_EQ(split(L"12345", L"23"), wstr_vec{L"1", L"45"});
            CHECK_EQ(split(L"12345", L"a"), wstr_vec{L"12345"});
            CHECK_EQ(split(L"12345", L""), wstr_vec{L"12345"});
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

    TEST_CASE("parseVersion") {
        CHECK_EQ(parseVersion("2.0.4"), 200040000);
        CHECK_EQ(parseVersion("2.0.4-123"), 200040123);
        CHECK_EQ(parseVersion("2.0.4-rc1-123"), 200040123);
        CHECK_EQ(parseVersion("2.0.4-rc1"), 200040000);
        CHECK(! parseVersion(""));
        CHECK(! parseVersion("x.x.x"));
        CHECK(! parseVersion("x.x"));
    }

    TEST_CASE("startsWith") {
        CHECK(startsWith("abcd", "ab"));
        CHECK(! startsWith("abcd", "cd"));
    }

    TEST_CASE("endsWith") {
        CHECK(endsWith("abcd", "cd"));
        CHECK(! endsWith("abcd", "ab"));
    }

    TEST_CASE("replace") {
        CHECK_EQ(replace("abcd", "ab", "xy"), "xycd");
        CHECK_EQ(replace("abcd", "QWQW", "xy"), "abcd");
    }
}

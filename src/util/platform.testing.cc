// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform.h"

#include "testing.h"

using namespace zeek::agent;

TEST_SUITE("Platform") {
    TEST_CASE("getenv") {
        CHECK_EQ(platform::getenv(""), std::nullopt);

#ifndef HAVE_WINDOWS
        const auto home = platform::getenv("HOME");
#else
        const auto home = platform::getenv("HOMEPATH");
#endif
        REQUIRE(home);
        CHECK_FALSE(home->empty());

        CHECK_EQ(platform::getenv("TEST_ENV_DOES_NOT_EXIST"), std::nullopt);
    }
}

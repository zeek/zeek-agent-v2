// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "sockets.h"

#include "autogen/config.h"
#include "util/testing.h"

#include <netinet/in.h>

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "sockets" * doctest::test_suite("Tables")) {
    useTable("sockets");

    int port = -1, fd = -1;
    while ( true ) {
        // Listen on a random port, then check if we can see it.
        fd = socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(fd >= 0);

        fchmod(fd, 0777);

        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));

        port = (random() + 1024) % 65536;

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if ( bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 )
            // port presumably already in use, try another one
            continue;

        fchmod(fd, 0777);
        REQUIRE(listen(fd, SOMAXCONN) >= 0);
        break;
    }

    // We should be able to see our port.
    auto result = query(format("SELECT pid, state from sockets WHERE local_port = {}", port));
    REQUIRE_EQ(result.rows.size(), 1);
    CHECK_EQ(result.get<int64_t>(0, "pid"), getpid());
    CHECK_EQ(result.get<std::string>(0, "state"), std::string("LISTEN"));

    // Clean up
    close(fd);
}

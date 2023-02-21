// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// Socket implementation for POSIX systems.

#include "socket.h"

#include "util/fmt.h"
#include "util/testing.h"

using namespace zeek::agent;

socket::SocketBuffer& socket::SocketBuffer::operator=(const SocketBuffer& other) {
    if ( this == &other )
        return *this;

    _socket = other._socket;
    _remote = other._remote;
    return *this;
}

int socket::SocketBuffer::sync() {
    if ( auto rc = _socket->write(str(), *_remote); ! rc ) {
        logger()->debug("failed to send message to socket: {}", rc.error());
        _remote->setError(rc.error());
    }

    str("");
    return 0;
}

socket::Remote& socket::Remote::operator=(const Remote& other) noexcept {
    if ( this == &other )
        return *this;

    _dst = other._dst;
    _sbuf = SocketBuffer(other._sbuf._socket, this);
    _sout = std::make_unique<std::ostream>(&_sbuf);
    return *this;
}

TEST_SUITE("socket") {
    TEST_CASE("read-and-write") {
        auto path1 = filesystem::path(frmt("/tmp/zeek-agent-test-socket.{}.1", getpid()));
        auto path2 = filesystem::path(frmt("/tmp/zeek-agent-test-socket.{}.2", getpid()));

        Socket socket1;
        REQUIRE(! socket1);
        REQUIRE(socket1.bind(path1));
        REQUIRE(socket1);

        Socket socket2;
        REQUIRE(! socket2);
        REQUIRE(socket2.bind(path2));
        REQUIRE(socket2);

        socket1.write("Hello, Socket 2!", {&socket1, path2});

        auto result = socket2.read();
        REQUIRE(result);
        REQUIRE(*result);
        auto [data_1, remote_sender_1] = **result;
        CHECK_EQ(data_1, "Hello, Socket 2!");

        remote_sender_1 << "Hello, Socket 1!" << std::flush;

        result = socket1.read();
        REQUIRE(result);
        REQUIRE(*result);
        auto [data_2, remote_sender_2] = **result;
        CHECK_EQ(data_2, "Hello, Socket 1!");

        CHECK(remote_sender_1);
        CHECK(remote_sender_2);
        CHECK(socket1);
        CHECK(socket2);
    }

    TEST_CASE("unknown-remote") {
        auto path = filesystem::path(frmt("/tmp/zeek-agent-test-socket.{}", getpid()));

        Socket socket;
        REQUIRE(socket.bind(path));

        socket::Remote remote(&socket, filesystem::path("/DOES-NOT-EXIST"));
        remote << "xyz" << std::flush;

        CHECK(! remote);
        CHECK(remote.error());
    }
}

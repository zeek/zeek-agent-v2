// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.
//
// Socket implementation for POSIX systems.

#include "socket.h"

#include "core/logger.h"
#include "util/helpers.h"

#include <sys/socket.h>
#include <sys/un.h>

using namespace zeek::agent;

static const auto SocketBufferSize = 32768U;

// Converts an opaque address handle into a sockaddr_un.
static struct sockaddr_un dst2sock(const socket::Address& dst) {
    struct sockaddr_un sock;
    memcpy(&sock, dst.data(), sizeof(sock));
    return sock;
}

// Converts a sockaddr_un into an opaque address handle.
static socket::Address sock2dst(const struct sockaddr_un& dst) {
    return {reinterpret_cast<const char*>(&dst), sizeof(dst)};
}

socket::Address socket::Remote::pathToDestination(const filesystem::path& path) {
    struct sockaddr_un dst;

    if ( strlen(path.c_str()) >= sizeof(dst.sun_path) )
        throw FatalError(frmt("socket path too long: {}", path.native()));

    bzero(&dst, sizeof(dst));
    dst.sun_family = AF_UNIX;
    strncpy(dst.sun_path, path.c_str(), sizeof(dst.sun_path) - 1);
    dst.sun_path[sizeof(dst.sun_path) - 1] = '\0';
    return sock2dst(dst);
}

template<>
struct Pimpl<Socket>::Implementation {
    // One-time initialization.
    void init();

    // One-time initialization.
    void done();

    // Binds the socket to a local path, setting it up for communication.
    Result<Nothing> bind(const filesystem::path& path);

    // Reads one message from the socket. If no input is currently available,
    Result<Socket::ReadResult> read();

    // Sends one message to the currently active destination. This will fail
    Result<Nothing> write(const std::string& data, const socket::Remote& dst);

    Socket* _socket = nullptr; // socket that this implementation belongs to
    int _fd = -1;              // socket's fd
    filesystem::path _path;    // path the socket is bound to
};

void Socket::Implementation::init() {}

void Socket::Implementation::done() {
    if ( _fd >= 0 )
        close(_fd);

    if ( ! _path.empty() )
        unlink(_path.c_str());
}

Result<Nothing> Socket::Implementation::bind(const filesystem::path& path) {
    if ( _fd >= 0 )
        return result::Error("socket already bound");

    int flags;
    struct sockaddr_un local;

    if ( strlen(path.c_str()) >= sizeof(local.sun_path) )
        return result::Error(frmt("socket path too long: {}", path.native()));

    auto fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if ( fd < 0 )
        return result::Error(frmt("cannot create socket: {}", strerror(errno)));

    ScopeGuard _([&]() {
        if ( fd >= 0 )
            close(fd);
    });

    const int bufsize = SocketBufferSize;
    if ( setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0 )
        logger()->warn("cannot set socket receive buffer size: {}", strerror(errno));

    if ( setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0 )
        logger()->warn("cannot set socket send buffer size: {}", strerror(errno));

    // Let operations time out so that our I/O methods don't block and the
    // caller can also check for termination.
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    if ( setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 )
        return result::Error(frmt("cannot set socket timeout: {}", strerror(errno)));

    bzero(&local, sizeof(local));
    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, path.c_str(), sizeof(local.sun_path) - 1);
    local.sun_path[sizeof(local.sun_path) - 1] = '\0';
    unlink(path.c_str());

    {
        // Grant only the current user the permission to access the socket.
        auto old_umask = umask(0077);
        ScopeGuard _([&]() { umask(old_umask); });

        if ( ::bind(fd, (struct sockaddr*)&local, sizeof(local)) < 0 )
            return result::Error(frmt("cannot bind to socket: {}", strerror(errno)));
    }

    _path = path;
    _fd = fd;
    fd = -1;

    return Nothing();
}

Result<Socket::ReadResult> Socket::Implementation::read() {
    if ( _fd < 0 )
        return result::Error("socket not open");

    struct sockaddr_un sender;
    socklen_t sender_size = sizeof(sender);

    char buffer[SocketBufferSize];
    auto len = recvfrom(_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender, &sender_size);
    if ( len < 0 ) {
        if ( errno != EAGAIN || errno != EWOULDBLOCK )
            return result::Error(strerror(errno));

        return {std::nullopt};
    }

    return std::make_optional(std::make_pair(std::string(buffer, len), socket::Remote(_socket, sock2dst(sender))));
}

Result<Nothing> Socket::Implementation::write(const std::string& data, const socket::Remote& dst) {
    if ( _fd < 0 )
        return result::Error("socket not open");

    if ( data.empty() )
        return Nothing();

    int attempts = 0;
    while ( attempts++ < 50 ) {
        struct sockaddr_un sockaddr = dst2sock(dst.destination());
        auto len = sendto(_fd, data.data(), data.size(), 0, (struct sockaddr*)&sockaddr, sizeof(sockaddr));
        if ( len >= 0 )
            return Nothing();

        if ( errno == ENOBUFS ) {
            usleep(100); // give client a chance to catch up
            continue;
        }

        if ( errno == EAGAIN || errno == EWOULDBLOCK )
            return Nothing(); // time out

        break;
    }

    return result::Error(strerror(errno));
}

Socket::Socket() {
    pimpl()->_socket = this;
    pimpl()->init();
}

Socket::~Socket() { pimpl()->done(); }

bool Socket::isActive() const { return pimpl()->_fd >= 0; };

Result<Nothing> Socket::bind(const filesystem::path& path) { return pimpl()->bind(path); }

Result<Socket::ReadResult> Socket::read() { return pimpl()->read(); }

Result<Nothing> Socket::write(const std::string& data, const socket::Remote& dst) { return pimpl()->write(data, dst); }

bool Socket::supportsIPC() { return true; }

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/logger.h"
#include "util/helpers.h"
#include "util/pimpl.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace zeek::agent {

class Socket;

namespace socket {

class Remote;

/***
 * Opaque address handle identifying a remote socket endpoint. It's derived
 * internally from the socket paths. Externally,
 * there's no further semantics associated with the content of this string.
 */
using Address = std::string;

/**
 * Private helper class for `Remote` implementing a `stringbuf` variant that
 * sends output to a socket.
 **/
class SocketBuffer : public std::stringbuf {
private:
    friend class Remote;

    SocketBuffer(Socket* socket = nullptr, Remote* remote = nullptr) : _socket(socket), _remote(remote) {}
    SocketBuffer(const SocketBuffer& other) : _socket(other._socket), _remote(other._remote) {}

    int sync() override;

    SocketBuffer& operator=(const SocketBuffer& other);

    Socket* _socket = nullptr;
    Remote* _remote = {};
};

/**
 * Remote endpoint of a socket, accepting `<<` stream operations for sending
 * output to that destination.
 */
class Remote {
public:
    /**
     * Constructor.
     *
     * @param local local socket the remote endpoint is associated with
     * @param dst file system path identifying remote endpoint
     */
    Remote(Socket* local, const filesystem::path& dst)
        : _dst(pathToDestination(dst)), _sbuf(local, this), _sout(std::make_unique<std::ostream>(&_sbuf)) {}

    /**
     * Constructor.
     *
     * @param local local socket the remote endpoint is associated with
     * @param dst opaque handle identifying the remote endpoint, as returned by `read()` or `destination()`.
     */
    Remote(Socket* local = nullptr, Address dst = {})
        : _dst(std::move(dst)), _sbuf(local, this), _sout(std::make_unique<std::ostream>(&_sbuf)) {}

    /** Copy constructor. */
    Remote(const Remote& other)
        : _dst(other._dst), _sbuf(other._sbuf._socket, this), _sout(std::make_unique<std::ostream>(&_sbuf)) {}

    /** Returns an opaque handle identifying the remote endpoint. */
    Address destination() const { return _dst; }

    /** Returns `ostream` sending output to the remote endpoint. */
    std::ostream& stream() { return *_sout; }

    /** Returns any error that a previous I/O operation has triggered. */
    const auto& error() const { return _error; }

    /*o Implicit conversion to an `ostream` sending output out to the socket. */
    operator std::ostream&() { return stream(); }

    /** Returns true if no error has been recorded by a previous I/O operation. */
    explicit operator bool() const { return ! _error.has_value(); }

    Remote& operator=(const Remote& other) noexcept;
    bool operator==(const Remote& other) const { return _dst == other._dst; }

    /** Wrapper to make the remote endpoint compatible with `ostream-`style `<<` output.  */
    template<typename T>
    Remote& operator<<(const T& t) {
        stream() << t;
        return *this;
    }

    using _manip_type = std::ostream&(std::ostream&);

    /** Wrapper to make the remote endpoint compatible with `ostream-`style `<<` output.  */
    Remote& operator<<(_manip_type m) {
        stream() << m;
        return *this;
    }

protected:
    friend class SocketBuffer;

    void setError(const result::Error& err) {
        _sout->setstate(std::ios_base::failbit);
        _error = err;
    }

private:
    // Convert a file system path into an opaque handle identifying the remote endpoint.
    Address pathToDestination(const filesystem::path& path);

    Address _dst = {};                   // opaque handle of remote endpoint
    socket::SocketBuffer _sbuf;          // stream buffer bound to the remote endpoint
    std::unique_ptr<std::ostream> _sout; // `ostream` using `sbuf` as its buffer
    std::optional<result::Error> _error; // error state
};

} // namespace socket

/**
 * Provides a socket for IPC.
 *
 * This is a helper class that provides IPC functionality for our interactive
 * console. Behind the scenes, we may implement sockets differently per
 * platform. On POSIX systems, we use Unix datagramm sockets. Windows is not
 * currently implemented.
 */
class Socket : public Pimpl<Socket> {
public:
    /** Constructor. */
    Socket();

    /** Destructor. */
    ~Socket();

    /**
     * Binds the socket to a local path, setting it up for communication.
     *
     * @param path a local file system path identifying the socket; this is
     * what remote endpoints will use to address the socket.
     */
    Result<Nothing> bind(const filesystem::path& path);

    /** Result type of `read()`. */
    using ReadResult = std::optional<std::pair<std::string, socket::Remote>>;

    /**
     * Reads one message from the socket. If no input is currently available,
     * this will block briefly and then return with an unset optional.
     *
     * @returns the optional will be either set to the pair of received message
     * and its remote sender, or remain unset if no message is currently
     * pending; if an error occurs, the result will reflect it
     */
    Result<ReadResult> read();

    /**
     * Sends one message to the given destination.
     *
     * @param data message to send; it will be send atomically, i.e., the
     * receiver will always receive the whole message from a single call to
     * `read()`
     * @returns success if the message was sent, or a corresponding error otherwise
     */
    Result<Nothing> write(const std::string& data, const socket::Remote& dst);

    /** Returns true if the socket is open and ready for communication. */
    bool isActive() const;

    /** Returns the result of `isActive() && ! error()`. */
    explicit operator bool() const { return isActive(); }

    /**
     * Returns true if the socket implementation supports true IPC between
     * independent processes.
     */
    static bool supportsIPC();
};

} // namespace zeek::agent

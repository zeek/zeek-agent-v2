// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

// clang-format off
#include "platform.h"
#include "platform.darwin.h"
// clang-format on

#include "autogen/config.h"
#include "core/logger.h"
#include "fmt.h"
#include "helpers.h"
#include "testing.h"

#include <string>

#include <pathfind.hpp>

#include <EndpointSecurity/EndpointSecurity.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

std::string platform::name() { return "Darwin"; }

filesystem::path platform::configurationFile() {
    // TODO: These paths aren't necessarily right yet.
    if ( auto home = platform::getenv("HOME") )
        return filesystem::path(*home) / ".config" / "zeek-agent";
    else {
        filesystem::path exec = PathFind::FindExecutable();
        return exec / "../etc" / "zeek-agent.conf";
    }
}

filesystem::path platform::dataDirectory() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path dir;

    if ( auto home = platform::getenv("HOME") )
        dir = filesystem::path(*home) / ".cache" / "zeek-agent";
    else
        dir = "/var/run/org.zeek.agent";

    std::error_code ec;
    filesystem::create_directories(dir, ec);
    if ( ec )
        throw FatalError(frmt("cannot create path '{}'", dir.native()));

    return dir;
}

// The EndpointSecurity code borrows from
// https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba.
template<>
struct Pimpl<EndpointSecurity>::Implementation {
    // Initialize ES, if not done yet.
    Result<Nothing> init();

    // Shutdown ES, if running.
    void done();

    static int _num_clients; // number of active ES clients.
    static es_client_t* _es_client;
    static Result<Nothing> _es_init_result;
};

int EndpointSecurity::Implementation::_num_clients = 0;
es_client_t* EndpointSecurity::Implementation::_es_client = nullptr;
Result<Nothing> EndpointSecurity::Implementation::_es_init_result;

static es_handler_block_t dummy_handler = ^(es_client_t* clt, const es_message_t* msg) {
};

Result<Nothing> EndpointSecurity::Implementation::init() {
    if ( _num_clients++ > 0 )
        return _es_init_result;

    es_new_client_result_t res = es_new_client(&_es_client, dummy_handler);

    switch ( res ) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: _es_init_result = Nothing(); break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            _es_init_result =
                result::Error("macOS entitlement not available (com.apple.developer.endpoint-security.client)");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            _es_init_result = result::Error(
                "Application lacks Transparency, Consent, and Control (TCC) approval "
                "from the user. This can be resolved by granting 'Full Disk Access' from "
                "the 'Security & Privacy' tab of System Preferences.");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: _es_init_result = result::Error("not running as root"); break;

        default: _es_init_result = result::Error(format("unexpected error ({})", res)); break;
    }

    if ( _es_init_result )
        ZEEK_AGENT_DEBUG("darwin", "EndpointSecurity available");
    else
        ZEEK_AGENT_DEBUG("darwin", "EndpointSecurity not available: ", _es_init_result.error());

    return _es_init_result;
}

void EndpointSecurity::Implementation::done() {
    assert(_num_clients > 0);

    if ( --_num_clients != 0 )
        return;

    if ( _es_client )
        es_delete_client(_es_client);

    _es_client = nullptr;
    _es_init_result = {};
}

Result<Nothing> EndpointSecurity::init() { return pimpl()->init(); }

void EndpointSecurity::done() { return pimpl()->done(); }

EndpointSecurity::EndpointSecurity() {}
EndpointSecurity::~EndpointSecurity() { done(); }

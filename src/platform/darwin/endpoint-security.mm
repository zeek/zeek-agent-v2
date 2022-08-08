// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// The EndpointSecurity code borrows from
// https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba.

#include "endpoint-security.h"

#include "autogen/config.h"
#include "core/logger.h"

#include <EndpointSecurity/EndpointSecurity.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

template<>
struct Pimpl<EndpointSecurity>::Implementation {
    // Initialize ES, if not done yet.
    Result<Nothing> init();

    // Shutdown ES, if running.
    void done();

    es_client_t* _es_client = nullptr;
    Result<Nothing> _es_init_result;
};

static es_handler_block_t dummy_handler = ^(es_client_t* clt, const es_message_t* msg) {
};

Result<Nothing> EndpointSecurity::Implementation::init() {
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
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: _es_init_result = result::Error("too many clients"); break;
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: _es_init_result = result::Error("invalid argument"); break;
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: _es_init_result = result::Error("internal error"); break;
    }

    if ( _es_init_result )
        ZEEK_AGENT_DEBUG("darwin", "EndpointSecurity available");
    else
        ZEEK_AGENT_DEBUG("darwin", "EndpointSecurity not available: {}", _es_init_result.error());

    return _es_init_result;
}

void EndpointSecurity::Implementation::done() {
    if ( _es_client )
        es_delete_client(_es_client);

    _es_client = nullptr;
    _es_init_result = {};
}

Result<Nothing> EndpointSecurity::isAvailable() {
    if ( pimpl()->_es_init_result )
        return Nothing();
    else
        return pimpl()->init();
}

EndpointSecurity::EndpointSecurity() { pimpl()->init(); }
EndpointSecurity::~EndpointSecurity() { pimpl()->done(); }

EndpointSecurity* platform::darwin::endpointSecurity() {
    static auto es = std::unique_ptr<EndpointSecurity>{};

    if ( ! es )
        es = std::unique_ptr<EndpointSecurity>(new EndpointSecurity);

    return es.get();
}

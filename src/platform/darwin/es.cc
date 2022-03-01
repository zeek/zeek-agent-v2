// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// See https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba


#include "./es.h"

#include "util/fmt.h"

#include <EndpointSecurity/EndpointSecurity.h>

using namespace zeek::agent;

// TODO: Move to PIMPL-class storage.
es_client_t* g_client = nullptr;

es_handler_block_t dummy_handler = ^(es_client_t* clt, const es_message_t* msg) {
};

Result<Nothing> darwin::EndpointSecurity::start() {
    es_new_client_result_t res = es_new_client(&g_client, dummy_handler);

    switch ( res ) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return result::Error("macOS entitlement not available (com.apple.developer.endpoint-security.client)");

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return result::Error(
                "Application lacks Transparency, Consent, and Control (TCC) approval "
                "from the user. This can be resolved by granting 'Full Disk Access' from "
                "the 'Security & Privacy' tab of System Preferences.");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return result::Error("not running as root"); break;

        default: return result::Error(format("unexpected error ({})", res));
    }

    return Nothing();
}

void darwin::EndpointSecurity::stop() {
    if ( g_client )
        es_delete_client(g_client);
}

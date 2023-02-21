// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// Note that contrary to what Apple's documentation says, FilterDataProvider is
// *not* sandboxed on macOS. See // https://developer.apple.com/forums/thread/133761.

#include "network-extension.h"

#include "autogen/config.h"
#include "core/logger.h"

#include <NetworkExtension/NetworkExtension.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

ne::Subscriber::~Subscriber() { _ne->_subscribers.remove(this); }

template<>
struct Pimpl<NetworkExtension>::Implementation {
    bool running = false;
};

Result<Nothing> NetworkExtension::isAvailable() {
    if ( pimpl()->running ) {
        ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] available");
        return Nothing();
    }
    else {
        ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] not available");
        return result::Error("network extension not running");
    }
}

NetworkExtension::NetworkExtension() {}

NetworkExtension::~NetworkExtension() {}

std::unique_ptr<ne::Subscriber> NetworkExtension::subscribe(std::string tag, Callback callback) {
    auto subscriber = std::unique_ptr<ne::Subscriber>(new ne::Subscriber(this, std::move(tag), std::move(callback)));
    _subscribers.push_back(subscriber.get());
    return std::move(subscriber);
}

void NetworkExtension::newFlow(const ne::Flow& flow) {
    ZEEK_AGENT_DEBUG("darwin",
                     frmt("[NetworkExtension] New flow: {}/{} -> {}/{}", to_string(flow.local_addr),
                          to_string(flow.local_port), to_string(flow.remote_addr), to_string(flow.remote_port)));

    for ( const auto& s : _subscribers )
        s->_callback(flow);
}

NetworkExtension* platform::darwin::networkExtension() {
    static auto ne = std::unique_ptr<NetworkExtension>{};

    if ( ! ne )
        ne = std::unique_ptr<NetworkExtension>(new NetworkExtension);

    return ne.get();
}

@interface FilterDataProvider : NEFilterDataProvider
@end

@implementation FilterDataProvider
- (void)startFilterWithCompletionHandler:(void (^)(NSError* error))completionHandler {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] starting");
    networkExtension()->pimpl()->running = true;

    // Create a filter that matches all traffic and let it all pass through our
    // `handleNewFlow()` filter.
    auto all_traffic = [[NENetworkRule alloc] initWithRemoteNetwork:nil
                                                       remotePrefix:0
                                                       localNetwork:nil
                                                        localPrefix:0
                                                           protocol:NENetworkRuleProtocolAny
                                                          direction:NETrafficDirectionAny];

    auto rule = [[NEFilterRule alloc] initWithNetworkRule:all_traffic action:NEFilterActionFilterData];
    auto setting = [[NEFilterSettings alloc] initWithRules:[NSArray arrayWithObjects:rule, nil]
                                             defaultAction:NEFilterActionAllow];
    [self applySettings:setting
        completionHandler:^(NSError* _Nullable error) {
          if ( error != nil ) {
              logger()->info("failed to apply filter settings in network extension");
              networkExtension()->pimpl()->running = false;
          }

          completionHandler(error);
        }];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] stopping");
    networkExtension()->pimpl()->running = false;
    completionHandler();
}

- (NEFilterNewFlowVerdict*)handleNewFlow:(NEFilterFlow*)flow {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] got flow");

    if ( ! [flow isKindOfClass:[NEFilterSocketFlow class]] )
        return [NEFilterNewFlowVerdict allowVerdict];

    auto sf = (NEFilterSocketFlow*)flow;
    auto local = (NWHostEndpoint*)sf.localEndpoint;
    auto remote = (NWHostEndpoint*)sf.remoteEndpoint;

    ne::Flow nf;
    nf.local_addr = [local.hostname UTF8String];
    nf.local_port = [local.port UTF8String];
    nf.remote_addr = [remote.hostname UTF8String];
    nf.remote_port = [remote.port UTF8String];

    networkExtension()->newFlow(nf);

    return [NEFilterNewFlowVerdict allowVerdict];
}

@end

[[noreturn]] void platform::darwin::enterNetworkExtensionMode() {
    [NEProvider startSystemExtensionMode];
    dispatch_main();
}

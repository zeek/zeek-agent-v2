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

template<>
struct Pimpl<NetworkExtension>::Implementation {
    bool running = false;
};

Result<Nothing> NetworkExtension::isAvailable() {
    if ( pimpl()->running )
        return Nothing();
    else
        return result::Error("network extension  not running");
}

NetworkExtension::NetworkExtension() {}

NetworkExtension::~NetworkExtension() {}

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
    networkExtension()->pimpl()->running = false;
    completionHandler();
}

- (NEFilterNewFlowVerdict*)handleNewFlow:(NEFilterFlow*)flow {
    // TODO: Report new flow to subscribers here.
    // logger()->info("new flow");
    return [NEFilterNewFlowVerdict allowVerdict];
}

@end

[[noreturn]] void platform::darwin::enterNetworkExtensionMode() {
    [NEProvider startSystemExtensionMode];
    dispatch_main();
}

// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "xpc.h"

#include "core/logger.h"
#include "endpoint-security.h"
#include "network-extension.h"

using namespace zeek::agent;

@implementation IPC

+ (IPC*)sharedObject {
    static dispatch_once_t once;
    static IPC* sharedObject;
    dispatch_once(&once, ^{
      sharedObject = [[self alloc] init];
    });

    return sharedObject;
}

- (instancetype)init {
    [super init];
    _defaults = [NSUserDefaults standardUserDefaults];
    _listener = [[NSXPCListener alloc] initWithMachServiceName:@"org.zeek.zeek-agent.agent"];
    _listener.delegate = self;
    [_listener resume];
    return self;
}

- (const Options&)options {
    return _configuration->options();
}

- (BOOL)listener:(NSXPCListener*)listener shouldAcceptNewConnection:(NSXPCConnection*)connection {
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(IPCProtocol)];
    connection.exportedObject = self;
    [connection resume];
    return YES;
}

- (void)getStatusWithReply:(void (^)(NSString*, NSString*, NSString*))reply {
    logger()->debug("[IPC] remote call: getStatus");

    auto es = (platform::darwin::endpointSecurity()->isAvailable() ? "+ES" : "-ES");
    auto ne = (platform::darwin::networkExtension()->isAvailable() ? "+NE" : "-NE");

    auto version = [NSString stringWithUTF8String:Version];
    auto capabilities = join(std::vector<std::string>{es, ne}, " ");
    auto capabilities_ = [NSString stringWithUTF8String:capabilities.c_str()];
    auto agent_id = [NSString stringWithUTF8String:[[IPC sharedObject] options].agent_id.c_str()];
    reply(version, capabilities_, agent_id);
}

- (void)getOptionsWithReply:(void (^)(NSDictionary<NSString*, NSString*>*))reply {
    logger()->debug("[IPC] remote call: getOptions");

    auto options = [NSMutableDictionary dictionary];

    NSArray* keys = [NSArray arrayWithObjects:@"zeek.destination", @"log.level", nil];
    for ( id key in keys ) {
        NSString* value = [_defaults stringForKey:key];
        options[key] = (value ? value : @"");
    }

    reply(options);

    CFRelease(keys);
    CFRelease(options);
}

- (void)setOptions:(NSDictionary<NSString*, NSString*>*)options {
    logger()->debug("[IPC] remote call: setOptions");

    for ( id key in options ) {
        auto value = [options objectForKey:key];
        [_defaults setObject:value forKey:key];
    }
}

- (void)exit {
    logger()->debug("[IPC] remote call: exit");
    exit(0);
}
@end

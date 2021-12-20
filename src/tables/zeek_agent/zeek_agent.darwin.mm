// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "zeek_agent.h"

#include "autogen/config.h"
#include "core/database.h"

#include <chrono>

#include <Foundation/Foundation.h>
#include <Foundation/NSProcessInfo.h>
#include <SystemConfiguration/SCDynamicStore.h>
#include <sys/utsname.h>

using namespace zeek::agent;
using namespace zeek::agent::table;

namespace {

class ZeekAgentDarwin : public ZeekAgent {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres);
};

database::RegisterTable<ZeekAgentDarwin> _;

static Value primaryAddress() {
    // Adapted from: SCDynamicStoreRef storeRef = SCDynamicStoreCreate(NULL, (CFStringRef)@"FindCurrentInterfaceIpMac",
    // NULL, NULL);
    SCDynamicStoreRef storeRef = SCDynamicStoreCreate(NULL, (CFStringRef) @"FindCurrentInterfaceIpMac", NULL, NULL);
    if ( ! storeRef )
        return {};

    CFPropertyListRef global = SCDynamicStoreCopyValue(storeRef, CFSTR("State:/Network/Global/IPv4"));
    if ( ! global )
        return {};

    NSString* primaryInterface = [(__bridge NSDictionary*)global valueForKey:@"PrimaryInterface"];
    if ( ! primaryInterface )
        return {};

    std::string ipv4, ipv6;

    if ( auto interfaceState = [NSString stringWithFormat:@"State:/Network/Interface/%@/IPv4", primaryInterface] ) {
        if ( CFPropertyListRef state = SCDynamicStoreCopyValue(storeRef, (CFStringRef)interfaceState) ) {
            if ( NSString* ip = [(__bridge NSDictionary*)state valueForKey:@"Addresses"][0] )
                ipv4 = [ip UTF8String];

            CFRelease(state);
        }
    }

    if ( auto interfaceState = [NSString stringWithFormat:@"State:/Network/Interface/%@/IPv6", primaryInterface] ) {
        if ( CFPropertyListRef state = SCDynamicStoreCopyValue(storeRef, (CFStringRef)interfaceState) ) {
            if ( NSString* ip = [(__bridge NSDictionary*)state valueForKey:@"Addresses"][0] )
                ipv4 = [ip UTF8String];

            CFRelease(state);
        }
    }

    CFRelease(storeRef);

    return ipv4.size() ? ipv4 : ipv6;
}

std::vector<std::vector<Value>> ZeekAgentDarwin::snapshot(const std::vector<table::Where>& wheres) {
    std::vector<char> hostname_buffer(1024);
    gethostname(hostname_buffer.data(), static_cast<int>(hostname_buffer.size()));
    hostname_buffer.push_back(0);

    auto version = [[NSProcessInfo processInfo] operatingSystemVersionString];

    Value id = options().agent_id;
    Value hostname = hostname_buffer.data();
    Value address = primaryAddress();
    Value platform = "Darwin";
    Value os_name = std::string("macOS ") + std::string([version UTF8String]);
    Value agent = VersionNumber;
    Value broker = {}; // TODO
    Value uptime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock().now() - startupTime()).count();

    Value kernel_name, kernel_release, kernel_arch;
    struct utsname uname_info {};
    if ( uname(&uname_info) >= 0 ) {
        kernel_name = uname_info.sysname;
        kernel_release = uname_info.release;
        kernel_arch = uname_info.machine;
    }

    return {
        {id, hostname, address, platform, os_name, kernel_name, kernel_release, kernel_arch, agent, broker, uptime}};
}
} // namespace

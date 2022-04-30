// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "util/platform.h"

#include "util/platform.darwin.h"

#include <iostream>
#include <optional>

#include <Foundation/Foundation.h>
#include <util/filesystem.h>

using namespace zeek::agent;

std::optional<filesystem::path> platform::darwin::getApplicationSupport() {
    auto domain = platform::runningAsAdmin() ? NSLocalDomainMask : NSUserDomainMask;
    auto paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, domain, YES);
    auto dir = [paths firstObject];
    return filesystem::path([dir UTF8String]) / "ZeekAgent";
}

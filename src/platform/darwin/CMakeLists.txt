# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE platform.mm endpoint-security.mm network-extension.mm xpc.mm os-log-sink.mm)
target_link_libraries(zeek-agent PRIVATE "EndpointSecurity")
target_link_libraries(zeek-agent PRIVATE "-framework NetworkExtension")
target_link_libraries(zeek-agent PRIVATE "-framework Cocoa")
target_link_libraries(zeek-agent PRIVATE "bsm")

add_subdirectory(ZeekAgent.app)

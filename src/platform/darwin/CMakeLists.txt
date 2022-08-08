# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE platform.mm)
target_link_libraries(zeek-agent PRIVATE "EndpointSecurity")
target_link_libraries(zeek-agent PRIVATE "-framework NetworkExtension")
target_link_libraries(zeek-agent PRIVATE "-framework Cocoa")

add_subdirectory(ZeekAgent.app)

# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE zeek_agent.test.cc)

if ( HAVE_DARWIN )
    target_sources(zeek-agent PRIVATE zeek_agent.darwin.mm)
    target_link_libraries(zeek-agent PRIVATE "-framework Cocoa")
    target_link_libraries(zeek-agent PRIVATE "-framework SystemConfiguration")
endif ()

if ( HAVE_LINUX )
    target_sources(zeek-agent PRIVATE zeek_agent.linux.cc)
endif ()

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE zeek_agent.windows.cc)
endif ()

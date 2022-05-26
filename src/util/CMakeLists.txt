# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        ascii-table.cc
        helpers.cc
        platform.testing.cc
        result.cc
)

if ( HAVE_DARWIN )
    target_sources(zeek-agent PRIVATE platform.posix.cc platform.darwin.mm)
    target_link_libraries(zeek-agent PRIVATE "EndpointSecurity")
endif ()

if ( HAVE_LINUX )
    target_sources(zeek-agent PRIVATE platform.posix.cc platform.linux.cc)
endif ()

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE platform.windows.cc)
endif ()

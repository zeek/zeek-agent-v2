# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE users.test.cc)

if ( HAVE_DARWIN )
    target_sources(zeek-agent PRIVATE users.darwin.mm)
    target_link_libraries(zeek-agent PRIVATE "-framework Collaboration")
endif ()

if ( HAVE_LINUX )
    target_sources(zeek-agent PRIVATE users.linux.cc)
    target_link_libraries(zeek-agent PRIVATE pfs)
endif ()

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE users.windows.cc)
endif ()

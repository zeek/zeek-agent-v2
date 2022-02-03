# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE system_logs.test.cc)

if ( HAVE_DARWIN )
    target_sources(zeek-agent PRIVATE system_logs.darwin.cc)
    target_link_libraries(zeek-agent PRIVATE "-framework LoggingSupport")
    set_target_properties(zeek-agent PROPERTIES LINK_FLAGS "-Wl,-F/System/Library/PrivateFrameworks/")
endif ()

if ( HAVE_LINUX )
    target_sources(zeek-agent PRIVATE system_logs.linux.cc)
endif ()

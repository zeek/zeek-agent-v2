# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        testing.cc
)

if ( HAVE_DARWIN )
    add_subdirectory(darwin)
endif ()

if ( HAVE_LINUX )
    add_subdirectory(linux)
endif ()

if ( HAVE_WINDOWS )
    add_subdirectory(windows)
endif ()

# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        ascii-table.cc
        helpers.cc
        platform.cc
        result.cc
)

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE platform.windows.cc)
endif ()

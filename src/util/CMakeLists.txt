# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        ascii-table.cc
        helpers.cc
        platform.cc
        result.cc
)

if (WIN32)
    target_sources(zeek-agent PRIVATE windows-util.cc)
endif ()

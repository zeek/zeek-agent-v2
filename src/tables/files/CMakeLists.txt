# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE files.cc)

if ( HAVE_POSIX )
    target_sources(zeek-agent PRIVATE files.posix.cc)
endif ()

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE files.windows.cc)
endif ()

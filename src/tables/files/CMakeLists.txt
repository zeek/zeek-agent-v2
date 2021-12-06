# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE files.test.cc)

if ( HAVE_POSIX )
    target_sources(zeek-agent PRIVATE files.posix.cc)
endif ()

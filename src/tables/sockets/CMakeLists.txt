# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE sockets.test.cc)

if ( HAVE_DARWIN )
    target_sources(zeek-agent PRIVATE sockets.darwin.cc)
endif ()

if ( HAVE_LINUX )
    generate_bpf_code(zeek-agent sockets sockets.linux.bpf.c)
    target_sources(zeek-agent PRIVATE sockets.linux.cc)
endif ()

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE sockets.windows.cc)
endif ()

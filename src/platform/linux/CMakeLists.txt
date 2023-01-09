# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE platform.cc bpf.cc)
target_link_libraries(zeek-agent PRIVATE bpf)

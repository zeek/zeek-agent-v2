
if ( USE_STATIC_LINKING )
    set(OPENSSL_USE_STATIC_LIBS on)

    # CMake 3.24 has an option to find zlib's static library, but that's too
    # recent for us. So we use a hammer instead.
    # set(ZLIB_USE_STATIC_LIBS on)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif ()

# Configure OpenSSL first, it'll be used by both Broker and IXWebSocket.
find_package(OpenSSL REQUIRED)
include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})

if ( WIN32 )
  # We use C++20 on MSVC, which means we have full std::span support on that
  # platform
  option(UUID_USING_CXX20_SPAN "Using span from std instead of gsl" ON)

  # std::filesystem returns everything as UTF8 on Windows which means any call
  # to native() returns a std::wstring or a wchar_t. We need to trigger the
  # inclusion of fmt/xchar.h so that there's support for wide characters in
  # fmtlib when it includes it.
  set(SPDLOG_WCHAR_FILENAMES ON)
  set(SPDLOG_WCHAR_SUPPORT ON)
 endif()

add_subdirectory(doctest EXCLUDE_FROM_ALL)
add_subdirectory(fmt EXCLUDE_FROM_ALL)
add_subdirectory(replxx EXCLUDE_FROM_ALL)
add_subdirectory(json EXCLUDE_FROM_ALL)
add_subdirectory(stduuid EXCLUDE_FROM_ALL)
add_subdirectory(tomlplusplus EXCLUDE_FROM_ALL)
add_subdirectory(out_ptr EXCLUDE_FROM_ALL)

option(GHC_FILESYSTEM_WITH_INSTALL "With install target" ON)
add_subdirectory(filesystem EXCLUDE_FROM_ALL)

option(GLOB_USE_GHC_FILESYSTEM "Use ghc::filesystem instead of std::filesystem" ON)
add_subdirectory(glob EXCLUDE_FROM_ALL)

set(SPDLOG_FMT_EXTERNAL ON)
add_subdirectory(spdlog EXCLUDE_FROM_ALL)
# just setting SPDLOG_FMT_EXTERNAL isn't sufficient for some reason
target_compile_definitions(spdlog PUBLIC SPDLOG_FMT_EXTERNAL)
target_link_libraries(spdlog PUBLIC fmt)

# IXWebSocket will pick up on us having configured OpenSSL already.
option(USE_TLS "Enable TLS support" ON)
option(USE_OPEN_SSL "Use OpenSSL" ON)
option(IXWEBSOCKET_INSTALL "Install IXWebSocket" OFF)
add_subdirectory(IXWebSocket)

# pathfind's cmake config is too old and not really usable. Set it up ourselves.
add_library(pathfind STATIC pathfind/src/pathfind.cpp)
target_include_directories(pathfind PUBLIC pathfind/src)
add_library(pathfind::pathfind ALIAS pathfind)

# sqlite doesn't have a cmake config.
add_library(sqlite STATIC sqlite/sqlite3.c)
target_include_directories(sqlite PUBLIC sqlite)
# TODO: The following should help us receiving the original WHERE constraints
# instead of the optimizer mangling them, but it doesn't seem to have an effect.
target_compile_definitions(sqlite PRIVATE SQLITE_OMIT_LIKE_OPTIMIZATION)
target_compile_definitions(sqlite PRIVATE SQLITE_OMIT_OR_OPTIMIZATION)
target_compile_definitions(sqlite PRIVATE SQLITE_OMIT_BETWEEN_OPTIMIZATION)
target_compile_definitions(sqlite PRIVATE SQLITE_ENABLE_COLUMN_METADATA)
add_library(sqlite::sqlite ALIAS sqlite)

# Build a mininmal, static version of libroker.
if ( USE_BROKER )
    set(HAVE_BROKER YES)
    set(BROKER_DISABLE_DOCS ON)
    set(BROKER_DISABLE_TESTS ON)
    set(DISABLE_PYTHON_BINDINGS ON)
    set(ENABLE_STATIC_ONLY ON)
    set(BROKER_EXTERNAL_SQLITE_TARGET "sqlite::sqlite")

    add_subdirectory(broker EXCLUDE_FROM_ALL)
    target_link_libraries(broker_static INTERFACE ${CMAKE_DL_LIBS}) # linker gets the order wrong w/o this
else ()
    set(HAVE_BROKER NO)
endif ()

# adapted from Spicy
set(REPROC++ ON)
set(REPROC_MULTITHREADED OFF)
set(REPROC_OBJECT_LIBRARIES ON)
add_subdirectory(reproc EXCLUDE_FROM_ALL)
set_property(TARGET reproc PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET reproc++ PROPERTY POSITION_INDEPENDENT_CODE ON)

if ( HAVE_LINUX )
    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "" FORCE)
    add_subdirectory(pfs EXCLUDE_FROM_ALL)
    target_include_directories(pfs PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/pfs/include>")
    target_compile_definitions(pfs PRIVATE preadv64=preadv) # work-around preadv64 not being defined on Alpine 3.19.
endif()

if ( NOT HAVE_GETOPT_LONG )
    add_library(3rdparty STATIC bsd-getopt-long.c)
    target_include_directories(pathfind PUBLIC .)
    add_library(3rdparty:3rdparty ALIAS 3rdparty)
endif()

# On Linux, build libbpf.
if ( HAVE_LINUX )
    include(ExternalProject)

    find_program (llvm_strip llvm-strip REQUIRED) # needed by bpftools, ensure we have it
    find_library(elf NAMES elf REQUIRED)
    find_library(zstd NAMES zstd)

    set(bpftool_source "${CMAKE_CURRENT_SOURCE_DIR}/bpftool")
    set(bpftool_build "${CMAKE_CURRENT_BINARY_DIR}/bpftool")
    set(libbpf_lib "${bpftool_build}/bootstrap/libbpf")

    set(libbpf_include "${bpftool_build}/libbpf/include")
    file(MAKE_DIRECTORY ${libbpf_include})

    ExternalProject_Add(bpftool
        SOURCE_DIR "${bpftool_source}"
        BINARY_DIR "${bpftool_build}"
        BUILD_COMMAND make -C ${bpftool_source}/src OUTPUT=${bpftool_build}/
        DOWNLOAD_COMMAND ""
        CONFIGURE_COMMAND ""
        INSTALL_COMMAND make -C ${bpftool_source}/src OUTPUT=${bpftool_build}/ DESTDIR=${CMAKE_BINARY_DIR}/ prefix= install-bin
        BUILD_BYPRODUCTS ${libbpf_lib}/libbpf.a
        LOG_BUILD ON
        LOG_INSTALL ON
        LOG_OUTPUT_ON_FAILURE ON
    )

    # bpftools already comes with libbpf, and it conviniently builds a static
    # library as well. We'll just use that instead of re-building our own.
    add_library(bpf STATIC IMPORTED GLOBAL)
    set_target_properties(bpf PROPERTIES IMPORTED_LOCATION "${libbpf_lib}/libbpf.a")
    target_include_directories(bpf INTERFACE "${libbpf_include}")
    target_link_libraries(bpf INTERFACE ${elf})
    if ( zstd )
        target_link_libraries(bpf INTERFACE ${zstd})
    endif ()
    add_dependencies(bpf bpftool)

    set(BPFTOOL "${CMAKE_BINARY_DIR}/sbin/bpftool" PARENT_SCOPE)
    set(BPF_INCLUDE_DIR "${libbpf_include}" PARENT_SCOPE)
endif ()



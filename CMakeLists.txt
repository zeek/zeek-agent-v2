# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15.1)

project(ZeekAgent)

if ( CMAKE_SYSTEM_NAME STREQUAL "Darwin" )
    set(CMAKE_OSX_DEPLOYMENT_TARGET 11.0 CACHE STRING "Minimum macOS version" FORCE) # Big Sur

    # Hack to avoid CMake telling us that it doesn't support universal binaries for Swift.
    # We later enable universal binaries explicitly ourselves for Swift code.
    set(old_CMAKE_OSX_ARCHITECTURES "${CMAKE_OSX_ARCHITECTURES}")
    set(CMAKE_OSX_ARCHITECTURES "")
    enable_language(Swift)
    set(CMAKE_OSX_ARCHITECTURES "${old_CMAKE_OSX_ARCHITECTURES}")
endif ()

enable_language(C)
enable_language(CXX)

### Initialize defaults & global options

# Defaults here should match 'configure'.
option(USE_CCACHE "" "no")
option(USE_SANITIZERS "" "")
option(USE_WERROR "" "no")
option(USE_DOCTEST "" "yes")
option(USE_STATIC_LINKING "" "no")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if ( NOT CMAKE_BUILD_TYPE )
    # CMake doesn't set build type by default.
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

include(Util)

include(GNUInstallDirs)
if (NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY )
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
endif ()

if( NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY )
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
endif ()

if ( NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY )
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
endif ()

if ( USE_CCACHE )
    find_program(CCACHE_PROGRAM ccache)
    if( CCACHE_PROGRAM )
        set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
        set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    else ()
        set(USE_CCACHE "no (error: could not find ccache)")
    endif()
endif ()

if ( USE_STATIC_LINKING )
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

enable_testing()

### Determine version information

file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/VERSION ZEEK_AGENT_VERSION LIMIT_COUNT 1)
set(CMAKE_PROJECT_VERSION ${ZEEK_AGENT_VERSION})

# Get current git commit. If we cannot get the current commit (e.g., no .git
# directory present for release tarballs), this will leave ZEEK_AGENT_COMMIT unset.
execute_process(
    COMMAND ${CMAKE_COMMAND} -E env GIT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/.git git rev-parse --short HEAD
    OUTPUT_VARIABLE ZEEK_AGENT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE ignored)

if ( NOT "${SPICY_COMMIT}" STREQUAL "" )
    set(ZEEK_AGENT_VERSION_LONG "${ZEEK_AGENT_VERSION} (${ZEEK_AGENT_COMMIT})")
else ()
    set(ZEEK_AGENT_VERSION_LONG "${ZEEK_AGENT_VERSION}")
endif ()

### Platform-specific code.

if (UNIX)
  set(HAVE_POSIX true)
else()
  set(HAVE_POSIX false)
endif()

if ( CMAKE_SYSTEM_NAME STREQUAL "Darwin" )
    set(HAVE_DARWIN true)
elseif ( CMAKE_SYSTEM_NAME STREQUAL "Linux" )
    set(HAVE_LINUX true)
elseif ( CMAKE_SYSTEM_NAME STREQUAL "Windows" )
    set(HAVE_WINDOWS true)
else ()
    message(FATAL_ERROR "unknown platform, supporting only Linux and macOS currently")
endif()

### Additional targets.

include(ProcessorCount)
ProcessorCount(NUM_CPUS)
if(NUM_CPUS EQUAL 0)
    set(NUM_CPUS 1)
endif()

# Create a target for running clang-tidy through our helper script.
add_custom_target(tidy COMMAND ${CMAKE_SOURCE_DIR}/auxil/run-clang-tidy -j ${NUM_CPUS} ${CMAKE_BINARY_DIR})

### Add subdirectories.

add_subdirectory(3rdparty)
add_subdirectory(src)
add_subdirectory(packaging)

### Emit configuration summary.

if ( NOT "${USE_SANITIZERS}" )
    set(USE_SANITIZERS_DISPLAY "no")
endif ()

message(
    "\n====================|  Zeek Agent Build Summary  |===================="
    "\n"
    "\nVersion:               ${ZEEK_AGENT_VERSION_LONG}"
    "\n"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nBuild directory:       ${PROJECT_BINARY_DIR}"
    "\nInstall prefix:        ${CMAKE_INSTALL_PREFIX}"
    "\n"
    "\nHost system:           ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION} (${CMAKE_SYSTEM_PROCESSOR})"
    "\n"
    "\nBuild with tests:      ${USE_DOCTEST}"
    "\nUse ccache:            ${USE_CCACHE}"
    "\nUse sanitizers:        ${USE_SANITIZERS_DISPLAY}"
    "\nLink statically:       ${USE_STATIC_LINKING}"
    "\n"
    "\nWarnings are errors:   ${USE_WERROR}"
    "\n"
    "\n================================================================\n"
)

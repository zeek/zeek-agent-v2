
set(SPDLOG_FMT_EXTERNAL ON)
option(UUID_BUILD_TESTS "Build the unit tests" OFF)

add_subdirectory(doctest EXCLUDE_FROM_ALL)
add_subdirectory(filesystem EXCLUDE_FROM_ALL)
add_subdirectory(fmt EXCLUDE_FROM_ALL)
add_subdirectory(replxx EXCLUDE_FROM_ALL)
add_subdirectory(json EXCLUDE_FROM_ALL)
add_subdirectory(spdlog EXCLUDE_FROM_ALL)
add_subdirectory(stduuid EXCLUDE_FROM_ALL)
add_subdirectory(tomlplusplus EXCLUDE_FROM_ALL)

# pathfind's cmake config is too old and not really usable. Set it up ourselves.
add_library(pathfind STATIC pathfind/src/pathfind.cpp)
target_include_directories(pathfind PUBLIC pathfind/src)
add_library(pathfind::pathfind ALIAS pathfind)

# sqlite doesn't have a cmake config.
add_library(sqlite STATIC sqlite/sqlite3.c)
target_include_directories(sqlite PUBLIC sqlite)
add_library(sqlite::sqlite ALIAS sqlite)

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
    target_include_directories(pfs PUBLIC pfs/include)
endif()

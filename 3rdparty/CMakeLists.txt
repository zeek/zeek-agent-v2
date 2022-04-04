
set(SPDLOG_FMT_EXTERNAL ON)
option(UUID_BUILD_TESTS "Build the unit tests" OFF)

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
add_subdirectory(filesystem EXCLUDE_FROM_ALL)
add_subdirectory(fmt EXCLUDE_FROM_ALL)
add_subdirectory(replxx EXCLUDE_FROM_ALL)
add_subdirectory(json EXCLUDE_FROM_ALL)
add_subdirectory(spdlog EXCLUDE_FROM_ALL)
add_subdirectory(stduuid EXCLUDE_FROM_ALL)
add_subdirectory(tomlplusplus EXCLUDE_FROM_ALL)
add_subdirectory(out_ptr EXCLUDE_FROM_ALL)

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
set(BROKER_DISABLE_DOCS ON)
set(BROKER_DISABLE_TESTS ON)
set(DISABLE_PYTHON_BINDINGS ON)
set(ENABLE_STATIC_ONLY ON)
set(BROKER_EXTERNAL_SQLITE_TARGET "sqlite::sqlite")

if ( USE_STATIC_LINKING )
    set(OPENSSL_USE_STATIC_LIBS on)
endif ()

add_subdirectory(broker EXCLUDE_FROM_ALL)
target_link_libraries(broker_static INTERFACE ${CMAKE_DL_LIBS}) # linker gets the order wrong w/o this

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

if ( NOT HAVE_GETOPT_LONG )
    add_library(3rdparty STATIC bsd-getopt-long.c)
    target_include_directories(pathfind PUBLIC .)
    add_library(3rdparty:3rdparty ALIAS 3rdparty)
endif()

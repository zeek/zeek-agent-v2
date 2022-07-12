
# OS-independent CPack configuration.
set(CPACK_COMPONENTS_ALL "")
set(CPACK_OUTPUT_FILE_PREFIX "dist")
set(CPACK_PACKAGE_CONTACT "info@zeek.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Zeek Agent is an endpoint monitoring tool reporting host information to Zeek.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://zeek.org")
set(CPACK_PACKAGE_RELOCATABLE yes)
set(CPACK_PACKAGE_VENDOR "Zeek Project")
set(CPACK_PACKAGE_VERSION "${ZEEK_AGENT_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${ZEEK_AGENT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${ZEEK_AGENT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${ZEEK_AGENT_VERSION_PATCH}")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "zeek-agent-${ZEEK_AGENT_VERSION}-source")

list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/build/")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/build-.*/")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/.cache/")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/.clangd/")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/.*\.git/")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/compile_commands\.json$")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/\.swp$")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/\.pyc$")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_BINARY_DIR}/")

if ( HAVE_DARWIN )
    # Note to future self: CMake's "productbuild" generator doesn't really
    # work. It's hard to parameterize, and doesn't install things the way we
    # want. So doing using CMake's bundle to build the container app, and
    # putting the extensions in there manually to get the right structure.

    # CPack configuration for the outer container app. The extension bundles
    # are set up manually inside darwin/ZeekAgent.app/CMakeLists.txt.
    set(CPACK_GENERATOR "Bundle")
    set(CPACK_SYSTEM_NAME "macos${MACOS_MINIMUM_VERSION}")
    set(CPACK_APPLE_BUNDLE_ID "org.zeek.zeek-agent")
    set(CPACK_BUNDLE_ICON "${CMAKE_CURRENT_SOURCE_DIR}/darwin/ZeekAgent.app/ZeekAgent.icns")
    set(CPACK_BUNDLE_NAME "ZeekAgent")
    set(CPACK_BUNDLE_PLIST "${CMAKE_CURRENT_BINARY_DIR}/darwin/ZeekAgent.app/Info.plist.app")
    set(CPACK_DMG_DISABLE_APPLICATIONS_SYMLINK no)
    set(CPACK_DMG_VOLUME_NAME "Zeek Agent ${CPACK_PACKAGE_VERSION}")

    set(CPACK_POST_BUILD_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/darwin/post-build.cmake")
    set(CPACK_COMMAND_HDIUTIL "${CMAKE_CURRENT_SOURCE_DIR}/darwin/hdiutil-with-codesign")

    add_subdirectory(darwin/ZeekAgent.app)
elseif ( HAVE_LINUX )
    set(CPACK_GENERATOR "TGZ")
    set(CPACK_SYSTEM_NAME "linux-${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif ()

set(CPACK_PACKAGE_FILE_NAME "zeek-agent-${ZEEK_AGENT_VERSION}-${CPACK_SYSTEM_NAME}")

include(CPack)

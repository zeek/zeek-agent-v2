
# OS-independent CPack configuration.
set(CPACK_COMPONENTS_ALL "")
set(CPACK_OUTPUT_FILE_PREFIX "dist")
set(CPACK_PACKAGE_NAME "ZeekAgent")
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

set(ZEEK_PACKAGE_FILE_NAME_BASE "zeek-agent-${ZEEK_AGENT_VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${ZEEK_PACKAGE_FILE_NAME_BASE}-source")

list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/build/")
list(APPEND CPACK_SOURCE_IGNORE_FILES "^${CMAKE_SOURCE_DIR}.*/out/")
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
elseif ( HAVE_WINDOWS )
    # Include all dynamically linked runtime libaries such as MSVCRxxx.dll
    include(InstallRequiredSystemLibraries)

    set(CPACK_GENERATOR WIX)
    set(CPACK_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/windows" ${CPACK_MODULE_PATH})
    set(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}/windows\\\\icon.bmp")
    set(CPACK_PACKAGE_FILE_NAME "${ZEEK_PACKAGE_FILE_NAME_BASE}")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "${CMAKE_PROJECT_NAME}")

    # WIX expects the version number to be formatted like a.b.c.d. We use the commit
    # number from the dev info if needed for the last value.
    set(CPACK_PACKAGE_VERSION "${ZEEK_AGENT_VERSION_MAJOR}.${ZEEK_AGENT_VERSION_MINOR}.${ZEEK_AGENT_VERSION_PATCH}.${ZEEK_AGENT_VERSION_COMMITNUM}")

    # Don't ask to make links on the desktop
    set(CPACK_CREATE_DESKTOP_LINKS OFF)

    # TODO: This sets to the version of Windows where the build was done. Should it be the targeted
    # Windows SDK version instead?
    set(CPACK_SYSTEM_NAME "windows-${CMAKE_SYSTEM_VERSION}")

    # WIX wants the version number to be in x.x.x.x format. Anything else is invalid.
    string(REPLACE "-" "\." CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION}")

    set(CPACK_WIX_UPGRADE_GUID "FEA1F3E0-AA96-4843-85DF-BA001997EFED")
    set(CPACK_WIX_PRODUCT_ICON "${CMAKE_CURRENT_SOURCE_DIR}/windows/icon.ico")
    set(CPACK_WIX_UI_BANNER "${CMAKE_CURRENT_SOURCE_DIR}/windows/banner.png")
    set(CPACK_WIX_UI_DIALOG "${CMAKE_CURRENT_SOURCE_DIR}/windows/sidebar.png")

    # These are needed in order to put the zeek-agent.cfg template file in a directory outside of
    # the normal program files directory. wix-patch.xml also includes the configuration for
    # installing the application as a service.
    file(COPY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/zeek-agent.cfg.template" "${CMAKE_CURRENT_BINARY_DIR}/zeek-agent.cfg")
    set(ZEEK_AGENT_CONF_FILE_NAME "zeek-agent.cfg")
    configure_file("windows/wix-extra.xml.in" "wix-extra.xml")
    set(CPACK_WIX_EXTRA_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/wix-extra.xml")
    set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/windows/wix-patch.xml")

    # WiX wants the license file in a file with a .txt or .rtf extension specifically.
    file(COPY_FILE "${CMAKE_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt" ONLY_IF_DIFFERENT)
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt")

    # Include the string overrides file to rewrite the text on the final panel of the installer.
    # configure_file("windows/wix-string-overrides.wxl.in" "wix-string-overrides.wxl")
    # set(CPACK_WIX_LIGHT_EXTRA_FLAGS  "-loc" "${CMAKE_CURRENT_BINARY_DIR}/wix-string-overrides.wxl")
    set(CPACK_WIX_LIGHT_EXTRA_FLAGS  "-loc" "${CMAKE_CURRENT_SOURCE_DIR}/windows/wix-string-overrides.wxl")

    install(FILES "${CMAKE_SOURCE_DIR}/LICENSE" DESTINATION . RENAME LICENSE.txt)

endif ()

if ( NOT HAVE_WINDOWS )
    set(CPACK_PACKAGE_FILE_NAME "${ZEEK_PACKAGE_FILE_NAME_BASE}-${CPACK_SYSTEM_NAME}")
endif ()

include(CPack)

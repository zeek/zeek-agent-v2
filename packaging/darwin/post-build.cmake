
set(installers "")

foreach (pkg "${CPACK_PACKAGE_FILES}")
    STRING(REPLACE ".dmg" "" bundle "${pkg}")
    execute_process(COMMAND ${CMAKE_CURRENT_LIST_DIR}/create-installer "${bundle}/${CPACK_BUNDLE_NAME}.app" "${bundle}.pkg" "${CMAKE_CURRENT_LIST_DIR}/.." "${CPACK_PACKAGE_DIRECTORY}/" "${CPACK_PACKAGE_VERSION}" COMMAND_ERROR_IS_FATAL ANY)
    list(APPEND installers "${bundle}.pkg")
endforeach()

if ("$ENV{MACOS_CERTIFICATE_APPLICATION_ID}" STREQUAL "" OR "$ENV{MACOS_NOTARIZATION_USER}" STREQUAL "")
    message(STATUS "Not running notarization: MACOS_CERTIFICATE_APPLICATION_ID/MACOS_NOTARIZATION_USER not set")
    return()
endif()

foreach (pkg "${installers}")
    execute_process(COMMAND ${CMAKE_CURRENT_LIST_DIR}/notarize installer "${pkg}" COMMAND_ERROR_IS_FATAL ANY)
endforeach()

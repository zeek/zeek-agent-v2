if ("$ENV{MACOS_CERTIFICATE_APPLICATION_ID}" STREQUAL "" OR "$ENV{MACOS_APP_ID}" STREQUAL "" OR "$ENV{MACOS_NOTARIZATION_USER}" STREQUAL "")
    message(STATUS "Not running code signing: MACOS_CERTIFICATE_APPLICATION_ID/MACOS_APP_ID/MACOS_NOTARIZATION_USER not set")
    return()
endif()

foreach (pkg "${CPACK_PACKAGE_FILES}")
    execute_process(COMMAND ${CMAKE_CURRENT_LIST_DIR}/notarize "${pkg}" COMMAND_ERROR_IS_FATAL ANY)
endforeach()
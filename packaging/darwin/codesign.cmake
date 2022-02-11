# We reuse CPack's variable here to specify the certificate. Needs to be string
# "Developer ID Application: XXX (YYY)". Certificate needs to be in keychain.
if (NOT $ENV{CPACK_BUNDLE_APPLE_CERT_APP} STREQUAL "")
    message("=== Perform Darwin code signing")

    set(CODESIGN_TARGETS ${CPACK_TEMPORARY_INSTALL_DIRECTORY}/bin/zeek-agent)

    foreach (target ${CODESIGN_TARGETS})
        execute_process(COMMAND codesign
                            --force
                            --strict
                            --options=runtime
                            --identifier "org.zeek.zeek-agent"
                            --sign "$ENV{CPACK_BUNDLE_APPLE_CERT_APP}"
                            --timestamp
                            ${target}
                        RESULT_VARIABLE STATUS)

        if (STATUS AND NOT STATUS EQUAL 0)
            message(FATAL_ERROR "codesign failed: ${STATUS}")
        endif()

        execute_process(COMMAND codesign -dv ${target}
                        RESULT_VARIABLE STATUS)

        if (STATUS AND NOT STATUS EQUAL 0)
            message(FATAL_ERROR "codesign could not verify: ${STATUS}")
        endif()

    endforeach()
else()
    message(STATUS "Not running codesign: CPACK_BUNDLE_APPLE_CERT_APP is not set")
endif()

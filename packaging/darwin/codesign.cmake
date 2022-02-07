# We reuse CPack's variable here to specify the certificate. Needs to be string
# "Developer ID Application: XXX (YYY)". Certificate needs to be in keychain.
if (NOT $ENV{CPACK_BUNDLE_APPLE_CERT_APP} STREQUAL "")
    message("=== Perform Darwin code signing")

    set(CODESIGN_TARGETS ${CPACK_TEMPORARY_INSTALL_DIRECTORY}/bin/zeek-agent)

    foreach (target ${CODESIGN_TARGETS})
        execute_process(COMMAND codesign
                --force
                --identifier "org.zeek.zeek-agent"
                --sign "Developer ID Application: Robin Sommer (JHQJS8VH7W)"
                --timestamp
                ${target})
        execute_process(COMMAND codesign -dv ${target})
    endforeach()
else()
    message(WARNING "Cannot run codesign: CPACK_BUNDLE_APPLE_CERT_APP is not set")
endif()

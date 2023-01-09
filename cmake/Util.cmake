# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.
#
# A collection of small helpers for the Zeek Agent build system.

# Warn or abort if we don't a given version isn't recent enough.
function(require_version name found have need require)
    if ( NOT ${found} )
        if ( require )
            message(FATAL_ERROR "${name} required, but not found")
        else ()
            set(${found} no PARENT_SCOPE)
            set(${have} "not found")
        endif ()
    else ()
         if ( ${have} VERSION_LESS "${need}" )
            if ( require )
                message(FATAL_ERROR "Need ${name} version >= ${need}, found ${${have}}")
            endif ()

            message(STATUS "Warning: Need ${name} version >= ${need}, found ${${have}}")
            set(${found} no PARENT_SCOPE)
            set(${have} "${${have}} (error: too old, must be at least ${zeek_mininum_version})" PARENT_SCOPE)
        endif()
    endif()
endfunction ()

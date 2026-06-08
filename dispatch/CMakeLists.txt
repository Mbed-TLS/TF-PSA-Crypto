# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright The Mbed TLS Contributors

if(GEN_FILES)
    add_custom_command(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers.h
            ${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers_no_static.c
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
                ${PROJECT_SOURCE_DIR}/scripts/generate_driver_wrappers.py
                ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS
            ${PROJECT_SOURCE_DIR}/scripts/generate_driver_wrappers.py
            ${PROJECT_SOURCE_DIR}/scripts/data_files/driver_templates/psa_crypto_driver_wrappers.h.jinja
            ${PROJECT_SOURCE_DIR}/scripts/data_files/driver_templates/psa_crypto_driver_wrappers_no_static.c.jinja
    )

    add_custom_target(
            ${TF_PSA_CRYPTO_TARGET_PREFIX}libtfpsacrypto_generated_dispatch_target
        DEPENDS
            "${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers.h"
            "${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers_no_static.c"
        )

    # List generated headers as sources explicitly. Normally CMake finds
    # headers by tracing include directives, but if that happens before the
    # generated headers are generated, this process doesn't find them.
    list(APPEND dispatch_src_files
        "${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers.h"
        "${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers_no_static.c"
    )
else()
    list(APPEND dispatch_src_files
        "${CMAKE_CURRENT_SOURCE_DIR}/psa_crypto_driver_wrappers_no_static.c"
    )
endif(GEN_FILES)

set(tf_psa_crypto_objlib "dispatch")
include(${PROJECT_SOURCE_DIR}/objlib.cmake)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
    install(DIRECTORY "include/"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

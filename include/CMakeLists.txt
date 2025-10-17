option(INSTALL_TF_PSA_CRYPTO_HEADERS "Install TF PSA Crypto headers." ON)

# The handling of TF_PSA_CRYPTO_CONFIG_NAME assumes that the default
# configuration file 'include/psa/crypto_config.h' exists in the source tree.
# That file is copied into the build tree and then modified with 'config.py'
# according to the configuration name provided via TF_PSA_CRYPTO_CONFIG_NAME.
set(TF_PSA_CRYPTO_CONFIG_NAME "" CACHE STRING "Name of the configuration to use (see config.py documentation)")

if(TF_PSA_CRYPTO_CONFIG_NAME)
    if(TF_PSA_CRYPTO_CONFIG_FILE)
        message(FATAL_ERROR "TF_PSA_CRYPTO_CONFIG_NAME and TF_PSA_CRYPTO_CONFIG_FILE are incompatible.")
    endif()
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/psa)
    configure_file(${PROJECT_SOURCE_DIR}/include/psa/crypto_config.h
                   ${CMAKE_CURRENT_BINARY_DIR}/psa/crypto_config.h
                   COPYONLY)

    message(STATUS "Setting ${TF_PSA_CRYPTO_CONFIG_NAME} configuration")
    execute_process(
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/scripts/config.py
            -f ${CMAKE_CURRENT_BINARY_DIR}/psa/crypto_config.h
            ${TF_PSA_CRYPTO_CONFIG_NAME}
        RESULT_VARIABLE result
    )
    if(result)
        message(FATAL_ERROR "Setting ${TF_PSA_CRYPTO_CONFIG_NAME} configuration failed")
    endif()
endif(TF_PSA_CRYPTO_CONFIG_NAME)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
    file(GLOB psa_headers "psa/*.h")
    file(GLOB tf-psa-crypto_headers "tf-psa-crypto/*.h")
    file(GLOB mbedtls_crypto_headers "../drivers/builtin/include/mbedtls/*.h" "mbedtls/*.h")

    if(TF_PSA_CRYPTO_CONFIG_NAME)
        list(REMOVE_ITEM psa_headers "${PROJECT_SOURCE_DIR}/include/psa/crypto_config.h")
        list(APPEND psa_headers "${CMAKE_CURRENT_BINARY_DIR}/psa/crypto_config.h")
    endif()

    install(FILES ${psa_headers}
        DESTINATION include/psa
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(FILES ${tf-psa-crypto_headers}
        DESTINATION include/tf-psa-crypto
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(FILES ${mbedtls_crypto_headers}
        DESTINATION include/mbedtls
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

option(INSTALL_TF_PSA_CRYPTO_HEADERS "Install TF PSA Crypto headers." ON)

# Generate a build-tree configuration when transformations are requested.
if(TF_PSA_CRYPTO_CONFIG_NAME OR TF_PSA_CRYPTO_CONFIG_SET OR
   TF_PSA_CRYPTO_CONFIG_UNSET)
    if(TF_PSA_CRYPTO_CONFIG_FILE)
        set(TF_PSA_CRYPTO_BASE_CONFIG_FILE "${TF_PSA_CRYPTO_CONFIG_FILE}")
        if(NOT EXISTS "${TF_PSA_CRYPTO_BASE_CONFIG_FILE}")
            file(RELATIVE_PATH TF_PSA_CRYPTO_CONFIG_FILE_RELATIVE
                 "${PROJECT_BINARY_DIR}" "${TF_PSA_CRYPTO_CONFIG_FILE}")
            set(TF_PSA_CRYPTO_BASE_CONFIG_FILE
                "${PROJECT_SOURCE_DIR}/${TF_PSA_CRYPTO_CONFIG_FILE_RELATIVE}")
        endif()
    else()
        set(TF_PSA_CRYPTO_BASE_CONFIG_FILE
            "${PROJECT_SOURCE_DIR}/include/psa/crypto_config.h")
    endif()
    if(NOT EXISTS "${TF_PSA_CRYPTO_BASE_CONFIG_FILE}")
        message(FATAL_ERROR
            "TF-PSA-Crypto configuration file not found: ${TF_PSA_CRYPTO_BASE_CONFIG_FILE}")
    endif()

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/psa)
    set(TF_PSA_CRYPTO_GENERATED_CONFIG_FILE
        "${CMAKE_CURRENT_BINARY_DIR}/psa/crypto_config.h")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E copy
                "${TF_PSA_CRYPTO_BASE_CONFIG_FILE}"
                "${TF_PSA_CRYPTO_GENERATED_CONFIG_FILE}"
        RESULT_VARIABLE result
    )
    if(result)
        message(FATAL_ERROR
            "Failed to copy the TF-PSA-Crypto base configuration file")
    endif()

    function(tf_psa_crypto_configure_generated_file)
        execute_process(
            COMMAND
                ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
                "${PROJECT_SOURCE_DIR}/scripts/config.py"
                --file "${TF_PSA_CRYPTO_GENERATED_CONFIG_FILE}"
                ${ARGN}
            RESULT_VARIABLE result
        )
        if(result)
            message(FATAL_ERROR
                "Failed to configure the generated TF-PSA-Crypto configuration file")
        endif()
    endfunction(tf_psa_crypto_configure_generated_file)

    if(TF_PSA_CRYPTO_CONFIG_NAME)
        tf_psa_crypto_configure_generated_file("${TF_PSA_CRYPTO_CONFIG_NAME}")
    endif()
    foreach(option IN LISTS TF_PSA_CRYPTO_CONFIG_UNSET)
        tf_psa_crypto_configure_generated_file(unset "${option}")
    endforeach(option)
    foreach(option IN LISTS TF_PSA_CRYPTO_CONFIG_SET)
        string(FIND "${option}" "=" separator)
        if(separator EQUAL -1)
            tf_psa_crypto_configure_generated_file(--force set "${option}")
        else()
            string(SUBSTRING "${option}" 0 ${separator} name)
            math(EXPR value_start "${separator} + 1")
            string(SUBSTRING "${option}" ${value_start} -1 value)
            tf_psa_crypto_configure_generated_file(--force set "${name}" "${value}")
        endif()
    endforeach(option)

    set(TF_PSA_CRYPTO_CONFIG_FILE "${TF_PSA_CRYPTO_GENERATED_CONFIG_FILE}")
    set(TF_PSA_CRYPTO_CONFIG_FILE "${TF_PSA_CRYPTO_GENERATED_CONFIG_FILE}"
        PARENT_SCOPE)
    set(TF_PSA_CRYPTO_CONFIG_TRANSFORMED ON)
    set(TF_PSA_CRYPTO_CONFIG_TRANSFORMED ON PARENT_SCOPE)
endif()

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
    install(DIRECTORY "."
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h"
        PATTERN "crypto_config.h" EXCLUDE
    )

    if(NOT TF_PSA_CRYPTO_CONFIG_TRANSFORMED)
        install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/psa/crypto_config.h"
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/psa)
    else()
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/psa/crypto_config.h"
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/psa)
    endif()
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

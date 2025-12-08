set(pqcp_target "${TF_PSA_CRYPTO_TARGET_PREFIX}pqcp")
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(pqcp_static_target ${pqcp_target})
endif()
set(target_libraries ${pqcp_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND pqcp_static_target "_static")
    list(APPEND target_libraries ${pqcp_static_target})
endif()

file(GLOB src_pqcp RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} src/*.c)
foreach (target IN LISTS target_libraries)
    add_library(${target} OBJECT
        ${src_pqcp}
        #mldsa-native/mldsa/mldsa_native.c
    )

    tf_psa_crypto_set_base_compile_options(${target})

#    target_compile_options(${target} PRIVATE "-DMLD_CONFIG_FILE=\"tf-psa-crypto/build_info.h\"")

    target_include_directories(${target}
        PRIVATE mldsa-native/mldsa
        PRIVATE include
        PRIVATE ${TF_PSA_CRYPTO_DIR}/include
        PRIVATE ${TF_PSA_CRYPTO_DIR}/drivers/builtin/include
        PRIVATE ${TF_PSA_CRYPTO_DIR}/drivers/everest/include
    )
    tf_psa_crypto_set_config_files_compile_definitions(${target})
endforeach(target)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${pqcp_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
  install(FILES mldsa-native/mldsa/mldsa-native.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

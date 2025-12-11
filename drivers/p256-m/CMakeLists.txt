set(p256-m_target "${TF_PSA_CRYPTO_TARGET_PREFIX}p256-m")
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(p256-m_static_target ${p256-m_target})
endif()
set(target_libraries ${p256-m_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND p256-m_static_target "_static")
    list(APPEND target_libraries ${p256-m_static_target})
endif()

foreach (target IN LISTS target_libraries)
    add_library(${target} OBJECT
        p256-m_driver_entrypoints.c
        p256-m/p256-m.c)

    tf_psa_crypto_set_base_compile_options(${target})

    target_include_directories(${target}
      PUBLIC p256-m
      PRIVATE ${TF_PSA_CRYPTO_DIR}/include
              ${TF_PSA_CRYPTO_DIR}/core
              ${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS}
    )
    tf_psa_crypto_set_config_files_compile_definitions(${target})
endforeach(target)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${p256-m_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

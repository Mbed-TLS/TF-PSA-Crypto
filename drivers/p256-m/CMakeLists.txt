set(p256m_target "${TF_PSA_CRYPTO_TARGET_PREFIX}p256m_objs")
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(p256m_static_target ${p256m_target})
endif()
set(target_libraries ${p256m_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND p256m_static_target "_static")
    list(APPEND target_libraries ${p256m_static_target})
endif()

foreach (target IN LISTS target_libraries)
    add_library(${target} OBJECT
        p256-m_driver_entrypoints.c
        p256-m/p256-m.c)

    set_base_compile_options(${target})

    target_include_directories(${target}
      PRIVATE p256-m
              ${TF_PSA_CRYPTO_DIR}/include
              ${TF_PSA_CRYPTO_DIR}/core
              ${TF_PSA_CRYPTO_DIR}/drivers/builtin/include
              ${TF_PSA_CRYPTO_DIR}/drivers/everest/include)
    set_config_files_compile_definitions(${target})
endforeach(target)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${p256m_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)


file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/dummy_p256m.c" "")
set(dummy_p256m_target ${TF_PSA_CRYPTO_TARGET_PREFIX}p256m)
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(dummy_p256m_static_target ${dummy_p256m_target})
endif()
set(target_dummy_libraries ${dummy_p256m_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND dummy_p256m_static_target "_static")
    list(APPEND target_libraries ${dummy_p256m_static_target})
endif()

if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    add_library(${dummy_p256m_static_target}
      STATIC "${CMAKE_CURRENT_BINARY_DIR}/dummy_p256m.c")
    install(TARGETS ${dummy_p256m_static_target}
      EXPORT MbedTLSTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(TARGETS ${dummy_p256m_static_target}
      EXPORT TF-PSA-CryptoTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(USE_STATIC_TF_PSA_CRYPTO_LIBRARY)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    add_library(${dummy_p256m_target}
      SHARED "${CMAKE_CURRENT_BINARY_DIR}/dummy_p256m.c")
    set_property(TARGET ${dummy_p256m_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
    install(TARGETS ${dummy_p256m_target}
      EXPORT MbedTLSTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(TARGETS ${dummy_p256m_target}
      EXPORT TF-PSA-CryptoTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

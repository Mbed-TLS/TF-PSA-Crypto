set(everest_target "${TF_PSA_CRYPTO_TARGET_PREFIX}everest_objs")
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(everest_static_target ${everest_target})
endif()
set(target_libraries ${everest_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND everest_static_target "_static")
    list(APPEND target_libraries ${everest_static_target})
endif()

foreach (target IN LISTS target_libraries)
    add_library(${target} OBJECT
      library/everest.c
      library/x25519.c
      library/Hacl_Curve25519_joined.c)

    set_base_compile_options(${target})
    target_include_directories(${target}
      PRIVATE include
              ${TF_PSA_CRYPTO_DIR}/include
              ${TF_PSA_CRYPTO_DIR}/drivers/builtin/include
              include/tf-psa-crypto/private/everest
              include/tf-psa-crypto/private/everest/kremlib
              ${TF_PSA_CRYPTO_DIR}/core)
    set_config_files_compile_definitions(${target})
endforeach(target)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${everest_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)

  install(DIRECTORY include/tf-psa-crypto/private/everest
    DESTINATION include/tf-psa-crypto/private/everest
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    FILES_MATCHING PATTERN "*.h")

endif(INSTALL_TF_PSA_CRYPTO_HEADERS)


file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/dummy_everest.c" "")
set(dummy_everest_target ${TF_PSA_CRYPTO_TARGET_PREFIX}everest)
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(dummy_everest_static_target ${dummy_everest_target})
endif()
set(target_dummy_libraries ${dummy_everest_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND dummy_everest_static_target "_static")
    list(APPEND target_libraries ${dummy_everest_static_target})
endif()

if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    add_library(${dummy_everest_static_target}
      STATIC "${CMAKE_CURRENT_BINARY_DIR}/dummy_everest.c")
    install(TARGETS ${dummy_everest_static_target}
      EXPORT MbedTLSTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(TARGETS ${dummy_everest_static_target}
      EXPORT TF-PSA-CryptoTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(USE_STATIC_TF_PSA_CRYPTO_LIBRARY)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    add_library(${dummy_everest_target}
      SHARED "${CMAKE_CURRENT_BINARY_DIR}/dummy_everest.c")
    set_property(TARGET ${dummy_everest_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
    install(TARGETS ${dummy_everest_target}
      EXPORT MbedTLSTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(TARGETS ${dummy_everest_target}
      EXPORT TF-PSA-CryptoTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

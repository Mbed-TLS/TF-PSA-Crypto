set(p256m_target ${TF_PSA_CRYPTO_TARGET_PREFIX}p256m)

add_library(${p256m_target}
    p256-m_driver_entrypoints.c
    p256-m/p256-m.c)

set_base_compile_options(${p256m_target})

target_include_directories(${p256m_target}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
         $<BUILD_INTERFACE:${TF_PSA_CRYPTO_DIR}/include>
         $<BUILD_INTERFACE:${TF_PSA_CRYPTO_DIR}/drivers/builtin/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE ${TF_PSA_CRYPTO_DIR}/core
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/p256-m>
          $<BUILD_INTERFACE:${TF_PSA_CRYPTO_DIR}/drivers/everest/include/tf-psa-crypto/private/>)
set_config_files_compile_definitions(${p256m_target})

install(TARGETS ${p256m_target}
  EXPORT MbedTLSTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(TARGETS ${p256m_target}
  EXPORT TF-PSA-CryptoTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

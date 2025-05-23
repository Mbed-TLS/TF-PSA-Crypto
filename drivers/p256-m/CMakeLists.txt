set(p256m_target ${TF_PSA_CRYPTO_TARGET_PREFIX}p256m_objs)

add_library(${p256m_target} OBJECT
    p256-m_driver_entrypoints.c
    p256-m/p256-m.c)

set_base_compile_options(${p256m_target})

target_include_directories(${p256m_target}
  PRIVATE p256-m
          ${TF_PSA_CRYPTO_DIR}/include
          ${TF_PSA_CRYPTO_DIR}/core
          ${TF_PSA_CRYPTO_DIR}/drivers/builtin/include
          ${TF_PSA_CRYPTO_DIR}/drivers/everest/include)
set_config_files_compile_definitions(${p256m_target})

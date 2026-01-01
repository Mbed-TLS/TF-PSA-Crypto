file(GLOB builtin_src_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} src/*.c)
# RISCV64 assembly files
if(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    file(GLOB riscv_asm_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/*.S")
    list(APPEND builtin_src_files ${riscv_asm_files})
endif()
set(tf_psa_crypto_driver "builtin")
include(${PROJECT_SOURCE_DIR}/drivers/driver.cmake)

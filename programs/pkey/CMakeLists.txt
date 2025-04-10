set(executables_mbedcrypto
    rsa_sign_pss
    rsa_verify_pss
)
add_dependencies(${programs_target} ${executables_mbedcrypto})

foreach(exe IN LISTS executables_mbedcrypto)
    add_executable(${exe} ${exe}.c ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/tests/src/helpers.c ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/tests/src/drivers/platform_builtin_keys.c)
    set_base_compile_options(${exe})
    target_link_libraries(${exe} ${tfpsacrypto_target} ${CMAKE_THREAD_LIBS_INIT})
    target_include_directories(${exe} PRIVATE ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/tests/include ../../core/)
endforeach()

install(TARGETS ${executables_mbedcrypto}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

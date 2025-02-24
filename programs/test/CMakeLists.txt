set(executables
    benchmark
)

foreach(exe IN LISTS executables)
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:tf_psa_crypto_test>)
    set_base_compile_options(${exe})
    target_link_libraries(${exe} ${tfpsacrypto_target} ${CMAKE_THREAD_LIBS_INIT})
    target_include_directories(${exe} PRIVATE ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/framework/tests/include)
endforeach()

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY AND NOT ${CMAKE_SYSTEM_NAME} MATCHES "[Ww][Ii][Nn]")
    add_executable(dlopen "dlopen.c")
    set_base_compile_options(dlopen)
    target_include_directories(dlopen PRIVATE ${TF_PSA_CRYPTO_DIR}/drivers/builtin/include/)
    target_link_libraries(dlopen ${CMAKE_DL_LIBS} ${tfpsacrypto_target})
    add_dependencies(${programs_target} dlopen)
    list(APPEND executables dlopen)
endif()

add_dependencies(${programs_target} ${executables})

install(TARGETS ${executables}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

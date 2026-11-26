set(libs
    ${tfpsacrypto_target}
    ${CMAKE_THREAD_LIBS_INIT}
    ${mbedtls_target}
)

find_library(FUZZINGENGINE_LIB FuzzingEngine)
if(FUZZINGENGINE_LIB)
    project(fuzz CXX)
endif()

set(executables
    fuzz_pubkey
    fuzz_privkey
)
add_dependencies(${programs_target} ${executables})

foreach(exe IN LISTS executables)

    set(exe_sources ${exe}.c fuzz_common.c)
    if(NOT FUZZINGENGINE_LIB)
        list(APPEND exe_sources fuzz_onefile.c)
    endif()

    add_executable(${exe} ${exe_sources} $<TARGET_OBJECTS:tf_psa_crypto_test>)
    tf_psa_crypto_set_base_compile_options(${exe})
    target_include_directories(${exe} PRIVATE
        ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/tests/include
        ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/../tests/include/test)

    if (NOT FUZZINGENGINE_LIB)
        target_link_libraries(${exe} ${libs})
    else()
        target_link_libraries(${exe} ${libs} FuzzingEngine)
        SET_TARGET_PROPERTIES(${exe} PROPERTIES LINKER_LANGUAGE CXX)
    endif()

endforeach()

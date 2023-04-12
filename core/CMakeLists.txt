option(USE_STATIC_PSA_CRYPTO_LIBRARY "Build PSA-Crypto static library." ON)
option(USE_SHARED_PSA_CRYPTO_LIBRARY "Build PSA-Crypto shared library." OFF)
option(LINK_WITH_PTHREAD "Explicitly link the PSA-Crypto library to pthread." OFF)
option(LINK_WITH_TRUSTED_STORAGE "Explicitly link the PSA-Crypto library to trusted_storage." OFF)

set(src_psa_crypto_core
    psa_crypto.c
    psa_crypto_client.c
    psa_crypto_se.c
    psa_crypto_slot_management.c
    psa_crypto_storage.c
    psa_its_file.c
    psa_crypto_driver_wrappers.c
)

if(GEN_FILES)
    add_custom_command(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/psa_crypto_driver_wrappers.c
        COMMAND
            ${PSA_CRYPTO_PYTHON_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_driver_wrappers.py
                ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_driver_wrappers.py
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files/driver_templates/psa_crypto_driver_wrappers.c.jinja
    )
else()
    link_to_source(psa_crypto_driver_wrappers.c)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

if(LINK_WITH_PTHREAD)
    set(libs ${libs} pthread)
endif()

if(LINK_WITH_TRUSTED_STORAGE)
    set(libs ${libs} trusted_storage)
endif()

if (NOT USE_STATIC_PSA_CRYPTO_LIBRARY AND NOT USE_SHARED_PSA_CRYPTO_LIBRARY)
    message(FATAL_ERROR "Need to choose static or shared PSA-Crypto build!")
endif(NOT USE_STATIC_PSA_CRYPTO_LIBRARY AND NOT USE_SHARED_PSA_CRYPTO_LIBRARY)

set(psacrypto_target "${PSA_CRYPTO_TARGET_PREFIX}psacrypto")
set(psacrypto_target  ${psacrypto_target} PARENT_SCOPE)

if(USE_STATIC_PSA_CRYPTO_LIBRARY)
    set(psacrypto_static_target ${psacrypto_target})
endif()

set(target_libraries ${psacrypto_target})

if(USE_STATIC_PSA_CRYPTO_LIBRARY AND USE_SHARED_PSA_CRYPTO_LIBRARY)
    string(APPEND psacrypto_static_target "_static")

    list(APPEND target_libraries
        ${psacrypto_static_target})
endif()

file(GLOB src_psa_crypto_builtin ${CMAKE_CURRENT_SOURCE_DIR}/../drivers/builtin/src/*.c)

if(USE_STATIC_PSA_CRYPTO_LIBRARY)
    add_library(${psacrypto_static_target} STATIC ${src_psa_crypto_core} ${src_psa_crypto_builtin})
    set_target_properties(${psacrypto_static_target} PROPERTIES OUTPUT_NAME psacrypto)
    target_link_libraries(${psacrypto_static_target} PUBLIC ${libs})
endif(USE_STATIC_PSA_CRYPTO_LIBRARY)

if(USE_SHARED_PSA_CRYPTO_LIBRARY)
    set(CMAKE_LIBRARY_PATH ${CMAKE_CURRENT_BINARY_DIR})
    add_library(${psacrypto_target} SHARED ${src_psa_crypto_core} ${src_psa_crypto_builtin})
    set_target_properties(${psacrypto_target} PROPERTIES VERSION 0.1.0 SOVERSION 0)
    target_link_libraries(${psacrypto_target} PUBLIC ${libs})
endif(USE_SHARED_PSA_CRYPTO_LIBRARY)

foreach(target IN LISTS target_libraries)
    add_library(PSACrypto::${target} ALIAS ${target})  # add_subdirectory support
    target_include_directories(${target}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include/>
               $<INSTALL_INTERFACE:include/>
        PUBLIC $<BUILD_INTERFACE:${PSA_CRYPTO_DIR}/include/>
               $<INSTALL_INTERFACE:include/>
        PUBLIC $<BUILD_INTERFACE:${PSA_CRYPTO_DIR}/drivers/builtin/include/>
        PRIVATE ${PSA_CRYPTO_DIR}/core
        PRIVATE ${PSA_CRYPTO_DIR}/drivers/builtin/src)
    install(
        TARGETS ${target}
        EXPORT PSACryptoTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endforeach(target)

set(lib_target "${PSA_CRYPTO_TARGET_PREFIX}lib")

add_custom_target(${lib_target} DEPENDS ${psacrypto_target})
if(USE_STATIC_PSA_CRYPTO_LIBRARY AND USE_SHARED_PSA_CRYPTO_LIBRARY)
    add_dependencies(${lib_target} ${psacrypto_static_target})
endif()

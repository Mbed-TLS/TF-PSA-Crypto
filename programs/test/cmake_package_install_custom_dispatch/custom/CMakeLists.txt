list(APPEND dispatch_src_files
    "${CMAKE_CURRENT_SOURCE_DIR}/custom_dispatch.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/psa_crypto_driver_wrappers_no_static.c"
)

set(tf_psa_crypto_objlib "dispatch")
include(${PROJECT_SOURCE_DIR}/objlib.cmake)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
    install(DIRECTORY "include/"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

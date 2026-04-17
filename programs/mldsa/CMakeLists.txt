# mldsa_export_pubkey
tfpsacrypto_build_program_common(mldsa_export_public mldsa_export_public.c asn1_file_io.c)
target_include_directories(mldsa_export_public PRIVATE
      ${PROJECT_SOURCE_DIR}/drivers/pqcp/src
      ${PROJECT_SOURCE_DIR}/drivers/pqcp/mldsa-native/mldsa/
)

target_link_libraries(mldsa_export_public PRIVATE ${tfpsacrypto_static_target} ${CMAKE_THREAD_LIBS_INIT})

# mldsa_sign
tfpsacrypto_build_program_common(mldsa_sign mldsa_sign.c asn1_file_io.c)
target_include_directories(mldsa_sign PRIVATE
      ${PROJECT_SOURCE_DIR}/drivers/pqcp/src
      ${PROJECT_SOURCE_DIR}/drivers/pqcp/mldsa-native/mldsa/
)

target_link_libraries(mldsa_sign PRIVATE ${tfpsacrypto_static_target} ${CMAKE_THREAD_LIBS_INIT})

# mldsa_verify
tfpsacrypto_build_program_common(mldsa_verify mldsa_verify.c asn1_file_io.c)
target_include_directories(mldsa_verify PRIVATE
      ${PROJECT_SOURCE_DIR}/drivers/pqcp/src
      ${PROJECT_SOURCE_DIR}/drivers/pqcp/mldsa-native/mldsa/
)

target_link_libraries(mldsa_verify PRIVATE ${tfpsacrypto_static_target} ${CMAKE_THREAD_LIBS_INIT})

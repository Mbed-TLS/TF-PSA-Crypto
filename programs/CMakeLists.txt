set(programs_target "${TF_PSA_CRYPTO_TARGET_PREFIX}tfpsacrypto-programs")
add_custom_target(${programs_target})

add_subdirectory(psa)
add_subdirectory(test)
add_subdirectory(fuzz)

# The driver-dispatch test configuration enables test-only PSA driver hooks in
# the core library. The ML-DSA demo programs link only against tfpsacrypto, so
# they do not pull in the test support objects that satisfy those references.
#
# test_psa_crypto_drivers enables this mode via CFLAGS, not via the
# TF_PSA_CRYPTO_TEST_DRIVER CMake option, so detect both forms here.
if(NOT TF_PSA_CRYPTO_TEST_DRIVER AND
   NOT CMAKE_C_FLAGS MATCHES "(^| )-DPSA_CRYPTO_DRIVER_TEST([= ]|$)")
    add_subdirectory(mldsa)
endif()

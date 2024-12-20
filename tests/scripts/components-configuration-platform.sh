# components-configuration-platform.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Platform
################################################################

component_tf_psa_crypto_build_no_std_function () {
    # catch compile bugs in _uninit functions
    msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT

    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE:String=Check "$TF_PSA_CRYPTO_ROOT_DIR"
    make
}

component_tf_psa_crypto_test_no_date_time () {
    msg "build: default config without MBEDTLS_HAVE_TIME_DATE"
    scripts/config.py unset MBEDTLS_HAVE_TIME_DATE
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Check $TF_PSA_CRYPTO_ROOT_DIR
    make

    msg "test: !MBEDTLS_HAVE_TIME_DATE - main suites"
    make test
}

component_tf_psa_crypto_test_platform_calloc_macro () {
    msg "build: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_PLATFORM_CALLOC_MACRO calloc
    scripts/config.py set MBEDTLS_PLATFORM_FREE_MACRO free
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=$ASAN_CC -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    make test
}

component_tf_psa_crypto_test_have_int32 () {
    msg "build: gcc, force 32-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS='-DMBEDTLS_HAVE_INT32' -DCMAKE_BUILD_TYPE:String=Release "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: gcc, force 32-bit bignum limbs"
    make test
}

component_tf_psa_crypto_test_have_int64 () {
    msg "build: gcc, force 64-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS="-DMBEDTLS_HAVE_INT64" -DCMAKE_BUILD_TYPE:String=Release "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: gcc, force 64-bit bignum limbs"
    make test
}

component_tf_psa_crypto_test_have_int32_cmake_new_bignum () {
    msg "build: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_TEST_HOOKS
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS="-DMBEDTLS_HAVE_INT32" -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    make test
}

component_tf_psa_crypto_test_no_udbl_division () {
    msg "build: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    scripts/config.py full
    scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Release "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    make test
}

component_tf_psa_crypto_test_no_64bit_multiplication () {
    msg "build: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    scripts/config.py full
    scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Release "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    make test
}

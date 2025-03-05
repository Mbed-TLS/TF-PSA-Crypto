# components-configuration.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing
################################################################

component_tf_psa_crypto_test_default_out_of_box () {
    msg "build: default config (out-of-box)" # ~1min
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Check "$TF_PSA_CRYPTO_ROOT_DIR"
    make
    # Disable fancy stuff
    unset MBEDTLS_TEST_OUTCOME_FILE

    msg "test: main suites, default config (out-of-box)" # ~10s
    make test
}

component_tf_psa_crypto_test_default_gcc_asan () {
    msg "build: gcc, ASan" # ~ 1 min 50s
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test
}

component_tf_psa_crypto_test_default_gcc_asan_new_bignum () {
    msg "build: gcc, ASan" # ~ 1 min 50s
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test
}

component_tf_psa_crypto_test_full_gcc_asan () {
    msg "build: full config, gcc, ASan"
    scripts/config.py full
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: main suites (inc. selftests) (full config, ASan build)"
    make test
}

component_tf_psa_crypto_test_full_gcc_asan_new_bignum () {
    msg "build: full config, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: main suites (inc. selftests) (full config, new bignum, ASan)"
    make test
}

component_tf_psa_crypto_test_full_clang () {
    msg "build: full config, clang" # ~ 50s
    scripts/config.py full
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang -DCMAKE_BUILD_TYPE:String=Release -DTEST_CPP=1 "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: main suites (full config, clang)" # ~ 5s
    make test
}

component_tf_psa_crypto_test_default_no_deprecated () {
    # Test that removing the deprecated features from the default
    # configuration leaves something consistent.
    msg "build: default + MBEDTLS_DEPRECATED_REMOVED" # ~ 30s
    scripts/config.py set MBEDTLS_DEPRECATED_REMOVED

    cd $OUT_OF_SOURCE_DIR
    cmake "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: default + MBEDTLS_DEPRECATED_REMOVED" # ~ 5s
    make test
}

component_tf_psa_crypto_build_tfm () {
    # TF-M configuration needs a TF-M platform.
    cp configs/ext/crypto_config_profile_medium.h "$CRYPTO_CONFIG_H"

    cd $OUT_OF_SOURCE_DIR
    msg "build: TF-M config, clang, armv7-m thumb2"
    cmake -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS="--target=arm-linux-gnueabihf -march=armv7-m -mthumb -Os -Werror -Wasm-operand-widths -Wunused -I../framework/tests/include/spe" \
        -DCMAKE_C_COMPILER_WORKS=TRUE \
        -DENABLE_TESTING=OFF \
        -DENABLE_PROGRAMS=OFF \
        "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    rm -rf *
    msg "build: TF-M config, gcc native build"
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS="-Os -I../framework/tests/include/spe" "$TF_PSA_CRYPTO_ROOT_DIR"
    make
}

component_tf_psa_crypto_test_malloc_0_null () {
    msg "build: malloc(0) returns NULL (ASan+UBSan build)"
    scripts/config.py full
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Asan -DTF_PSA_CRYPTO_USER_CONFIG_FILE="$TF_PSA_CRYPTO_ROOT_DIR/tests/configs/user-config-malloc-0-null.h" "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: malloc(0) returns NULL (ASan+UBSan build)"
    make test
}

component_tf_psa_crypto_test_memory_buffer_allocator_backtrace () {
    msg "build: default config with memory buffer allocator and backtrace enabled"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_MEMORY_BACKTRACE
    scripts/config.py set MBEDTLS_MEMORY_DEBUG
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Release "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_MEMORY_BUFFER_ALLOC_C and MBEDTLS_MEMORY_BACKTRACE"
    make test
}

component_tf_psa_crypto_test_memory_buffer_allocator () {
    msg "build: default config with memory buffer allocator"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Release "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_MEMORY_BUFFER_ALLOC_C"
    make test
}

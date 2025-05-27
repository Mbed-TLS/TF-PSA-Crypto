# components-compiler.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Compiler Testing
################################################################

support_build_tf_psa_crypto_tfm_armcc () {
    support_build_tf_psa_crypto_armcc
}

component_build_tf_psa_crypto_tfm_armcc () {
    # test the TF-M configuration can build cleanly with various warning flags enabled
    cp configs/ext/crypto_config_profile_medium.h "$CRYPTO_CONFIG_H"

    msg "build: TF-M config, armclang armv7-m thumb2"
    helper_armc6_cmake_build_test "--target=arm-arm-none-eabi -mcpu=cortex-m0 -mthumb -Os -I../framework/tests/include/spe"
}

test_build_opt () {
    info=$1 cc=$2; shift 2
    $cc --version
    cd $OUT_OF_SOURCE_DIR
    for opt in "$@"; do
        msg "build/test: $cc $opt, $info" # ~ 30s
        cmake -DCMAKE_C_COMPILER="$cc" -DCMAKE_C_FLAGS="$opt -pedantic" "$TF_PSA_CRYPTO_ROOT_DIR"
        make
        # We're confident enough in compilers to not run _all_ the tests,
        # but at least run the unit tests. In particular, runs with
        # optimizations use inline assembly whereas runs with -O0
        # skip inline assembly.
        make test # ~30s
        rm -Rf *
    done
}

# For FreeBSD we invoke the function by name so this condition is added
# to disable the existing test_clang_opt function for linux.
if [[ $(uname) != "Linux" ]]; then
    component_test_tf_psa_crypto_clang_opt () {
        scripts/config.py full
        test_build_opt 'full config' clang -O0 -Os -O2
    }
fi

component_test_tf_psa_crypto_clang_latest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$CLANG_LATEST" -O0 -Os -O2
}

support_test_tf_psa_crypto_clang_latest_opt () {
    type "$CLANG_LATEST" >/dev/null 2>/dev/null
}

component_test_tf_psa_crypto_clang_earliest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$CLANG_EARLIEST" -O2
}

support_test_tf_psa_crypto_clang_earliest_opt () {
    type "$CLANG_EARLIEST" >/dev/null 2>/dev/null
}

component_test_tf_psa_crypto_gcc_latest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$GCC_LATEST" -O0 -Os -O2
}

support_test_tf_psa_crypto_gcc_latest_opt () {
    type "$GCC_LATEST" >/dev/null 2>/dev/null
}

component_test_tf_psa_crypto_gcc_earliest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$GCC_EARLIEST" -O2
}

support_test_tf_psa_crypto_gcc_earliest_opt () {
    type "$GCC_EARLIEST" >/dev/null 2>/dev/null
}

component_build_tf_psa_crypto_zeroize_checks () {
    msg "build: check for obviously wrong calls to mbedtls_platform_zeroize()"

    scripts/config.py full
    cd $OUT_OF_SOURCE_DIR

    # Only compile - we're looking for sizeof-pointer-memaccess warnings
    cmake -DTF_PSA_CRYPTO_USER_CONFIG_FILE="$TF_PSA_CRYPTO_ROOT_DIR/tests/configs/user-config-zeroize-memset.h" \
          -DCMAKE_C_FLAGS="-DMBEDTLS_TEST_DEFINES_ZEROIZE -Wsizeof-pointer-memaccess" "$TF_PSA_CRYPTO_ROOT_DIR"
    make
}

component_test_tf_psa_crypto_zeroize () {
    # Test that the function mbedtls_platform_zeroize() is not optimized away by
    # different combinations of compilers and optimization flags by using an
    # auxiliary GDB script. Unfortunately, GDB does not return error values to the
    # system in all cases that the script fails, so we must manually search the
    # output to check whether the pass string is present and no failure strings
    # were printed.

    # Don't try to disable ASLR. We don't care about ASLR here. We do care
    # about a spurious message if Gdb tries and fails, so suppress that.
    gdb_disable_aslr=
    if [ -z "$(gdb -batch -nw -ex 'set disable-randomization off' 2>&1)" ]; then
        gdb_disable_aslr='set disable-randomization off'
    fi

    cd $OUT_OF_SOURCE_DIR
    for optimization_flag in -O2 -O3 -Ofast -Os; do
        for compiler in clang gcc; do
            msg "test: $compiler $optimization_flag, mbedtls_platform_zeroize()"
            cmake -DCMAKE_C_COMPILER="$compiler" \
                  -DCMAKE_C_FLAGS="$optimization_flag -Wno-error=array-bounds -g3" \
                  -DCMAKE_BUILD_TYPE:String=Custom \
                  -DENABLE_PROGRAMS=ON "$TF_PSA_CRYPTO_ROOT_DIR"
            make
            gdb -ex "$gdb_disable_aslr" -ex "set \$is_tf_psa_crypto=1" \
                -x $FRAMEWORK/tests/programs/test_zeroize.gdb -nw -batch \
                -nx 2>&1 | tee test_zeroize.log
            grep "The buffer was correctly zeroized" test_zeroize.log
            not grep -i "error" test_zeroize.log

            # Restore the build directory for the next iteration
            rm -Rf *
        done
    done
}

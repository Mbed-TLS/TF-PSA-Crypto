# components-configuration-crypto.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Crypto
################################################################

CMAKE_BUILTIN_BUILD_DIR="drivers/builtin/CMakeFiles/builtin.dir/src"
CMAKE_EXTRAS_BUILD_DIR="extras/CMakeFiles/extras.dir"

component_test_accel_ecc_all () {
    msg "build: full + all ECC accelerated"

    # Configure
    # ---------

    ./scripts/config.py full
    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecc.h" ..
    cmake --build .

    # Make sure built-in EC alg objects are empty.
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    not grep mbedtls_ecjpake_ ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    # Also ensure that ECP module was not re-enabled
    not grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o

    # Run the tests
    # -------------

    msg "test: full + all ECC accelerated"
    ctest
}

component_test_accel_ecc_all_but_ecp_light() {
    msg "build: full + all ECC accelerated but ECP_LIGHT"

    # Configure
    # ---------

    ./scripts/config.py full

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # Emphasize on the configuration that enable ECP_LIGHT. Note that currently
    # ECC key pair derivation acceleration is not supported.
    scripts/config.py set MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py set MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py set PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecc.h" ..
    cmake --build .

    # Make sure built-in EC alg objects are empty but ECP one.
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    not grep mbedtls_ecjpake_ ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    not grep mbedtls_ecp_mul ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
    grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o

    # Run the tests
    # -------------

    msg "test: full + all ECC accelerated but ECP_LIGHT"
    ctest
}

# This is a common configuration helper used directly from
# common_test_accel_ecc_ffdh_no_bignum and indirectly from:
# - component_test_accel_ecc_no_bignum
#       - accelerate all EC algs, disable RSA and FFDH
# - component_test_accel_ecc_ffdh_no_bignum
#       - accelerate all EC and FFDH algs, disable only RSA
#
# This function accepts one parameter:
# $1: a string value which states which components are tested. Allowed values
#     are "ECC" or "ECC_DH".
config_accel_ecc_ffdh_no_bignum () {
    test_target="$1"

    scripts/config.py "full"

    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # RSA support is intentionally disabled on this test because RSA_C depends
    # on BIGNUM_C.
    scripts/config.py unset-all "PSA_WANT_KEY_TYPE_RSA_[0-9A-Z_a-z]*"
    scripts/config.py unset-all "PSA_WANT_ALG_RSA_[0-9A-Z_a-z]*"

    if [ "$test_target" = "ECC" ]; then
        # When testing ECC only, we disable FFDH support.
        scripts/config.py unset PSA_WANT_ALG_FFDH
        scripts/config.py unset-all "PSA_WANT_KEY_TYPE_DH_[0-9A-Z_a-z]*"
        scripts/config.py unset-all "PSA_WANT_DH_RFC7919_[0-9]*"
    fi

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Common helper used by:
# - component_test_accel_ecc_no_bignum
# - component_test_accel_ecc_ffdh_no_bignum
#
# The goal is to build and test accelerating either:
# - ECC only or
# - both ECC and FFDH
common_test_accel_ecc_ffdh_no_bignum () {
    test_target="$1"

    # This is an internal helper to simplify text message handling
    if [ "$test_target" = "ECC_DH" ]; then
        accel_text="ECC/FFDH"
        removed_text="ECP - DH"
    else
        accel_text="ECC"
        removed_text="ECP"
    fi

    msg "build: full + accelerated $accel_text algs - $removed_text - BIGNUM"

    # Configure
    # ---------

    config_accel_ecc_ffdh_no_bignum "$test_target"

    if [ "$test_target" = "ECC_DH" ]; then
        user_config_accel_file_path="../tests/configs/user-config-accel-ecc-ffdh.h"
    else
        user_config_accel_file_path="../tests/configs/user-config-accel-ecc.h"
    fi

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="${user_config_accel_file_path}" ..
    cmake --build .

    # Make sure any built-in EC alg was not re-enabled
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.o
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.o
    not grep mbedtls_ecjpake_ ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.o
    # Also ensure that ECP, RSA or BIGNUM modules were not re-enabled
    not grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.o
    not grep mbedtls_rsa_ ${CMAKE_BUILTIN_BUILD_DIR}/rsa.o
    not grep mbedtls_mpi_ ${CMAKE_BUILTIN_BUILD_DIR}/bignum.o

    # Run the tests
    # -------------

    msg "test suites: full + accelerated $accel_text algs - $removed_text - BIGNUM"
    ctest
}

component_test_accel_ecc_no_bignum () {
    common_test_accel_ecc_ffdh_no_bignum "ECC"
}

component_test_accel_ecc_ffdh_no_bignum () {
    common_test_accel_ecc_ffdh_no_bignum "ECC_DH"
}

component_test_accel_ecc_some_key_types () {
    msg "build: full with accelerated EC algs and some key types"

    # Configure
    # ---------
    # Start from no builtin ECC at all, like in test_accel_ecc_all. Then, just
    # disable MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE.

    ./scripts/config.py full
    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    cp "tests/configs/user-config-accel-ecc.h" \
        "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-key-types.h"
    cp "tests/configs/user-config-test-driver-extension.h" $OUT_OF_SOURCE_DIR

    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-key-types.h" \
         unset MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="user-config-accel-ecc-some-key-types.h" ..
    cmake --build .

    # ECP should be enabled but not the others
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    not grep mbedtls_ecdsa ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_ecjpake ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
    grep mbedtls_ecp_mul ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o

    # Run the tests
    # -------------

    msg "test suites: full with accelerated EC algs and some key types"
    ctest
}

# Run tests with only (non-)Weierstrass accelerated
# Common code used in:
# - component_test_accel_ecc_weierstrass_curves
# - component_test_accel_ecc_non_weierstrass_curves
common_test_accel_ecc_some_curves () {
    weierstrass=$1
    if [ $weierstrass -eq 1 ]; then
        desc="Weierstrass"
    else
        desc="non-Weierstrass"
    fi
    msg "build: full minus PK with accelerated EC algs and $desc curves"

    # Configure
    # ---------

    # Start with config crypto_full and remove PK_C:
    # that's what's supported now, see docs/driver-only-builds.md.
    ./scripts/config.py full
    scripts/config.py unset MBEDTLS_PK_C
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # this is not supported by the driver API yet
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    cp "tests/configs/user-config-accel-ecc.h" "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-curves.h"
    cp "tests/configs/user-config-test-driver-extension.h" $OUT_OF_SOURCE_DIR

    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-curves.h" \
                      unset-all MBEDTLS_PSA_ACCEL_ECC_

    if [ $weierstrass -eq 1 ]; then
        scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-curves.h" \
                          set-all MBEDTLS_PSA_ACCEL_ECC_SECP
        scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-curves.h" \
                          set-all MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL
    else
        scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecc-some-curves.h" \
                          set-all MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY
    fi

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="user-config-accel-ecc-some-curves.h" ..
    cmake --build .

    # We expect ECDH to be re-enabled for the missing curves
    grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    # We expect ECP to be re-enabled, however the parts specific to the
    # families of curves that are accelerated should be ommited.
    # - functions with mxz in the name are specific to Montgomery curves
    # - ecp_muladd is specific to Weierstrass curves
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecp_muladd ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
        grep mxz ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
    else
        grep mbedtls_ecp_muladd ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
        not grep mxz ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
    fi
    # We expect ECDSA and ECJPAKE to be re-enabled only when
    # Weierstrass curves are not accelerated
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecdsa ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
        not grep mbedtls_ecjpake  ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    else
        grep mbedtls_ecdsa ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
        grep mbedtls_ecjpake  ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    fi

    # Run the tests
    # -------------

    msg "test suites: crypto_full minus PK with accelerated EC algs and weirstrass curves"
    ctest
}

component_test_accel_ecc_weierstrass_curves () {
    common_test_accel_ecc_some_curves 1
}

component_test_accel_ecc_non_weierstrass_curves () {
    common_test_accel_ecc_some_curves 0
}

component_test_accel_ecdh() {
    msg "build: accelerated ECDH"

    # Configure
    # ---------

    cp "tests/configs/user-config-accel-ecc.h" \
        "$OUT_OF_SOURCE_DIR/user-config-accel-ecdh.h"
    cp "tests/configs/user-config-test-driver-extension.h" $OUT_OF_SOURCE_DIR
    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecdh.h" \
         unset-all MBEDTLS_PSA_ACCEL_ALG

    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecdh.h" \
         set MBEDTLS_PSA_ACCEL_ALG_ECDH

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="user-config-accel-ecdh.h" ..
    cmake --build .

    # Make sure built-in ECDH is empty.
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o

    # Run the tests
    # -------------

    msg "test: accelerated ECDH"
    ctest
}

component_test_accel_ecdsa() {
    msg "build: accelerated ECDSA"

    # Configure
    # ---------

    # Note: We accelerate all curves, including Montgomery curves, even though
    # they are not usable for ECDSA. This is done because we want to test with
    # PK enabled, and PK does not support partial acceleration of ECC curves.

    cp "tests/configs/user-config-accel-ecc.h" \
        "$OUT_OF_SOURCE_DIR/user-config-accel-ecdsa.h"
    cp "tests/configs/user-config-test-driver-extension.h" $OUT_OF_SOURCE_DIR
    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecdsa.h" \
         unset-all MBEDTLS_PSA_ACCEL_ALG

    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecdsa.h" \
         set MBEDTLS_PSA_ACCEL_ALG_ECDSA
    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecdsa.h" \
         set MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="user-config-accel-ecdsa.h" ..
    cmake --build .

    # Make sure built-in ECDSA is empty.
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o

    # Run the tests
    # -------------

    msg "test: accelerated ECDSA"
    ctest
}

component_test_accel_ecjpake() {
    msg "build: full with accelerated EC-JPAKE"

    # Configure
    # ---------

    ./scripts/config.py full
    cp "tests/configs/user-config-accel-ecc.h" \
        "$OUT_OF_SOURCE_DIR/user-config-accel-ecjpake.h"
    cp "tests/configs/user-config-test-driver-extension.h" $OUT_OF_SOURCE_DIR
    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecjpake.h" \
         unset-all MBEDTLS_PSA_ACCEL_ALG

    scripts/config.py -f "$OUT_OF_SOURCE_DIR/user-config-accel-ecjpake.h" \
         set MBEDTLS_PSA_ACCEL_ALG_JPAKE

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="user-config-accel-ecjpake.h" ..
    cmake --build .

    # Make sure built-in EC-JPAKE is empty.
    not grep mbedtls_ecjpake_init ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o

    # Run the tests
    # -------------

    msg "test: full with accelerated JPAKE"
    ctest
}

component_test_accel_hash () {
    msg "test: accelerated hash"

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-hash.h" ..
    cmake --build .

    # Make sure built-in hash objects are empty.
    not grep mbedtls_md5 ${CMAKE_BUILTIN_BUILD_DIR}/md5.c.o
    not grep mbedtls_sha1 ${CMAKE_BUILTIN_BUILD_DIR}/sha1.c.o
    not grep mbedtls_sha256 ${CMAKE_BUILTIN_BUILD_DIR}/sha256.c.o
    not grep mbedtls_sha3 ${CMAKE_BUILTIN_BUILD_DIR}/sha3.c.o
    not grep mbedtls_sha512 ${CMAKE_BUILTIN_BUILD_DIR}/sha512.c.o
    not grep mbedtls_ripemd160 ${CMAKE_BUILTIN_BUILD_DIR}/ripemd160.c.o

    # Run the tests
    # -------------

    msg "test: accelerated hash"
    ctest
}

component_test_pqcp_own_shake_full () {
    msg "build: TF_PSA_CRYPTO_PQCP_OWN_SHAKE, built-in SHAKE enabled"
    scripts/config.py full
    scripts/config.py set TF_PSA_CRYPTO_PQCP_OWN_SHAKE

    cd $OUT_OF_SOURCE_DIR
    # Enable the test driver, so that we can assert that mldsa-native isn't
    # calling the XOF driver.
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On -DCMAKE_C_COMPILER=$ASAN_CC -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    cmake --build .

    # Make sure that mldsa-native's internal SHAKE is included in the build.
    grep -q tf_psa_crypto_pqcp_mldsa_shake128_absorb core/libtfpsacrypto.a
    grep -q tf_psa_crypto_pqcp_mldsa_shake128x4_absorb_once core/libtfpsacrypto.a
    grep -q tf_psa_crypto_pqcp_mldsa_shake256_absorb core/libtfpsacrypto.a
    grep -q tf_psa_crypto_pqcp_mldsa_shake256x4_absorb_once core/libtfpsacrypto.a
    # Make sure the built-in SHAKE, or at least SHA3, is included in the build.
    grep -q mbedtls_sha3_update ${CMAKE_BUILTIN_BUILD_DIR}/sha3.c.o
    # We assert which one is used in shake_driver_calls() in
    # test_suite_pqcp_mldsa.

    msg "test: TF_PSA_CRYPTO_PQCP_OWN_SHAKE, built-in SHAKE enabled"
    ctest
}

component_test_pqcp_own_shake_no_builtin () {
    msg "build: TF_PSA_CRYPTO_PQCP_OWN_SHAKE, built-in SHA3/SHAKE disabled"
    scripts/config.py set TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED
    scripts/config.py set TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED
    scripts/config.py set TF_PSA_CRYPTO_PQCP_OWN_SHAKE
    scripts/config.py unset PSA_WANT_ALG_SHAKE128
    scripts/config.py unset PSA_WANT_ALG_SHAKE256
    scripts/config.py unset PSA_WANT_ALG_SHA3_224
    scripts/config.py unset PSA_WANT_ALG_SHA3_256
    scripts/config.py unset PSA_WANT_ALG_SHA3_384
    scripts/config.py unset PSA_WANT_ALG_SHA3_512

    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_C_COMPILER=$ASAN_CC -DCMAKE_BUILD_TYPE:String=Asan "$TF_PSA_CRYPTO_ROOT_DIR"
    cmake --build .

    # Make sure that our SHAKE is not included in the build.
    not grep mbedtls_sha3 ${CMAKE_BUILTIN_BUILD_DIR}/sha3.c.o

    msg "test: TF_PSA_CRYPTO_PQCP_OWN_SHAKE, built-in SHA3/SHAKE disabled"
    ctest
}

component_test_psa_crypto_key_id_encodes_owner () {
    msg "build: full config + PSA_CRYPTO_KEY_ID_ENCODES_OWNER, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full config - USE_PSA_CRYPTO + PSA_CRYPTO_KEY_ID_ENCODES_OWNER, cmake, gcc, ASan"
    make test
}

component_test_psa_assume_exclusive_buffers () {
    msg "build: full config + MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full config + MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS, cmake, gcc, ASan"
    make test
}

component_test_crypto_with_static_key_slots() {
    msg "build: crypto full + MBEDTLS_PSA_STATIC_KEY_SLOTS"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_STATIC_KEY_SLOTS
    # Intentionally set MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE to a value that
    # is enough to contain:
    # - all RSA public keys up to 4096 bits (max of PSA_VENDOR_RSA_MAX_KEY_BITS).
    # - RSA key pairs up to 1024 bits, but not 2048 or larger.
    # - all FFDH key pairs and public keys up to 8192 bits (max of PSA_VENDOR_FFDH_MAX_KEY_BITS).
    # - all EC key pairs and public keys up to 521 bits (max of PSA_VENDOR_ECC_MAX_CURVE_BITS).
    scripts/config.py set MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE 1212
    # Disable the fully dynamic key store (default on) since it conflicts
    # with the static behavior that we're testing here.
    scripts/config.py unset MBEDTLS_PSA_KEY_STORE_DYNAMIC

    msg "test: crypto full + MBEDTLS_PSA_STATIC_KEY_SLOTS"
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .
    ctest
}

# check_renamed_symbols HEADER LIB
# Check that if HEADER contains '#define MACRO ...' then MACRO is not a symbol
# name in LIB.
check_renamed_symbols () {
    ! nm "$2" | sed 's/.* //' |
      grep -x -F "$(sed -n 's/^ *# *define  *\([A-Z_a-z][0-9A-Z_a-z]*\)..*/\1/p' "$1")"
}

component_build_psa_crypto_spm () {
    msg "build: full config + PSA_CRYPTO_KEY_ID_ENCODES_OWNER + PSA_CRYPTO_SPM, make, gcc"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
    scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    scripts/config.py set MBEDTLS_PSA_CRYPTO_SPM
    # We can only compile, not link, since our test and sample programs
    # aren't equipped for the modified names used when MBEDTLS_PSA_CRYPTO_SPM
    # is active.
    CFLAGS="-I$PWD/framework/tests/include/spe" cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build . --target tfpsacrypto

    # Check that if a symbol is renamed by crypto_spe.h, the non-renamed
    # version is not present.
    echo "Checking for renamed symbols in the library"
    check_renamed_symbols framework/tests/include/spe/crypto_spe.h library/libmbedcrypto.a
}

component_test_no_rsa_key_pair_generation () {
    msg "build: default config minus PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE"
    scripts/config.py unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: default config minus PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE"
    ctest
}

component_test_no_pem_no_fs () {
    msg "build: Default + !MBEDTLS_PEM_PARSE_C + !MBEDTLS_FS_IO (ASan build)"
    scripts/config.py unset MBEDTLS_PEM_PARSE_C
    scripts/config.py unset MBEDTLS_FS_IO
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C # requires a filesystem
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C # requires PSA ITS
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_PEM_PARSE_C !MBEDTLS_FS_IO - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test
}

component_test_rsa_no_crt () {
    msg "build: Default + RSA_NO_CRT (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_RSA_NO_CRT
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: RSA_NO_CRT - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test
}

component_test_no_ctr_drbg () {
    msg "build: Full minus CTR_DRBG"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CTR_DRBG_C

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - main suites"
    make test
}

component_test_no_hmac_drbg () {
    msg "build: Full minus HMAC_DRBG"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset PSA_WANT_ALG_DETERMINISTIC_ECDSA # requires HMAC_DRBG

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - main suites"
    make test
}

component_test_psa_external_rng_no_drbg () {
    msg "build: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset PSA_WANT_ALG_DETERMINISTIC_ECDSA # Requires HMAC_DRBG

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto - main suites"
    ctest
}

component_test_psa_external_rng_use_psa_crypto () {
    msg "build: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG/NV_SEED"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG/NV_SEED"
    ctest
}

component_full_no_pkparse_pkwrite () {
    msg "build: full without pkparse and pkwrite"

    scripts/config.py full
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    # Ensure that PK_[PARSE|WRITE]_C were not re-enabled accidentally (additive config).
    if [ -f ${TF_PSA_CRYPTO_ROOT_DIR}/extras/pkparse.c ]; then
        not grep mbedtls_pk_parse_key ${CMAKE_EXTRAS_BUILD_DIR}/pkparse.c.o
        not grep mbedtls_pk_write_key_der ${CMAKE_EXTRAS_BUILD_DIR}/pkwrite.c.o
    else
        not grep mbedtls_pk_parse_key ${CMAKE_BUILTIN_BUILD_DIR}/pkparse.c.o
        not grep mbedtls_pk_write_key_der ${CMAKE_BUILTIN_BUILD_DIR}/pkwrite.c.o
    fi

    msg "test: full without pkparse and pkwrite"
    ctest
}

component_full_no_pkwrite () {
    msg "build: full without pkwrite"

    # Using "full" config here instead of "crypto_full" as in "component_full_no_pkparse_pkwrite"
    # because here we would like to run "test_suite_debug" test cases.
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PK_WRITE_C
    # Disable modules that depend on PK_WRITE_C
    scripts/config.py unset MBEDTLS_X509_CRT_WRITE_C
    scripts/config.py unset MBEDTLS_X509_CSR_WRITE_C

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    # Ensure that PK_WRITE_C was not re-enabled accidentally (additive config).
    if [ -f ${TF_PSA_CRYPTO_ROOT_DIR}/extras/pkwrite.c ]; then
        not grep mbedtls_pk_write_key_der ${CMAKE_EXTRAS_BUILD_DIR}/pkwrite.c.o
    else
        not grep mbedtls_pk_write_key_der ${CMAKE_BUILTIN_BUILD_DIR}/pkwrite.c.o
    fi

    msg "test: full without pkwrite"
    make test
}

component_test_crypto_full_md_light_only () {
    msg "build: crypto_full with only the light subset of MD"
    scripts/config.py full

    # Disable MD
    scripts/config.py unset MBEDTLS_MD_C
    # Disable direct dependencies of MD_C
    scripts/config.py unset MBEDTLS_HKDF_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_PKCS7_C
    # Disable indirect dependencies of MD_C
    scripts/config.py unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
    # Disable things that would auto-enable MD_C
    scripts/config.py unset MBEDTLS_PKCS5_C

    # Note: MD-light is auto-enabled in build_info.h by modules that need it,
    # which we haven't disabled, so no need to explicitly enable it.
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    # Make sure we don't have the HMAC functions, but the hashing functions
    if [ -f ${TF_PSA_CRYPTO_ROOT_DIR}/extras/md.c ]; then
        not grep mbedtls_md_hmac ${CMAKE_EXTRAS_BUILD_DIR}/md.c.o
        grep mbedtls_md ${CMAKE_EXTRAS_BUILD_DIR}/md.c.o
    else
        not grep mbedtls_md_hmac ${CMAKE_BUILTIN_BUILD_DIR}/md.c.o
        grep mbedtls_md ${CMAKE_BUILTIN_BUILD_DIR}/md.c.o
    fi

    msg "test: crypto_full with only the light subset of MD"
    ctest
}

component_test_full_no_cipher () {
    msg "build: full no CIPHER"

    scripts/config.py full

    # The built-in implementation of the following algs/key-types depends
    # on CIPHER_C so we disable them.
    # This does not hold for KEY_TYPE_CHACHA20 and ALG_CHACHA20_POLY1305
    # so we keep them enabled.
    scripts/config.py unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py unset PSA_WANT_ALG_CMAC
    scripts/config.py unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py unset PSA_WANT_ALG_CFB
    scripts/config.py unset PSA_WANT_ALG_CTR
    scripts/config.py unset PSA_WANT_ALG_ECB_NO_PADDING
    scripts/config.py unset PSA_WANT_ALG_OFB
    scripts/config.py unset PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
    scripts/config.py unset PSA_WANT_ALG_STREAM_CIPHER

    # The following modules directly depends on CIPHER_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .
    # Ensure that CIPHER_C was not re-enabled
    not grep mbedtls_cipher_init ${CMAKE_BUILTIN_BUILD_DIR}/cipher.c.o

    msg "test: full no CIPHER"
    ctest
}

component_test_full_no_ccm () {
    msg "build: full no PSA_WANT_ALG_CCM"

    scripts/config.py full
    scripts/config.py unset PSA_WANT_ALG_CCM

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: full no PSA_WANT_ALG_CCM"
    ctest
}

component_test_full_no_ccm_star_no_tag () {
    msg "build: full no PSA_WANT_ALG_CCM_STAR_NO_TAG"

    # Full config enables CRYPTO_CONFIG so that PSA_WANT config symbols are evaluated
    scripts/config.py full

    # Disable CCM_STAR_NO_TAG, which is the target of this test, as well as all
    # other components that enable MBEDTLS_PSA_BUILTIN_CIPHER internal symbol.
    # This basically disables all unauthenticated ciphers on the PSA side, while
    # keeping AEADs enabled.
    #
    # Note: PSA_WANT_ALG_CCM is enabled, but it does not cause
    # PSA_WANT_ALG_CCM_STAR_NO_TAG to be re-enabled.
    scripts/config.py unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py unset PSA_WANT_ALG_STREAM_CIPHER
    scripts/config.py unset PSA_WANT_ALG_CTR
    scripts/config.py unset PSA_WANT_ALG_CFB
    scripts/config.py unset PSA_WANT_ALG_OFB
    scripts/config.py unset PSA_WANT_ALG_ECB_NO_PADDING
    # NOTE unsettting PSA_WANT_ALG_ECB_NO_PADDING without unsetting NIST_KW_C will
    # mean PSA_WANT_ALG_ECB_NO_PADDING is re-enabled, so disabling it also.
    scripts/config.py unset MBEDTLS_NIST_KW_C
    scripts/config.py unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py unset PSA_WANT_ALG_CBC_PKCS7

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    # Ensure MBEDTLS_PSA_BUILTIN_CIPHER was not enabled
    not grep mbedtls_psa_cipher ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_cipher.c.o

    msg "test: full no PSA_WANT_ALG_CCM_STAR_NO_TAG"
    ctest
}

component_test_config_symmetric_only () {
    msg "build: configs/crypto-config-symmetric-only.h"
    CRYPTO_CONFIG="configs/crypto-config-symmetric-only.h"
    CC=$ASAN_CC cmake -DTF_PSA_CRYPTO_CONFIG_FILE="$CRYPTO_CONFIG" -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: configs/crypto-config-symmetric-only.h - unit tests"
    make test
}

component_test_everest () {
    msg "build: Everest ECDH context (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Everest ECDH context - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test
}

component_test_everest_curve25519_only () {
    msg "build: Everest ECDH context, only Curve25519" # ~ 6 min
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    scripts/config.py unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
    scripts/config.py unset PSA_WANT_ALG_ECDSA
    scripts/config.py set PSA_WANT_ALG_ECDH
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset PSA_WANT_ALG_JPAKE

    # Disable all curves
    scripts/config.py unset-all "PSA_WANT_ECC_[0-9A-Z_a-z]*$"
    scripts/config.py set PSA_WANT_ECC_MONTGOMERY_255

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: Everest ECDH context, only Curve25519" # ~ 50s
    ctest
}

# Check that the specified libraries exist and are empty.
component_test_crypto_for_psa_service () {
  msg "build: make, config for PSA crypto service"
  scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
  # Disable things that are not needed for just cryptography, to
  # reach a configuration that would be typical for a PSA cryptography
  # service providing all implemented PSA algorithms.
  # System stuff
  scripts/config.py unset MBEDTLS_ERROR_C
  scripts/config.py unset MBEDTLS_TIMING_C
  scripts/config.py unset MBEDTLS_VERSION_FEATURES
  # Crypto stuff with no PSA interface
  scripts/config.py unset MBEDTLS_BASE64_C
  scripts/config.py unset MBEDTLS_HKDF_C # PSA's HKDF is independent
  # Keep MBEDTLS_MD_C because deterministic ECDSA needs it for HMAC_DRBG.
  scripts/config.py unset MBEDTLS_NIST_KW_C
  scripts/config.py unset MBEDTLS_PEM_PARSE_C
  scripts/config.py unset MBEDTLS_PEM_WRITE_C
  scripts/config.py unset MBEDTLS_PKCS12_C
  scripts/config.py unset MBEDTLS_PKCS5_C
  # MBEDTLS_PK_PARSE_C and MBEDTLS_PK_WRITE_C are actually currently needed
  # in PSA code to work with RSA keys. We don't require users to set those:
  # they will be reenabled in build_info.h.
  scripts/config.py unset MBEDTLS_PK_C
  scripts/config.py unset MBEDTLS_PK_PARSE_C
  scripts/config.py unset MBEDTLS_PK_WRITE_C
  CFLAGS="-O1" cmake .
  cmake --build .
  ctest
}

component_test_psa_crypto_config_ffdh_2048_only () {
    msg "build: full config - only DH 2048"

    scripts/config.py full

    # Disable all DH groups other than 2048.
    scripts/config.py unset PSA_WANT_DH_RFC7919_3072
    scripts/config.py unset PSA_WANT_DH_RFC7919_4096
    scripts/config.py unset PSA_WANT_DH_RFC7919_6144
    scripts/config.py unset PSA_WANT_DH_RFC7919_8192

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: full config - only DH 2048"
    ctest
}

component_test_tfm_config_as_is () {
    msg "build: crypto_config_profile_medium.h"
    CRYPTO_CONFIG="configs/ext/crypto_config_profile_medium.h"
    CC=$ASAN_CC cmake -DTF_PSA_CRYPTO_CONFIG_FILE="$CRYPTO_CONFIG" -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: crypto_config_profile_medium.h - unit tests"
    make test
}

# Helper for setting common configurations between:
# - component_test_tfm_config_p256m_driver_accel_ec()
# - component_test_tfm_config_no_p256m()
common_tfm_config () {
    # Enable TF-M config
    cp configs/ext/crypto_config_profile_medium.h "$CRYPTO_CONFIG_H"

    # Config adjustment for better test coverage in our environment.
    # This is not needed just to build and pass tests.
    #
    # Enable filesystem I/O for the benefit of PK parse/write tests.
    sed -i '/PROFILE_M_PSA_CRYPTO_CONFIG_H/i #define MBEDTLS_FS_IO' "$CRYPTO_CONFIG_H"
}

# Keep this in sync with component_test_tfm_config() as they are both meant
# to be used in analyze_outcomes.py for driver's coverage analysis.
component_test_tfm_config_p256m_driver_accel_ec () {
    msg "build: TF-M config + p256m driver + accel ECDH(E)/ECDSA"

    common_tfm_config

    # Build crypto library
    CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -I$PWD/framework/tests/include/spe" cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    not grep mbedtls_ecjpake_ ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    # Also ensure that ECP, RSA or BIGNUM modules were not re-enabled
    not grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
    not grep mbedtls_rsa_ ${CMAKE_BUILTIN_BUILD_DIR}/rsa.c.o
    not grep mbedtls_mpi_ ${CMAKE_BUILTIN_BUILD_DIR}/bignum.c.o
    # Check that p256m was built
    grep -q p256_ecdsa_ core/libtfpsacrypto.a

    # In "config-tfm.h" we disabled CIPHER_C tweaking TF-M's configuration
    # files, so we want to ensure that it has not be re-enabled accidentally.
    not grep mbedtls_cipher ${CMAKE_BUILTIN_BUILD_DIR}/cipher.c.o

    # Run the tests
    msg "test: TF-M config + p256m driver + accel ECDH(E)/ECDSA"
    ctest
}

# Keep this in sync with component_test_tfm_config_p256m_driver_accel_ec() as
# they are both meant to be used in analyze_outcomes.py for driver's coverage
# analysis.
component_test_tfm_config_no_p256m () {
    common_tfm_config

    # Disable P256M driver, which is on by default, so that analyze_outcomes
    # can compare this test with test_tfm_config_p256m_driver_accel_ec
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset MBEDTLS_PSA_P256M_DRIVER_ENABLED

    msg "build: TF-M config without p256m"
    CFLAGS="-I$PWD/framework/tests/include/spe" cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .
    # Check that p256m was not built
    not grep p256_ecdsa_ library/libmbedcrypto.a

    # In "config-tfm.h" we disabled CIPHER_C tweaking TF-M's configuration
    # files, so we want to ensure that it has not be re-enabled accidentally.
    not grep mbedtls_cipher ${CMAKE_BUILTIN_BUILD_DIR}/cipher.c.o

    msg "test: TF-M config without p256m"
    ctest
}

# This is an helper used by:
# - component_test_psa_ecc_key_pair_no_derive
# - component_test_psa_ecc_key_pair_no_generate
# The goal is to test with all PSA_WANT_KEY_TYPE_xxx_KEY_PAIR_yyy symbols
# enabled, but one. Input arguments are as follows:
# - $1 is the configuration to start from
# - $2 is the key type under test, i.e. ECC/RSA/DH
# - $3 is the key option to be unset (i.e. generate, derive, etc)
build_and_test_psa_want_key_pair_partial () {
    base_config=$1
    key_type=$2
    unset_option=$3
    disabled_psa_want="PSA_WANT_KEY_TYPE_${key_type}_KEY_PAIR_${unset_option}"

    msg "build: $base_config - ${disabled_psa_want}"
    scripts/config.py "$base_config"

    # All the PSA_WANT_KEY_TYPE_xxx_KEY_PAIR_yyy are enabled by default in
    # crypto_config.h so we just disable the one we don't want.
    scripts/config.py unset "$disabled_psa_want"

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: $base_config - ${disabled_psa_want}"
    ctest
}

component_test_psa_ecc_key_pair_no_derive () {
    build_and_test_psa_want_key_pair_partial full "ECC" "DERIVE"
}

component_test_psa_ecc_key_pair_no_generate () {
    build_and_test_psa_want_key_pair_partial full "ECC" "GENERATE"
}

# This is a temporary test to verify that full RSA support is present even when
# only one single new symbols (PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) is defined.
component_test_new_psa_want_key_pair_symbol () {
    msg "Build: crypto config - PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC"

    # Create a temporary output file unless there is already one set
    if [ "$MBEDTLS_TEST_OUTCOME_FILE" ]; then
        REMOVE_OUTCOME_ON_EXIT="no"
    else
        REMOVE_OUTCOME_ON_EXIT="yes"
        MBEDTLS_TEST_OUTCOME_FILE="$PWD/out.csv"
        export MBEDTLS_TEST_OUTCOME_FILE
    fi

    # Remove RSA dependencies
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT

    # Keep only PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC enabled in order to ensure
    # that proper translations is done in crypto_legacy.h.
    scripts/config.py unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT
    scripts/config.py unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT
    scripts/config.py unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "Test: crypto config - PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC"
    ctest

    # Parse only 1 relevant line from the outcome file, i.e. a test which is
    # performing RSA signature.
    msg "Verify that 'RSA PKCS1 Sign #1 (SHA512, 1536 bits RSA)' is PASS"
    cat $MBEDTLS_TEST_OUTCOME_FILE | grep 'RSA PKCS1 Sign #1 (SHA512, 1536 bits RSA)' | grep -q "PASS"

    if [ "$REMOVE_OUTCOME_ON_EXIT" == "yes" ]; then
        rm $MBEDTLS_TEST_OUTCOME_FILE
    fi
}

component_test_aead_chachapoly_disabled () {
    msg "build: full minus CHACHAPOLY"
    scripts/config.py full
    scripts/config.py unset PSA_WANT_ALG_CHACHA20_POLY1305

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: full minus CHACHAPOLY"
    ctest
}

component_test_aead_only_ccm () {
    msg "build: full minus CHACHAPOLY and GCM"
    scripts/config.py full
    scripts/config.py unset PSA_WANT_ALG_CHACHA20_POLY1305
    scripts/config.py unset PSA_WANT_ALG_GCM

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    cmake --build .

    msg "test: full minus CHACHAPOLY and GCM"
    ctest
}

component_test_ccm_aes_sha256 () {
    msg "build: CCM + AES + SHA256 configuration"

    cp configs/crypto-config-ccm-aes-sha256.h "$CRYPTO_CONFIG_H"

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .
    msg "test: CCM + AES + SHA256 configuration"
    ctest
}

support_build_aes_aesce_armcc () {
    support_build_tf_psa_crypto_armcc
}

# For timebeing, no aarch64 gcc available in CI and no arm64 CI node.
component_build_aes_aesce_armcc () {
    msg "Build: AESCE test on arm64 platform without plain C."
    scripts/config.py baremetal

    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
    scripts/config.py set MBEDTLS_HAVE_ASM

    msg "AESCE, build with default configuration."
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    helper_armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto"

    msg "AESCE, build AESCE only"
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    helper_armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto"
}

component_test_aes_only_128_bit_keys () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH"
    ctest
}

component_test_no_ctr_drbg_aes_only_128_bit_keys () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH - CTR_DRBG_C"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128
    scripts/config.py unset MBEDTLS_CTR_DRBG_C

    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH - CTR_DRBG_C"
    ctest
}

component_test_aes_only_128_bit_keys_have_builtins () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    ctest
}

component_test_gcm_largetable () {
    msg "build: default config + GCM_LARGE_TABLE - AESNI_C - AESCE_C"
    scripts/config.py set MBEDTLS_GCM_LARGE_TABLE
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C

    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: default config - GCM_LARGE_TABLE - AESNI_C - AESCE_C"
    ctest
}

component_test_aes_fewer_tables () {
    msg "build: default config with AES_FEWER_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_FEWER_TABLES
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: AES_FEWER_TABLES"
    ctest
}

component_test_aes_rom_tables () {
    msg "build: default config with AES_ROM_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_ROM_TABLES
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: AES_ROM_TABLES"
    ctest
}

component_test_aes_fewer_tables_and_rom_tables () {
    msg "build: default config with AES_ROM_TABLES and AES_FEWER_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_FEWER_TABLES
    scripts/config.py set MBEDTLS_AES_ROM_TABLES
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    cmake --build .

    msg "test: AES_FEWER_TABLES + AES_ROM_TABLES"
    ctest
}

# helper for component_test_block_cipher_no_decrypt_aesni() which:
# - enable/disable the list of config options passed from -s/-u respectively.
# - build
# - test for tests_suite_xxx
#
# Usage: helper_block_cipher_no_decrypt_build_test
#        [-s set_opts] [-u unset_opts] [-c cflags] [-l ldflags] [option [...]]
# Options:  -s set_opts     the list of config options to enable
#           -u unset_opts   the list of config options to disable
#           -c cflags       the list of options passed to CFLAGS
#           -l ldflags      the list of options passed to LDFLAGS
helper_block_cipher_no_decrypt_build_test () {
    while [ $# -gt 0 ]; do
        case "$1" in
            -s)
                shift; local set_opts="$1";;
            -u)
                shift; local unset_opts="$1";;
            -c)
                shift; local cflags="-Werror -Wall -Wextra $1";;
            -l)
                shift; local ldflags="$1";;
        esac
        shift
    done
    set_opts="${set_opts:-}"
    unset_opts="${unset_opts:-}"
    cflags="${cflags:-}"
    ldflags="${ldflags:-}"

    [ -n "$set_opts" ] && echo "Enabling: $set_opts" && scripts/config.py set-all $set_opts
    [ -n "$unset_opts" ] && echo "Disabling: $unset_opts" && scripts/config.py unset-all $unset_opts

    msg "build: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    CFLAGS="-O2 $cflags" LDFLAGS="$ldflags" cmake .
    cmake --build .

    # Make sure we don't have mbedtls_xxx_setkey_dec in AES/ARIA/CAMELLIA
    not grep mbedtls_aes_setkey_dec ${BUILTIN_SRC_PATH}/aes.o
    not grep mbedtls_aria_setkey_dec ${BUILTIN_SRC_PATH}/aria.o
    not grep mbedtls_camellia_setkey_dec ${BUILTIN_SRC_PATH}/camellia.o
    # Make sure we don't have mbedtls_internal_aes_decrypt in AES
    not grep mbedtls_internal_aes_decrypt ${BUILTIN_SRC_PATH}/aes.o
    # Make sure we don't have mbedtls_aesni_inverse_key in AESNI
    not grep mbedtls_aesni_inverse_key ${BUILTIN_SRC_PATH}/aesni.o

    msg "test: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    ctest

    cmake --build . --target clean
}

# This is a configuration function used in component_test_block_cipher_no_decrypt_xxx:
config_block_cipher_no_decrypt () {
    scripts/config.py set MBEDTLS_BLOCK_CIPHER_NO_DECRYPT
    scripts/config.py unset MBEDTLS_NIST_KW_C

    # Enable support for cryptographic mechanisms through the PSA API.
    # Note: XTS, KW are not yet supported via the PSA API in Mbed TLS.
    scripts/config.py unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py unset PSA_WANT_ALG_ECB_NO_PADDING
}

component_test_block_cipher_no_decrypt_aesni () {
    # Test BLOCK_CIPHER_NO_DECRYPT with AESNI intrinsics, AESNI assembly and
    # AES C implementation on x86_64 and with AESNI intrinsics on x86.

    # This consistently causes an llvm crash on clang 3.8, so use gcc
    export CC=gcc
    config_block_cipher_no_decrypt

    # test AESNI intrinsics
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-mpclmul -msse2 -maes"

    # test AESNI assembly
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-mno-pclmul -mno-sse2 -mno-aes"

    # test AES C implementation
    helper_block_cipher_no_decrypt_build_test \
        -u "MBEDTLS_AESNI_C"

    # test AESNI intrinsics for i386 target
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-m32 -mpclmul -msse2 -maes" \
        -l "-m32"
}

support_test_block_cipher_no_decrypt_aesce_armcc () {
    support_build_tf_psa_crypto_armcc
}

component_test_block_cipher_no_decrypt_aesce_armcc () {
    scripts/config.py baremetal

    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
    scripts/config.py set MBEDTLS_HAVE_ASM

    config_block_cipher_no_decrypt

    # test AESCE baremetal build
    scripts/config.py set MBEDTLS_AESCE_C
    msg "build: default config + BLOCK_CIPHER_NO_DECRYPT with AESCE"
    helper_armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto -Werror -Wall -Wextra"

    # Make sure we don't have mbedtls_xxx_setkey_dec in AES/ARIA/CAMELLIA
    not grep mbedtls_aes_setkey_dec ${CMAKE_BUILTIN_BUILD_DIR}/aes.c.o
    not grep mbedtls_aria_setkey_dec ${CMAKE_BUILTIN_BUILD_DIR}/aria.c.o
    not grep mbedtls_camellia_setkey_dec ${CMAKE_BUILTIN_BUILD_DIR}/camellia.c.o
    # Make sure we don't have mbedtls_internal_aes_decrypt in AES
    not grep mbedtls_internal_aes_decrypt ${CMAKE_BUILTIN_BUILD_DIR}/aes.c.o
    # Make sure we don't have mbedtls_aesce_inverse_key and aesce_decrypt_block in AESCE
    not grep mbedtls_aesce_inverse_key ${CMAKE_BUILTIN_BUILD_DIR}/aesce.c.o
    not grep aesce_decrypt_block ${CMAKE_BUILTIN_BUILD_DIR}/aesce.c.o
}

component_test_ctr_drbg_aes_256_sha_512 () {
    msg "build: full + MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_512 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_512
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_512 (ASan build)"
    make test
}

component_test_ctr_drbg_aes_256_sha_256 () {
    msg "build: full + MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_256 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_256
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_256 (ASan build)"
    make test
}

component_test_ctr_drbg_aes_128_sha_512 () {
    msg "build: full + set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_512
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128 (ASan build)"
    make test
}

component_test_ctr_drbg_aes_128_sha_256 () {
    msg "build: full + set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128 + MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_256 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128
    scripts/config.py set MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_256
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + set MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 128 + MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_256 (ASan build)"
    make test
}

component_test_full_static_keystore () {
    msg "build: full config - MBEDTLS_PSA_KEY_STORE_DYNAMIC"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_KEY_STORE_DYNAMIC
    CFLAGS="$ASAN_CFLAGS -Os" LDFLAGS="$ASAN_CFLAGS" cmake .
    cmake --build .
    msg "test: full config - MBEDTLS_PSA_KEY_STORE_DYNAMIC"
    ctest
}

component_test_min_mpi_window_size () {
    msg "build: Default + MBEDTLS_MPI_WINDOW_SIZE=1 (ASan build)" # ~ 10s
    scripts/config.py set MBEDTLS_MPI_WINDOW_SIZE 1
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_MPI_WINDOW_SIZE=1 - main suites (inc. selftests) (ASan build)" # ~ 10s
    make test
}

component_test_xts () {
    # Component dedicated to run XTS unit test cases while XTS is not
    # supported through the PSA API.
    msg "build: Default + MBEDTLS_CIPHER_MODE_XTS"

    cat <<'EOF' >psa_user_config.h
#define MBEDTLS_CIPHER_MODE_XTS
#define TF_PSA_CRYPTO_CONFIG_CHECK_BYPASS
EOF
    cmake -DTF_PSA_CRYPTO_USER_CONFIG_FILE="psa_user_config.h"
    make

    rm -f psa_user_config.h

    msg "test: Default + MBEDTLS_CIPHER_MODE_XTS"
    make test
}

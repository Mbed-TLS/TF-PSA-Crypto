# components-build-system.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Build System Testing
################################################################

component_test_tf_psa_crypto_cmake_out_of_source () {
    msg "build: cmake tf-psa-crypto 'out-of-source' build"
    cd $OUT_OF_SOURCE_DIR
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make
    msg "test: cmake tf-psa-crypto 'out-of-source' build"
    make test
}

component_test_tf_psa_crypto_cmake_as_subdirectory () {
    msg "build: cmake 'as-subdirectory' build"
    cd programs/test/cmake_subproject
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D GEN_FILES=ON .
    make
    ./cmake_subproject
}

component_test_tf_psa_crypto_as_package () {
    msg "build: cmake 'as-package' build"
    root_dir="$(pwd)"
    cd programs/test/cmake_package
    build_variant_dir="$(pwd)"
    cmake .
    make
    ./cmake_package
    if [[ "$OSTYPE" == linux* ]]; then
        PKG_CONFIG_PATH="${build_variant_dir}/tf-psa-crypto/pkgconfig" \
        ${root_dir}/framework/scripts/pkgconfig.sh \
        tfpsacrypto
        # This is the EXPECTED package name. Renaming it could break consumers
        # of pkg-config, consider carefully.
    fi
}

component_test_tf_psa_crypto_cmake_as_package_install () {
    msg "build: cmake 'as-installed-package' build"
    cd programs/test/cmake_package_install
    # Note: Explicitly generate files as these are turned off in releases
    cmake .
    make
    ./cmake_package_install
}

component_build_cmake_custom_config_file () {
    # Make a copy of config file to use for the in-tree test
    cp "$CONFIG_H" include/mbedtls_config_in_tree_copy.h
    cp "$CRYPTO_CONFIG_H" include/mbedtls_crypto_config_in_tree_copy.h

    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    # Build once to get the generated files (which need an intact config file)
    cmake "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS_CONFIG_FILE"
    cd "$MBEDTLS_ROOT_DIR"
    scripts/config.py full
    cp include/mbedtls/mbedtls_config.h $OUT_OF_SOURCE_DIR/full_config.h
    cp tf-psa-crypto/include/psa/crypto_config.h $OUT_OF_SOURCE_DIR/full_crypto_config.h
    cd "$OUT_OF_SOURCE_DIR"
    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS/TF_PSA_CRYPTO_CONFIG_FILE + -DMBEDTLS/TF_PSA_CRYPTO_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_SSL_ALL_ALERT_MESSAGES' >user_config.h
    echo '#undef MBEDTLS_NIST_KW_C' >crypto_user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h -DTF_PSA_CRYPTO_USER_CONFIG_FILE=crypto_user_config.h "$MBEDTLS_ROOT_DIR"
    make
    not programs/test/query_compile_time_config MBEDTLS_SSL_ALL_ALERT_MESSAGES
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h full_crypto_config.h

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"

    # Now repeat the test for an in-tree build:

    # Restore config for the in-tree test
    mv include/mbedtls_config_in_tree_copy.h "$CONFIG_H"
    mv include/mbedtls_crypto_config_in_tree_copy.h "$CRYPTO_CONFIG_H"

    # Build once to get the generated files (which need an intact config)
    cmake .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS_CONFIG_FILE"
    cp include/mbedtls/mbedtls_config.h full_config.h
    cp tf-psa-crypto/include/psa/crypto_config.h full_crypto_config.h

    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h -DMBEDTLS_CONFIG_FILE=full_config.h .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS/TF_PSA_CRYPTO_CONFIG_FILE + -DMBEDTLS/TF_PSA_CRYPTO_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_SSL_ALL_ALERT_MESSAGES' >user_config.h
    echo '#undef MBEDTLS_NIST_KW_C' >crypto_user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h -DTF_PSA_CRYPTO_USER_CONFIG_FILE=crypto_user_config.h .
    make
    not programs/test/query_compile_time_config MBEDTLS_SSL_ALL_ALERT_MESSAGES
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h
}

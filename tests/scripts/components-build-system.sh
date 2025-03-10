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

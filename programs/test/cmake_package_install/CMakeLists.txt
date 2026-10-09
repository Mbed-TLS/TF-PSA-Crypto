cmake_minimum_required(VERSION 3.5.1)

#
# Simulate configuring and building Mbed TLS as the user might do it. We'll
# install into a directory inside our own build directory.
#

set(TF-PSA-Crypto_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(TF-PSA-Crypto_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/tf-psa-crypto")
set(TF-PSA-Crypto_BINARY_DIR "${TF-PSA-Crypto_INSTALL_DIR}${CMAKE_FILES_DIRECTORY}")

set(tf_psa_crypto_cmake_args
    "-H${TF-PSA-Crypto_SOURCE_DIR}"
    "-B${TF-PSA-Crypto_BINARY_DIR}"
    "-DENABLE_PROGRAMS=NO"
    "-DENABLE_TESTING=NO"
    # Turn on generated files explicitly in case this is a release
    "-DGEN_FILES=ON"
    "-DCMAKE_INSTALL_PREFIX=${TF-PSA-Crypto_INSTALL_DIR}"
)
# TF_PSA_CRYPTO_DISPATCH_DIR, when set to an absolute path, is forwarded to
# the TF-PSA-Crypto build so it can use that directory instead of dispatch/.
if(TF_PSA_CRYPTO_DISPATCH_DIR)
    list(APPEND tf_psa_crypto_cmake_args
        "-DTF_PSA_CRYPTO_DISPATCH_DIR=${TF_PSA_CRYPTO_DISPATCH_DIR}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" ${tf_psa_crypto_cmake_args})

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        --build "${TF-PSA-Crypto_BINARY_DIR}"
        --target install)

#
# Locate the package.
#

list(INSERT CMAKE_PREFIX_PATH 0 "${TF-PSA-Crypto_INSTALL_DIR}")
find_package(TF-PSA-Crypto REQUIRED)

#
# At this point, the TF-PSA-Crypto targets should have been imported, and we
# can now link to them from our own program.
#

add_executable(cmake_package_install cmake_package_install.c)
if(TF_PSA_CRYPTO_DISPATCH_DIR)
    # The custom dispatch directory defines verify_custom_dispatch(). Linking
    # against it checks that TF_PSA_CRYPTO_DISPATCH_DIR was actually used.
    target_compile_definitions(cmake_package_install PRIVATE TEST_CUSTOM_DISPATCH)
endif()
target_link_libraries(cmake_package_install TF-PSA-Crypto::tfpsacrypto)

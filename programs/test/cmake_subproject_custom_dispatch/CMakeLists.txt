cmake_minimum_required(VERSION 3.5.1)

project(cmake_subproject_custom_dispatch)

# Test the target renaming support by adding a prefix to the targets built
set(TF_PSA_CRYPTO_TARGET_PREFIX subproject_dispatch_test_)

# We use the parent TF-PSA-Crypto directory as the TF_PSA_CRYPTO_DIR for this
# test. Other projects that use TF-PSA-Crypto as a subproject are likely to
# add by their own relative paths.
set(TF_PSA_CRYPTO_DIR ../../../)
set(TF_PSA_CRYPTO_DISPATCH_DIR ${CMAKE_CURRENT_LIST_DIR}/custom)

# Add TF-PSA-Crypto as a subdirectory.
add_subdirectory(${TF_PSA_CRYPTO_DIR} build)

# Link against all the TF-PSA-Crypto library. Verifies that the target has been
# created using the specified prefix

add_executable(cmake_subproject_custom_dispatch cmake_subproject_dispatch.c)
target_link_libraries(cmake_subproject_custom_dispatch
    subproject_dispatch_test_tfpsacrypto
    ${CMAKE_THREAD_LIBS_INIT}
)

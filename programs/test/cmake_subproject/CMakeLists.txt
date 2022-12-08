cmake_minimum_required(VERSION 2.6)

# Test the target renaming support by adding a prefix to the targets built
set(PSA_CRYPTO_TARGET_PREFIX subproject_test_)

# We use the parent of the PSA cryptography root as the PSA_CRYPTO_DIR for this
# test. Other projects that use PSA cryptography as a subproject are likely to
# add by their own relative paths.
set(PSA_CRYPTO_DIR ../../../)

# Add PSA cryptography as a subdirectory.
add_subdirectory(${PSA_CRYPTO_DIR} build)

add_executable(cmake_subproject cmake_subproject.c)
target_link_libraries(cmake_subproject subproject_test_psacrypto)

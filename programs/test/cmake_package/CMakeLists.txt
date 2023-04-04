cmake_minimum_required(VERSION 2.8.12)

#
# Simulate configuring and building PSA-Crypto as the user might do it.
# We'll skip installing it, and use the build directory directly instead.
#

set(PSACrypto_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(PSACrypto_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/psa-crypto")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        "-H${PSACrypto_SOURCE_DIR}"
        "-B${PSACrypto_BINARY_DIR}"
        "-DENABLE_PROGRAMS=NO"
        "-DENABLE_TESTING=NO")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        --build "${PSACrypto_BINARY_DIR}")

#
# Locate the package.
#

set(PSACrypto_DIR "${PSACrypto_BINARY_DIR}/cmake")
find_package(PSACrypto REQUIRED)

#
# At this point, the PSA-Crypto targets should have been imported, and we can
# now link to them from our own program.
#

add_executable(cmake_package cmake_package.c)
target_link_libraries(cmake_package PSACrypto::psacrypto)

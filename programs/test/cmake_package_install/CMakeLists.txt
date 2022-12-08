cmake_minimum_required(VERSION 2.8.12)

#
# Simulate configuring and building PSA cryptography as the user might do it.
# We'll install into a directory inside our own build directory.
#

set(PSACrypto_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(PSACrypto_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/psa-crypto")
set(PSACrypto_BINARY_DIR "${PSACrypto_INSTALL_DIR}${CMAKE_FILES_DIRECTORY}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        "-H${PSACrypto_SOURCE_DIR}"
        "-B${PSACrypto_BINARY_DIR}"
        "-DENABLE_PROGRAMS=NO"
        "-DENABLE_TESTING=NO"
        "-DCMAKE_INSTALL_PREFIX=${PSACrypto_INSTALL_DIR}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        --build "${PSACrypto_BINARY_DIR}"
        --target install)

#
# Locate the package.
#

set(PSACrypto_DIR "${PSACrypto_INSTALL_DIR}/cmake")
find_package(PSACrypto REQUIRED)

#
# At this point, the PSA cryptography target should have been imported, and
# we can now link to them from our own program.
#

add_executable(cmake_package_install cmake_package_install.c)
target_link_libraries(cmake_package_install PSACrypto::psacrypto)

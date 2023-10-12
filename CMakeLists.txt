#
# CMake build system design considerations:
#
# - Include directories:
#   + Do not define include directories globally using the include_directories
#     command but rather at the target level using the
#     target_include_directories command. That way, it is easier to guarantee
#     that targets are built using the proper list of include directories.
#   + Use the PUBLIC and PRIVATE keywords to specify the scope of include
#     directories. That way, a target linking to a library (using the
#     target_link_libraries command) inherits from the library PUBLIC include
#     directories and not from the PRIVATE ones.
# - TF_PSA_CRYPTO_TARGET_PREFIX: CMake targets are designed to be alterable by
#   calling CMake in order to avoid target name clashes, via the use of
#   TF_PSA_CRYPTO_TARGET_PREFIX. The value of this variable is prefixed to the
#   tfpsacrypto and apidoc targets.
#

# We specify a minimum requirement of 3.16.3, but for now use 3.5.1 here
# until our infrastructure catches up.
cmake_minimum_required(VERSION 3.5.1)

include(CMakePackageConfigHelpers)

# https://cmake.org/cmake/help/latest/policy/CMP0011.html
# Setting this policy is required in CMake >= 3.18.0, otherwise a warning is generated. The OLD
# policy setting is deprecated, and will be removed in future versions.
cmake_policy(SET CMP0011 NEW)
# https://cmake.org/cmake/help/latest/policy/CMP0012.html
# Setting the CMP0012 policy to NEW is required for FindPython3 to work with CMake 3.18.2
# (there is a bug in this particular version), otherwise, setting the CMP0012 policy is required
# for CMake versions >= 3.18.3 otherwise a deprecated warning is generated. The OLD policy setting
# is deprecated and will be removed in future versions.
cmake_policy(SET CMP0012 NEW)

set(TF_PSA_CRYPTO_VERSION 0.1.0)
set(TF_PSA_CRYPTO_SOVERSION 0)

if(TEST_CPP)
    project("TF-PSA-Crypto" LANGUAGES C CXX VERSION ${TF_PSA_CRYPTO_VERSION})
else()
    project("TF-PSA-Crypto" LANGUAGES C VERSION ${TF_PSA_CRYPTO_VERSION})
endif()

include(GNUInstallDirs)

# Determine if TF-PSA-Crypto is being built as a subproject using
# add_subdirectory()
if(NOT DEFINED TF_PSA_CRYPTO_AS_SUBPROJECT)
  set(TF_PSA_CRYPTO_AS_SUBPROJECT ON)
  if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(TF_PSA_CRYPTO_AS_SUBPROJECT OFF)
  endif()
endif()

# Set the project root directory.
set(TF_PSA_CRYPTO_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Put the version numbers into relevant files
set(version_number_files
        include/tf_psa_crypto/version.h
        doxygen/input/doc_mainpage.h
        doxygen/tfpsacrypto.doxyfile)
foreach(file ${version_number_files})
    configure_file(${file}.in
                   ${TF_PSA_CRYPTO_DIR}/${file})
endforeach(file)

# Set-up configuration file
set(TF_PSA_CRYPTO_CONFIG_FILE include/psa/crypto_config.h CACHE STRING
    "TF-PSA-Crypto configuration file, absolute path or path relative to the root directory")
get_filename_component(TF_PSA_CRYPTO_CONFIG_FILE_REALPATH
                       ${TF_PSA_CRYPTO_CONFIG_FILE} REALPATH BASE_DIR ${TF_PSA_CRYPTO_DIR})
configure_file(${TF_PSA_CRYPTO_CONFIG_FILE_REALPATH}
               ${CMAKE_CURRENT_BINARY_DIR}/include/psa/crypto_config.h
               COPYONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/psa/crypto_config.h
        DESTINATION include/psa
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

option(ENABLE_PROGRAMS "Build PSA cryptography example programs." ON)

option(TF_PSA_CRYPTO_FATAL_WARNINGS "Compiler warnings treated as errors" ON)
option(GEN_FILES "Generate the auto-generated files as needed." OFF)

if(NOT CMAKE_VERSION VERSION_LESS 3.15.0)
    set(Python3_FIND_STRATEGY LOCATION)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        set(TF_PSA_CRYPTO_PYTHON_EXECUTABLE ${Python3_EXECUTABLE})
    endif()
else()
    find_package(PythonInterp 3)
    if(PYTHONINTERP_FOUND)
        set(TF_PSA_CRYPTO_PYTHON_EXECUTABLE ${PYTHON_EXECUTABLE})
    endif()
endif()

option(DISABLE_PACKAGE_CONFIG_AND_INSTALL "Disable package configuration, target export and installation" ${TF_PSA_CRYPTO_AS_SUBPROJECT})

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "GNU" CMAKE_COMPILER_IS_GNU "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "MSVC" CMAKE_COMPILER_IS_MSVC "${CMAKE_C_COMPILER_ID}")

if(NOT CMAKE_COMPILER_IS_CLANG AND
   NOT CMAKE_COMPILER_IS_GNU AND
   NOT CMAKE_COMPILER_IS_MSVC)
    message(FATAL_ERROR "Compiler ${CMAKE_C_COMPILER_ID} not supported.")
endif()

option(ENABLE_TESTING "Build TF-PSA-Crypto tests." ON)

# If this is the root project add longer list of available CMAKE_BUILD_TYPE values
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
        CACHE STRING "Choose the type of build: None Debug Release ASan ASanDbg MemSan MemSanDbg Check CheckFull"
        FORCE)
endif()

# Create a symbolic link from ${base_name} in the binary directory
# to the corresponding path in the source directory.
# Note: Copies the file(s) on Windows.
function(link_to_source base_name)
    set(link "${CMAKE_CURRENT_BINARY_DIR}/${base_name}")
    set(target "${CMAKE_CURRENT_SOURCE_DIR}/${base_name}")

    # Linking to non-existent file is not desirable. At best you will have a
    # dangling link, but when building in tree, this can create a symbolic link
    # to itself.
    if (EXISTS ${target} AND NOT EXISTS ${link})
        if (CMAKE_HOST_UNIX)
            execute_process(COMMAND ln -s ${target} ${link}
                RESULT_VARIABLE result
                ERROR_VARIABLE output)

            if (NOT ${result} EQUAL 0)
                message(FATAL_ERROR "Could not create symbolic link for: ${target} --> ${output}")
            endif()
        else()
            if (IS_DIRECTORY ${target})
                file(GLOB_RECURSE files FOLLOW_SYMLINKS LIST_DIRECTORIES false RELATIVE ${target} "${target}/*")
                foreach(file IN LISTS files)
                    configure_file("${target}/${file}" "${link}/${file}" COPYONLY)
                endforeach(file)
            else()
                configure_file(${target} ${link} COPYONLY)
            endif()
        endif()
    endif()
endfunction(link_to_source)

# Get the filename without the final extension (i.e. convert "a.b.c" to "a.b")
function(get_name_without_last_ext dest_var full_name)
    # Split into a list on '.' (but a cmake list is just a ';'-separated string)
    string(REPLACE "." ";" ext_parts "${full_name}")
    # Remove the last item if there are more than one
    list(LENGTH ext_parts ext_parts_len)
    if (${ext_parts_len} GREATER "1")
        math(EXPR ext_parts_last_item "${ext_parts_len} - 1")
        list(REMOVE_AT ext_parts ${ext_parts_last_item})
    endif()
    # Convert back to a string by replacing separators with '.'
    string(REPLACE ";" "." no_ext_name "${ext_parts}")
    # Copy into the desired variable
    set(${dest_var} ${no_ext_name} PARENT_SCOPE)
endfunction(get_name_without_last_ext)

include(CheckCCompilerFlag)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

if(CMAKE_COMPILER_IS_GNU)
    # some warnings we want are not available with old GCC versions
    # note: starting with CMake 2.8 we could use CMAKE_C_COMPILER_VERSION
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wwrite-strings")
    if (GCC_VERSION VERSION_GREATER 3.0 OR GCC_VERSION VERSION_EQUAL 3.0)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wno-format-nonliteral")
    endif()
    if (GCC_VERSION VERSION_GREATER 4.3 OR GCC_VERSION VERSION_EQUAL 4.3)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wvla")
    endif()
    if (GCC_VERSION VERSION_GREATER 4.5 OR GCC_VERSION VERSION_EQUAL 4.5)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wlogical-op")
    endif()
    if (GCC_VERSION VERSION_GREATER 4.8 OR GCC_VERSION VERSION_EQUAL 4.8)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
    endif()
    if (GCC_VERSION VERSION_GREATER 5.0)
        CHECK_C_COMPILER_FLAG("-Wformat-signedness" C_COMPILER_SUPPORTS_WFORMAT_SIGNEDNESS)
        if(C_COMPILER_SUPPORTS_WFORMAT_SIGNEDNESS)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-signedness")
        endif()
    endif()
    if (GCC_VERSION VERSION_GREATER 7.0 OR GCC_VERSION VERSION_EQUAL 7.0)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-overflow=2 -Wformat-truncation")
    endif()
    set(CMAKE_C_FLAGS_RELEASE     "-O2")
    set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
    set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
    set(CMAKE_C_FLAGS_ASAN        "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O3")
    set(CMAKE_C_FLAGS_ASANDBG     "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
    set(CMAKE_C_FLAGS_CHECK       "-Os")
    set(CMAKE_C_FLAGS_CHECKFULL   "${CMAKE_C_FLAGS_CHECK} -Wcast-qual")
endif(CMAKE_COMPILER_IS_GNU)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral")
    set(CMAKE_C_FLAGS_RELEASE     "-O2")
    set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
    set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
    set(CMAKE_C_FLAGS_ASAN        "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O3")
    set(CMAKE_C_FLAGS_ASANDBG     "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
    set(CMAKE_C_FLAGS_MEMSAN      "-fsanitize=memory -O3")
    set(CMAKE_C_FLAGS_MEMSANDBG   "-fsanitize=memory -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2")
    set(CMAKE_C_FLAGS_CHECK       "-Os")
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_MSVC)
    # Strictest warnings, UTF-8 source and execution charset
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /utf-8")
endif(CMAKE_COMPILER_IS_MSVC)

if(TF_PSA_CRYPTO_FATAL_WARNINGS)
    if(CMAKE_COMPILER_IS_MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
    endif(CMAKE_COMPILER_IS_MSVC)

    if(CMAKE_COMPILER_IS_CLANG OR CMAKE_COMPILER_IS_GNU)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    endif(CMAKE_COMPILER_IS_CLANG OR CMAKE_COMPILER_IS_GNU)
endif(TF_PSA_CRYPTO_FATAL_WARNINGS)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    if(CMAKE_COMPILER_IS_GNU OR CMAKE_COMPILER_IS_CLANG)
        set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
    endif(CMAKE_COMPILER_IS_GNU OR CMAKE_COMPILER_IS_CLANG)
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

if(LIB_INSTALL_DIR)
    set(CMAKE_INSTALL_LIBDIR "${LIB_INSTALL_DIR}")
endif()

add_subdirectory(include)
add_subdirectory(drivers/builtin/include)
add_subdirectory(core)

#
# The C files in tests/src directory contain test code shared among test suites
# and programs. This shared test code is compiled and linked to test suites and
# programs objects as a set of compiled objects. The compiled objects are NOT
# built into a library that the test suite and program objects would link
# against as they link against the tfpsacrypto library.
# The reason is that such library is expected to have mutual dependencies with
# the tfpsacrypto library and that there is as of today no portable way of
# handling such dependencies (only toolchain specific solutions).
#
# Thus the below definition of the `tf_psa_crypto_test` CMake library of objects
# target. This library of objects is used by tests and programs CMake files
# to define the test executables.
#
if(ENABLE_TESTING OR ENABLE_PROGRAMS)
    file(GLOB TF_PSA_CRYPTO_TEST_FILES
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/src/*.c
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/src/drivers/*.c)
    add_library(tf_psa_crypto_test OBJECT ${TF_PSA_CRYPTO_TEST_FILES})
    target_include_directories(tf_psa_crypto_test
        PRIVATE ${CMAKE_BINARY_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/drivers/builtin/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/drivers/builtin/src
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/include)
endif()

if(ENABLE_PROGRAMS)
    add_subdirectory(programs)
endif()

ADD_CUSTOM_TARGET(${TF_PSA_CRYPTO_TARGET_PREFIX}apidoc
    COMMAND doxygen tfpsacrypto.doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen)

if(ENABLE_TESTING)
    enable_testing()

    add_subdirectory(tests)

    # additional convenience targets for Unix only
    if(UNIX)

# Typical sequence using lcov target (out-of-tree build from (root)/build):
# cmake -D CMAKE_BUILD_TYPE:String=Coverage ..
# cmake --build .
# {ctest|make test}
# make lcov
# Browse `Coverage/index.html`
        ADD_CUSTOM_TARGET(lcov
            COMMAND rm -rf Coverage
            COMMAND lcov --capture --initial --directory core/CMakeFiles/tfpsacrypto.dir -o files.info
            COMMAND lcov --capture --directory core/CMakeFiles/tfpsacrypto.dir -o tests.info
            COMMAND lcov --add-tracefile files.info --add-tracefile tests.info -o all.info
            COMMAND lcov --remove all.info -o final.info '*.h'
            COMMAND gendesc ${CMAKE_CURRENT_SOURCE_DIR}/tests/Descriptions.txt -o descriptions
            COMMAND genhtml --title "TF-PSA-Crypto" --description-file descriptions --keep-descriptions --legend --no-branch-coverage -o Coverage final.info
            COMMAND rm -f files.info tests.info all.info final.info descriptions
        )

# Typical sequence using memcheck target (out-of-tree build from (root)/build):
# cmake -D CMAKE_BUILD_TYPE:String=Release ..
# cmake --build .
# make memcheck
        ADD_CUSTOM_TARGET(memcheck
            COMMAND sed -i.bak s+/usr/bin/valgrind+`which valgrind`+ DartConfiguration.tcl
            COMMAND ctest -O memcheck.log -D ExperimentalMemCheck
            COMMAND tail -n1 memcheck.log | grep 'Memory checking results:' > /dev/null
            COMMAND rm -f memcheck.log
            COMMAND mv DartConfiguration.tcl.bak DartConfiguration.tcl
        )
    endif(UNIX)

    # Make scripts needed for testing available in an out-of-source build.
    if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
        link_to_source(scripts)
        # Copy (don't link) DartConfiguration.tcl, needed for memcheck, to
        # keep things simple with the sed commands in the memcheck target.
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DartConfiguration.tcl
                    ${CMAKE_CURRENT_BINARY_DIR}/DartConfiguration.tcl COPYONLY)
    endif()
endif()

if(NOT DISABLE_PACKAGE_CONFIG_AND_INSTALL)
    configure_package_config_file(
        "cmake/TF-PSA-CryptoConfig.cmake.in"
        "cmake/TF-PSA-CryptoConfig.cmake"
            INSTALL_DESTINATION "cmake")

    write_basic_package_version_file(
        "cmake/TF-PSA-CryptoConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion)

    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/cmake/TF-PSA-CryptoConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/cmake/TF-PSA-CryptoConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/TF-PSA-Crypto")

    export(
        EXPORT TF-PSA-CryptoTargets
        NAMESPACE TF-PSA-Crypto::
        FILE "cmake/TF-PSA-CryptoTargets.cmake")

    install(
        EXPORT TF-PSA-CryptoTargets
        NAMESPACE TF-PSA-Crypto::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/TF-PSA-Crypto"
        FILE "TF-PSA-CryptoTargets.cmake")

    if(CMAKE_VERSION VERSION_GREATER 3.15 OR CMAKE_VERSION VERSION_EQUAL 3.15)
        # Do not export the package by default
        cmake_policy(SET CMP0090 NEW)

        # Make this package visible to the system
        export(PACKAGE TF-PSA-Crypto)
    endif()
endif()

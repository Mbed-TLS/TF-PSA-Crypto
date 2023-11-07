README for TF-PSA-Crypto
========================

The TF-PSA-Crypto repository provides an implementation of the
[PSA Cryptography API] (https://arm-software.github.io/psa-api) (version 1.1).
This encompasses the on-going extensions to the PSA Cryptography API (e.g. PAKE).

The PSA Cryptography API implementation is organized around the
[PSA Cryptography driver interface](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md)
aiming to ease the support of cryptographic accelerators and processors.

Configuration
-------------

The TF-PSA-Crypto repository should build out of the box on most systems. Its
configuration is based on C preprocessor macros gathered in
`include/psa/crypto_config.h`. The C preprocessor macros or configuration
options are organized into four groups:
1. General configuration options, options that are not related to a specific
   part of the implementation of the PSA Cryptography API.
2. Configuration, using PSA_WANT_xxx macros as defined in psa-conditional-inclusion-c.md,
   of which parts of the PSA Cryptography API the user wishes to enable:
   cryptographic algorithms, key types, elliptic curves ...
3. Configuration of the PSA cryptography core as defined in psa-driver-interface.md
   which provides the key management, the generation of random numbers and the
   dispatch to drivers.
4. Configuration of the built-in implementation of the PSA driver interface as
   defined in psa-driver-interface.md: non-functional configuration related to
   performance/size trade-offs.

The file `include/psa/crypto_config.h` can be edited manually, or in a more
programmatic way using the Python 3 script `scripts/config.py` (use `--help`
for usage instructions).

Compiler options can be set using conventional environment variables such as
`CC` and `CFLAGS` when using the CMake build system (see below).

Documentation
-------------

Documentation for the PSA Cryptography API is available [on GitHub](https://arm-software.github.io/psa-api/crypto/).

To generate a local copy of the library documentation in HTML format:

1. Make sure that [Doxygen](http://www.doxygen.nl/) is installed.
1. Run `mkdir /path/to/build_dir && cd /path/to/build_dir`
1. Run `cmake /path/to/tf/psa/crypto/source`
1. Run `make apidoc`
1. Browse `apidoc/index.html` or `apidoc/modules.html`.

Compiling
---------

The build system is CMake.
The CMake build system creates one library: libtfpsacrypto.

### Tool versions

You need the following tools to build the library from the main branch with the
provided CMake files. TF-PSA-Crypto minimum tool version requirements are set
based on the versions shipped in the latest or penultimate (depending on the
release cadence) long-term support releases of major Linux distributions,
namely at time of writing: Ubuntu 20.04, RHEL 8, SLES 15 ...

* A C99 toolchain (compiler, linker, archiver). We actively test with GCC 5.4,
  Clang 3.8. More recent versions should work. Slightly older versions may work.
* Python 3.6.5 and later to generate some source files (see below), the test
  code, and to generate sample programs.
* Perl to run the tests, and to generate some source files in the main branch.
* CMake 3.16.3 or later.
* Microsoft Visual Studio 2019 or later (if using Visual Studio).
* Doxygen 1.8.14 or later.

### Generated source files

The TF-PSA-Crypto build system generates some library, sample program and test
C files as well as test data files. Their content depends only on the PSA
cryptography source code, not on the platform or on the library configuration.

The following tools are required for the generation of those files:

* Python 3 and some Python packages, for some library source files, sample
  programs and test data. To install the necessary packages, run
  ```
  python3 -m pip install -r scripts/basic.requirements.txt
  ```
* A C compiler for the host platform, for some test data.

When not cross-compiling, the build system generates the files automatically.

When cross-compiling, before to run the build system, you must set the `CC`
environment variable to a C compiler for the host platform, then run
`tests/scripts/check-generated-files.sh -u`.

### CMake

In order to build the source using CMake in a separate directory (recommended),
just enter at the command line:

    mkdir /path/to/build_dir && cd /path/to/build_dir
    cmake /path/to/tf/psa/crypto/source
    cmake --build .

In order to run the tests, enter:

    ctest

The test suites need Python to be built and Perl to be executed. If you don't
have one of these installed, you'll want to disable the test suites with:

    cmake -DENABLE_TESTING=Off /path/to/tf/psa/crypto/source

To configure CMake for building shared libraries, use:

    cmake -DUSE_SHARED_TF_PSA_CRYPTO_LIBRARY=On /path/to/tf/psa/crypto/source

There are many different build modes available within the CMake build system.
Most of them are available for gcc and clang, though some are compiler-specific:

- `Release`. This generates the default code without any unnecessary
  information in the binary files.
- `Debug`. This generates debug information and disables optimization of the code.
- `ASan`. This instruments the code with AddressSanitizer to check for memory
  errors. (This includes LeakSanitizer, with recent version of gcc and clang.)
  (With recent version of clang, this mode also instruments the code with
  UndefinedSanitizer to check for undefined behaviour.)
- `ASanDbg`. Same as ASan but slower, with debug information and better stack
  traces.
- `MemSan`. This instruments the code with MemorySanitizer to check for
  uninitialised memory reads. Experimental, needs recent clang on Linux/x86\_64.
- `MemSanDbg`. Same as MemSan but slower, with debug information, better stack
  traces and origin tracking.
- `Check`. This activates the compiler warnings that depend on optimization and
  treats all warnings as errors.

Switching build modes in CMake is simple. For debug mode, enter at the command
line:

    cmake -D CMAKE_BUILD_TYPE=Debug /path/to/tf/psa/crypto/source

To list other available CMake options, use:

    cmake -LH

Note that, with CMake, you can't adjust the compiler or its flags after the
initial invocation of cmake. This means that `CC=your_cc make` and `make
CC=your_cc` will *not* work (similarly with `CFLAGS` and other variables).
These variables need to be adjusted when invoking cmake for the first time,
for example:

    CC=your_cc cmake /path/to/tf/psa/crypto/source

If you already invoked cmake and want to change those settings, you need to
remove the build directory and create it again.

Note that it is possible to build in-place, use:

    cmake .
    make

Regarding variables, also note that if you set CFLAGS when invoking cmake,
your value of CFLAGS doesn't override the content provided by cmake (depending
on the build mode as seen above), it's merely prepended to it.

#### Consuming TF-PSA-Crypto

The TF-PSA-Crypto repository provides a package config file for consumption as
a dependency in other CMake projects. You can include TF-PSA-Crypto CMake
targets yourself with:

    find_package(TF-PSA-Crypto)

If prompted, set `TF-PSA-Crypto_DIR` to `${YOUR_TF_PSA_CRYPTO_INSTALL_DIR}/cmake`.
This creates the `TF-PSA-Crypto::tfpsacrypto` target.

You can then use it directly through `target_link_libraries()`:

    add_executable(xyz)

    target_link_libraries(xyz PUBLIC TF-PSA-Crypto::tfpsacrypto)

This will link the TF-PSA-Crypto library to your library or application, and
add its include directories to your target (transitively, in the case of
`PUBLIC` or `INTERFACE` link libraries).

#### TF-PSA-Crypto as a subproject

The TF-PSA-Crypto repository supports being built as a CMake subproject. One
can use `add_subdirectory()` from a parent CMake project to include
TF-PSA-Crypto as a subproject.

### Microsoft Visual Studio

The TF-PSA-Crypto library can be built with Microsoft Visual Studio Community
suitably installed as a CMake project. For a general documentation about
CMake projects in Visual Studio, please refer to its documentation.

The following instructions have been tested on Microsoft Visual Studio Community
2019 Version 16.11.26. The TF-PSA-Crypto library and its tests build out of the
box with:
. Visual Studio Community installed with the default "Desktop development with C++"
and "Python development" workloads.
. Python libraries needed for code and test generation installed as defined
in basic.requirements.txt. Refer to the Visual Studio documentation of Python
environments.
. When cloning the TF-PSA-Crypto repository in Visual Studio, a
CMakeSettings.json is created at the root of the repository. In that file, add
the line `"environments": [ {"CC" : "cl"} ]` to the configuration. That way
when building the library and its tests, a CC environment variable is set with
value "cl". This is needed by Python scripts that generate test cases. The
CMakeSettings.json file can be edited in Visual Studio by following
Project > CMake Settings for TF-PSA-Crypto > Edit JSON.
. If necessary (it may have been done automatically when updating
CMakeSettings.json), generate the CMake cache: Project > Generate Cache
. Build the library: Build > Build All
. The test suites can then be run: Test > Run CTests for TF-PSA-Crypto

Example programs
----------------

We've included example programs for different features and uses in
[`programs/`](programs/README.md). Please note that the goal of these sample
programs is to demonstrate specific features of the library, and the code may
need to be adapted to build a real-world application.

Tests
-----

The TF-PSA-Crypto repository includes an elaborate test suite in `tests/` that
initially requires Python to generate the tests files
(e.g. `test\_suite\_psa\_crypto.c`). These files are generated from a
`function file` (e.g. `suites/test\_suite\_psa\_crypto.function`) and a
`data file` (e.g. `suites/test\_suite\_psa\_crypto.data`). The `function file`
contains the test functions. The `data file` contains the test cases, specified
as parameters that will be passed to the test function.

License
-------

Unless specifically indicated otherwise in a file, TF-PSA-Crypto files are provided under a dual [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) OR [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) license. See the [LICENSE](LICENSE) file for the full text of these licenses.

## CMake as the only build system
TF-PSA-Crypto uses CMake exclusively to configure and drive its build process.
There is no support for the GNU Make and Microsoft Visual Studio project-based build systems as there is in Mbed TLS 3.x.

See the `Compiling` section in README.md for instructions on building the TF-PSA-Crypto library and tests with CMake.

### Translating Make commands to CMake

With no GNU Make support, all build, test, and installation operations must be performed using CMake.
This section provides a quick reference for translating common `make` commands into their CMake equivalents.

#### Basic build workflow

Run `cmake -S . -B build` once before building to configure the build and generate native build files (e.g., Makefiles) in the `build` directory.
This sets up an out-of-tree build, which is recommended.

| Make command   | CMake equivalent                               | Description                                                        |
|----------------|------------------------------------------------|--------------------------------------------------------------------|
| `make`         | `cmake --build build`                          | Build the libraries, programs, and tests in the `build` directory. |
| `make test`    | `ctest --test-dir build`                       | Run the tests produced by the previous build. |
| `make clean`   | `cmake --build build --target clean`           | Remove build artifacts produced by the previous build. |
| `make install` | `cmake --install build --prefix build/install` | Install the built libraries, headers, and tests to `build/install`. |

#### Building specific targets

Unless otherwise specified, the CMake command in the table below should be preceded by a `cmake -S . -B build` call to configure the build and generate build files in the `build` directory.

| Make command    | CMake equivalent                                                    | Description               |
|-----------------|---------------------------------------------------------------------|---------------------------|
| `make lib`      | `cmake --build build --target lib`                                  | Build only the libraries. |
| `make tests`    | `cmake -S . -B build -DENABLE_PROGRAMS=Off && cmake --build build`  | Build test suites. |
| `make programs` | `cmake --build build --target programs`                             | Build example programs. |
| `make apidoc`   | `cmake --build build --target tfpsacrypto-apidoc`                   | Build documentation. |

Target names may differ slightly; use `cmake --build build --target help` to list all available CMake targets.

There is no CMake equivalent for `make generated_files` or `make neat`.
Generated files are automatically created in the build tree with `cmake --build build` and removed with `cmake --build build --target clean`.
If you need to build the generated files in the source tree without involving CMake, you can call `framework/scripts/make_generated_files.py`.

There is currently no equivalent for `make uninstall` in the TF-PSA-Crypto CMake build system.

#### Common build options

The following table illustrates the approximate CMake equivalents of common make commands.
Most CMake examples show only the configuration step, others (like installation) correspond to different stages of the build process.

| Make usage                 | CMake usage                                                 | Description          |
|----------------------------|-------------------------------------------------------------|----------------------|
| `make DEBUG=1`             | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug`              | Build in debug mode. |
| `make SHARED=1`            | `cmake -S . -B build -DUSE_SHARED_TF_PSA_CRYPTO_LIBRARY=On` | Also build shared libraries. |
| `make GEN_FILES=""`        | `cmake -S . -B build -DGEN_FILES=OFF`                       | Skip generating files (not a strict equivalent). |
| `make DESTDIR=install_dir` | `cmake --install build --prefix install_dir`                | Specify installation path. |
| `make CC=clang`            | `cmake -S . -B build -DCMAKE_C_COMPILER=clang`              | Set the compiler. |
| `make CFLAGS='-O2 -Wall'`  | `cmake -S . -B build -DCMAKE_C_FLAGS="-O2 -Wall"`           | Set compiler flags. |

## Repository split
In Mbed TLS 4.0, the Mbed TLS project was split into two repositories:
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls): provides TLS and X.509 functionality.
- [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto): provides the standalone cryptography library, implementing the PSA Cryptography API.

If you use only the cryptotography part, you should consider migrating to TF-PSA-Crypto 1.0.

### File and directory relocations

The following table summarizes the file and directory relocations resulting from the repository split between Mbed TLS and TF-PSA-Crypto.
These changes reflect the move of cryptographic, cryptographic-adjacent, and platform components from Mbed TLS into the present TF-PSA-Crypto repository.

| Original location in Mbed TLS tree      | New location(s)                                          | Notes |
|-----------------------------------------|----------------------------------------------------------|-------|
| `library/*`                             | `core/`<br>`drivers/builtin/src/`                        | Contains cryptographic, cryptographic-adjacent (e.g., ASN.1, Base64), and platform C modules and headers. |
| `include/mbedtls/*`                     | `include/mbedtls/`<br>`drivers/builtin/include/private/` | Public headers moved to `include/mbedtls`; now internal headers moved to `include/private`. |
| `include/psa`                           | `include/psa`                                            | All PSA headers consolidated here. |
| `3rdparty/everest`<br>`3rdparty/p256-m` | `drivers/everest`<br>`drivers/p256-m`      | Third-party crypto driver implementations. |

### Configuration file split
All cryptography and platform configuration options have been moved from the Mbed TLS configuration file to `include/psa/crypto_config.h`, which is the configuration file of TF-PSA-Crypto.  See [Compile-time configuration](#compile-time-configuration) for more details.

TF-PSA-Crypto also provides the `scripts/config.py` Python script to adjust your configuration. This script updates `include/psa/crypto_config.h`.

There have been significant changes in the cryptography configuration options:
- See [psa-transition.md](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/psa-transition.md#compile-time-configuration).
- See also the following sections:
  - [PSA as the only cryptography API](#psa-as-the-only-cryptography-api) and its sub-section [Impact on the library Configuration](#impact-on-the-library-configuration)
  - [Random number generation configuration](#random-number-generation-configuration)

### Impact on some usages of the library

#### Linking directly to a built library

The TF-PSA-Crypto CMake build system provides the cryptography libraries under the name, `libtfpsacrypto.<ext>` in the `core` directory.
Thus both the name of the libraries and their location have changed compared to Mbed TLS.
You may also need to update include paths to the public header files, see [File and Directory Relocations](#file-and-directory-relocations) for details.

#### Using TF-PSA-Crypto as a CMake subproject

The base name of the static and shared cryptography libraries is now `tfpsacrypto`, formely `mbedcrypto`.
As before, this base name is also the base name of CMake targets to build the libraries.
If your CMake scripts reference a cryptography library target, you need to update its name accordingly.

For example, the following CMake code:
```
target_link_libraries(mytarget PRIVATE mbedcrypto)
```
should be updated to:
```
target_link_libraries(mytarget PRIVATE tfpsacrypto)
```

You can refer to the following example demonstrating how to consume TF-PSA-Crypto as a CMake subproject:
- `programs/test/cmake_subproject`

#### Using TF-PSA-Crypto as a CMake package

The same renaming applies to the cryptography library targets provided by the TF-PSA-Crypto CMake package.
The CMake package name has also changed from `MbedTLS` to `TF-PSA-Crypto`.

For example, the following CMake code:
```
find_package(MbedTLS REQUIRED)
target_link_libraries(myapp PRIVATE MbedTLS::mbedcrypto)
```
should be updated to:
```
find_package(TF-PSA-Crypto REQUIRED)
target_link_libraries(myapp PRIVATE TF-PSA-Crypto::tfpsacrypto)
```

You can also refer to the following example programs demonstrating how to consume TF-PSA-Crypto as a CMake package:
- `programs/test/cmake_package`
- `programs/test/cmake_package_install`

#### Using the TF-PSA-Crypto pkg-config file

The TF-PSA-Crypto CMake build system provides the pkg-config file `tfpsacrypto.pc`, formely `mbedcrypto.pc`. You will need to update the file name in your scripts.

#### Using TF-PSA-Crypto as an installed library

The TF-PSA-Crypto CMake build system installs the cryptography libraries `libtfpsacrypto.<ext>`, formely `libmbedcrypto.<ext>`.
Thus, you will need to link against `libtfpsacrypto.<ext>` instead of `libmbedcrypto.<ext>`.

Regarding the headers, the main change is the relocation of some headers to subdirectories called `private`.
These headers are installed primarily to satisfy compiler dependencies.
Others remain for historical reasons and may be cleaned up in later versions of the library.

We strongly recommend not relying on the declarations in these headers, as they may be removed or modified without notice, see [Private Declarations](#private-declarations).

Finally, note the new `include/tf-psa-crypto` directory, which contains the TF-PSA-Crypto version and build-time configuration headers.

### Audience-Specific Notes

#### Application Developers using a distribution package
- See [Impact on usages of the library](#impact-on-some-usages-of-the-library) for the possible impacts on:
  - Linking against the cryptography library or CMake targets.
  - Using the TF-PSA-Crypto pkg-config file.
  - Using TF-PSA-Crypto as an installed library.

### Developer or package maintainers
If you build or distribute TF-PSA-Crypto:
- The build system is CMake, Makefiles and Visual Studio projects are not supported.
- Review [File and directory relocations](#file-and-directory-relocations) for updated paths.
- See [Impact on usages of the library](#impact-on-some-usages-of-the-library) for the possible impacts on:
  - Linking against the cryptography library or CMake targets.
  - Using the TF-PSA-Crypto pkg-config file.
  - Using TF-PSA-Crypto as an installed library.
- The configuration file is `include/psa/crypto_config.h` (see [Configuration file split](#configuration-file-split)).

### Platform Integrators
If you integrate TF-PSA-Crypto with a platform or hardware drivers:
- Platform-specific configuration are now handled in `include/psa/crypto_config.h`.
- Review [File and directory relocations](#file-and-directory-relocations) for the location of platform components in TF-PSA-Crypto.

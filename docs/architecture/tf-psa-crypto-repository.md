TF-PSA-Crypto repository
========================

## Introduction

The TF-PSA-Crypto repository provides a reference implementation of the
[PSA Cryptography API] (https://arm-software.github.io/psa-api). This
encompasses the on-going extensions to the PSA Cryptography API like PAKE. It
is a reference implementation in the sense that it implements most features,
and it is where new features are usually tried out.

The PSA Cryptography API reference implementation is organized around the
[PSA Cryptography driver interface](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md)
which aims to ease the support of cryptographic accelerators and processors.

## Requirements

* The TF-PSA-Crypto repository exposes as public interface the cryptographic
  interface defined in the PSA cryptography API specification.
* The TF-PSA-Crypto repository provides a way to build and test a C static and/or
  shared library exposing completely or partially the PSA cryptography API.
* The TF-PSA-Crypto repository provides a configuration mechanism to define
  the parts of the PSA cryptography API exposed by the built C library.
* The TF-PSA-Crypto repository is derived from the Mbed TLS repository. No
  cryptographic development activities as such will occur on the TF-PSA-Crypto
  repository.
* The TF-PSA-Crypto repository is derived from the Mbed TLS repository but
  it does not mean that all its content comes from Mbed TLS. It may contain a
  marginal number of files on its own.
* The TF-PSA-Crypto repository must be able to evolve to be the development
  repository of the PSA cryptography implementation.
* The update of the TF-PSA-Crypto repository from the Mbed TLS repository
  should be automated and done at a reasonably short cadence (i.e, at least
  monthly). It is expected that the automation itself evolves with the
  evolutions of the Mbed TLS repository but the less the better. The trigger
  of the updates may or may not be automated.
* The testing of the TF-PSA-Crypto repository updates should be automated (CI).

## TF-PSA-Crypto repository overview

### Library code tree skeleton

```bash
├── core
├── drivers
│   └── builtin
│       ├── include
│       │   └── mbedtls
│       └── src
├── include
│   └── psa
```

* The PSA cryptographic interface is defined and exposed in include/psa.
* To ease the addition and integration of various partial and/or complete
  implementations of the PSA driver interface (based on different cryptographic
  code bases like everest or p256-m), the implementation of the PSA core and
  the implementations of the PSA driver interface are separated into two
  directories: core and drivers.
* The drivers directory contains various partial and or complete
  implementations of the PSA driver interface, one directory per
  cryptographic code base source. The first of them being the builtin
  directory hosting the TF-PSA-Crypto repository self-contained implementation
  of the PSA driver interface.

#### TF-PSA-Crypto as a mirror of the Mbed TLS PSA cryptography implementation

```bash
├── core
├── docs
│   ├── architecture
│   └── proposed
├── drivers
│   └── builtin
│       ├── include
│       │   └── mbedtls
│       └── src
├── include
│   └── psa
├── programs
│   ├── psa
│   └── test
├── scripts
└── tests
    ├── src
    └── suites
```

The builtin implementation of the PSA driver interface is made of copies
without modifications of Mbed TLS files from the development branch in
`drivers/builtin/include/mbedtls` and `drivers/builtin/src`.

The core and its headers (directories include/psa and core) are copies of the
relevant Mbed TLS files from the development branch without modifications. The
CMake and Doxygen files are specific to the TF-PSA-Crypto repository.

Almost all files in docs, programs, scripts and tests are just copies of
Mbed TLS files from the development branch.

### Build system
A fair amount of projects rely on the CMake build system to integrate Mbed TLS
thus TF-PSA-Crypto provides a CMake based build system as well. Each build
system is a significant amount of work thus the plan to just have a CMake build
system.

### Configuration
The build-time configuration information header is `include/psa/build_info.h`.
This file is included by the PSA headers (header files located in `include/psa`)
and the PSA core files (located in `core`) to access the configuration options
defined in
`include/psa/crypto_config.h` or TF_PSA_CRYPTO_CONFIG_FILE. The PSA core files do
not include `include/psa/build_info.h` directly but through the `core/tf_psa_crypto_common.h`
file.

Both the PSA headers and the PSA core files reference Mbed TLS configuration
options. Therefore, `include/psa/build_info.h` includes the header file
`drivers/builtin/include/mbedtls/config_psa.h` which defines the Mbed TLS
configuration options as implied by the set of enabled PSA configuration
options. The goal is to eventually get rid of the Mbed TLS configuration
options, in two ways:
- For PSA headers, use the configuration options of the TF-PSA-Crypto
  repository instead of their Mbed TLS equivalent.
- For PSA core files, some code needs also to be restructured as the key
  derivation and key agreement code where support for driver is yet to be added.

The build-time configuration information header for the builtin PSA driver
interface implementation is the Mbed TLS one: `include/mbedtls/build_info.h`.
It is based on the minimalist Mbed TLS configuration file
`drivers/builtin/mbedtls_config.h` (copied by `scripts/psa_crypto.py` into
`drivers/builtin/include/mbedtls/` to overwrite the Mbed TLS default
configuration file). This minimalist Mbed TLS configuration file enables only
four Mbed TLS configuration options:
- MBEDTLS_PSA_CRYPTO_C, enable the PSA cryptography interface.
- MBEDTLS_CIPHER_C, prerequisite of MBEDTLS_PSA_CRYPTO_C.
- MBEDTLS_PSA_CRYPTO_CONFIG, enable the selection of the cryptographic
  mechanisms supported by the PSA cryptography interface through PSA_WANT_xxx
  macros.
- MBEDTLS_USE_PSA_CRYPTO, use PSA cryptography API wherever possible.

The other configuration options that need to be enabled are again enabled by
the pre-processor logic in `drivers/builtin/include/mbedtls/config_psa.h`
given `include/psa/crypto_config.h`.

### Platform abstraction layer
The PSA cryptography implementation is mostly written in portable C99 and
builds and works out of the box on systems or platforms with support for the
C standard library.

The PSA cryptography implementation assumes the availability of the following
C standard library functions:
- memory functions: memcmp(), memcpy(), memset() and memmove()
- string functions: strcmp(), strlen(), strncmp(), strncpy() and strstr()

On another side, to ease the port of the library and its usage in an embedded
context, the PSA cryptography implementation does not use directly some
functions of the standard C library but rather their equivalent platform
abstraction functions whose names are `tf_psa_crypto_xyz` when the name of the
standard function is `xyz`. These functions are:
- dynamic memory allocation functions: tf_psa_crypto_calloc(),
  tf_psa_crypto_free()
- formatted output functions: tf_psa_crypto_printf(), tf_psa_crypto_fprintf()
  and tf_psa_crypto_snprintf()
- other functions: tf_psa_crypto_setbuf()

If the configuration option TF_PSA_CRYPTO_STD_FUNCTIONS is enabled (default),
these platform abstraction functions are just aliases to the corresponding
standard C library functions. Otherwise, these platform abstraction functions
have to be provided as part of the integration of the PSA cryptography library.

Finally, some platform abstraction functions are not just clones of standard C
library functions, like tf_psa_crypto_platform_entropy_nv_seed_read() for
example, see include/psa/platform.h for more information. If the configuration
option TF_PSA_CRYPTO_STD_FUNCTIONS is enabled the PSA cryptography library
provides an implementation of most of those functions based on functions of the
standard C library though.

## Updating the main branch

The TF-PSA-Crypto repository provides an implementation of the PSA cryptography
API through its main branch.

The main branch head is built from a commit of the TF-PSA-Crypto development
branch and a commit of the Mbed TLS development branch. Updating the main
branch consists in moving its head to be based on more recent commits of the
TF-PSA-Crypto and Mbed TLS development branches. In the following,
\<mbedtls-commit-id\> is the identifier of the commit of the Mbed TLS
development branch used to update the main branch, \<mbedtls-pr\> is
the number of the last PR merged into this commit, \<tf-psa-crypto-commit-id\>
is the identifier of the commit of the development branch of this repository
used for the update and \<tf-psa-crypto-pr\> the number of the last PR merged
into that commit. Just the first nine characters of the commit identifiers are
used.

An update follows the following flow:

* Checkout locally \<mbedtls-commit-id\>.

Build what we want to become the new head of the main branch:
* cd path/to/my/tf/psa/crypto/repo
* git checkout -b new-main development
* git clean -fdx
* ./scripts/psa_crypto.py --mbedtls path/to/the/mbedtls/commit/checked/out/above
* git add --all
* git commit -s -m"New main head"

Create the branch for the update pull request from current main head, merge
into it the TF-PSA-Crypto development branch to get its last version (not
necessary if the TF-PSA-Crypto development branch has not changed since the
last update) and then update the PSA cryptography implementation by applying
the patch to end up with the same tree as the new-main branch.
* git checkout -b update-against-\<mbedtls-commit-id\>-PR\<mbedtls-pr\>-with-\<tf-psa-crypto-commit-id\>-PR\<tf-psa-crypto-pr\> main
* git merge development -m"Merge \<tf-psa-crypto-commit-id\>-PR\<tf-psa-crypto-pr\>"
* git diff HEAD new-main > patch.file
* git apply patch.file
* rm patch.file
* git add --all
* git commit -s -m"Update against \<mbedtls-commit-id\>(PR \<mbedtls-pr\>)"

Clean-up
* git branch -D new-main

* Create a PR against the main branch with the update branch created above.
* Merge the PR which completes the update.

## Comparison with the Mbed TLS cryptography library

The TF-PSA-Crypto library does not support all the cryptographic features
that the Mbed TLS cryptographic library supports, the main area of discrepancy
being the handling of the various formats of private and public asymmetric
keys.

To be more specific, the following Mbed TLS C modules can be potentially
included in the Mbed TLS cryptography library but not in the TF-PSA-Crypto one:
- nist_kw.c
- pem.c
- pkcs5.c
- pkcs7.c
- pkcs12.c

Furthermore, the following Mbed TLS C modules can be potentially included in
the TF-PSA-Crypto library as the builtin driver implementation relies on them
but their interface is not public and thus may change without notice:
- asn1parse.c
- asn1write.c
- oid.c
- pk.c
- pkparse.c
- pkwrite.c

Otherwise, the TF-PSA-Crypto library does not have support for alternative
implementations of cryptography operations as Mbed TLS does through
MBEDTLS_xxx_ALT like configuration options. Alternative implementations should
instead be provided as PSA drivers.

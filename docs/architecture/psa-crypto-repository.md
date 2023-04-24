PSA cryptography repository
===========================

## Introduction

The PSA cryptography repository contains a reference implementation of the
[PSA Cryptography API and its unified driver interface](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface).
This encompasses the on-going extensions to the PSA cryptography API like
currently PAKE.

## Requirements

* The PSA cryptography repository exposes as public interface the cryptographic
  interface defined in the PSA cryptography API specification and solely this
  interface.
* The PSA cryptography repository provides a way to independently build and
  test a C static and/or shared library exposing completely or partially the
  PSA cryptography API, without relying on the Mbed TLS repository.
* The PSA cryptography repository provides a configuration mechanism to define
  the parts of the PSA cryptography API exposed by the built C library.
* The PSA cryptography repository is derived from the Mbed TLS repository. No
  cryptographic development activities as such will occur on the PSA
  cryptography repository.
* The PSA cryptography repository is derived from the Mbed TLS repository but
  it does not mean that all its content comes from Mbed TLS. It may contain a
  marginal number of files on its own.
* The PSA cryptography repository must be able to evolve to be the development
  repository of the PSA cryptography reference implementation.
* The update of the PSA cryptography repository from the Mbed TLS repository
  should be automated and done at a reasonably short cadence (i.e, at least
  monthly). It is expected that the automation itself evolves with the
  evolutions of the Mbed TLS repository but the less the better. The trigger
  of the updates may or may not be automated.
* The testing of the PSA cryptography repository updates should be automated (CI).

## PSA cryptography repository definition

Name of the GitHub repo: psa-crypto

### Repository tree

```bash
├── include
│   └── psa
├── core
├── drivers
│   └── builtin
│       ├── include
│       └── src
```

* The PSA cryptographic interface is defined and exposed in include/psa.
* To ease the addition and integration of various partial and/or complete
  implementations of the PSA unified driver interface (based on different
  cryptographic code bases like everest or p256-m), the implementation of the
  PSA core and the implementations of the PSA unified driver interface are
  separated into two directories: core and drivers.
* The drivers directory contains various partial and or complete
  implementations of the PSA unified driver interface, one directory per
  cryptographic code base source. The first of them being the builtin
  directory hosting the PSA cryptography repository self-contained
  implementation of the PSA unified driver interface.

#### First phase considerations

```bash
├── include
│   └── psa
├── core
├── drivers
│   └── builtin
│       ├── include
│       │   └── mbedtls
│       └── src
├── cmake
├── doxygen
│   └── input
├── programs
├── scripts
│   ├── data_files
│   │   ├── driver_jsons
│   │   └── driver_templates
│   └── mbedtls_dev
│       └── __pycache__
└── tests
```

The builtin implementation is made of copies without modifications of Mbed TLS
files from the development branch in `drivers/builtin/include/mbedtls` and
`drivers/builtin/src`.

The core and its headers (directories include/psa and core) are copies of the
relevant Mbed TLS files from the development branch with as little as possible
modifications. The cmake and doxygen files are specific to the PSA cryptography
repository.

All the files in scripts, programs and tests are just copies of Mbed TLS files
from the development branch or from a specific branch derived from the
development branch that we would need to rebase when we want to update the PSA
cryptography repository according to a newer version of the development branch.
The rebase needs to be trivial in most cases which contrains what can be done
in the specific branch.

### Build system
A fair amount of projects rely on the cmake build system to integrate Mbed TLS
thus we need to provide a cmake based build system for the PSA cryptography
repository as well. Each build system for the first phase and in the long term
is a significant amount of work thus the plan to just have a cmake build system.

## Updating the main branch

The PSA cryptography repository provides a reference implementation of the
PSA cryptography API through its main branch.

The main branch is updated against the head of the Mbed TLS development branch
according to the following sequence where \<mbedtls-commit-id> is the identifier
of the head of the Mbed TLS development branch, \<mbedtls-pr\> is the number
of the last PR merged into the Mbed TLS development branch and
\<psa-crypto-commit-id\> is the identifier of the head of the development
branch of this repository used for the update. Just the first nine characters
of the commit identifiers are used.

* Checkout the Mbed TLS branch https://github.com/ronald-cron-arm/mbedtls/tree/psa-crypto-repository.
  This branch should have been rebased beforehand on top of the head of the
  Mbed TLS development branch we want to update against.
* cd path/to/my/psa/crypto/repo
* git checkout -b update-against-\<mbedtls-commit-id\>-PR\<mbedtls-pr\>-with-\<psa-crypto-commit-id\>
  development
* ./scripts/psa_crypto.py --mbedlts path/to/the/mbedtls/branch
* git add --all
* git commit -s -m"Update against \<mbedtls-commit-id\>(PR \<mbedtls-pr\>) with \<psa-crypto-commit-id\>"
* Create a PR against the main branch with the branch that has just been created.
* Merge the PR which completes the update.

## Configuration
The build-time configuration information file is `include/psa/build_info.h`.
This file is included by the PSA headers (header files located in
`include/psa`) and the PSA core files (located in `core`) to access the
configuration options defined in `include/psa/crypto_config.h` or
PSA_CRYPTO_CONFIG_FILE. The PSA core files do not include it directly but
through the `core/common.h` file.

Both the PSA headers and the PSA core files reference Mbed TLS configuration
options. Therefore, `include/psa/build_info.h` includes the header file
`drivers/builtin/include/mbedtls/config_psa.h` which defines the Mbed TLS
configuration options as implied by the set of enabled PSA configuration
options. The goal is to eventually get rid of this. For PSA headers, it is
just to use the configuration options of the PSA cryptography repository
instead of their Mbed TLS equivalent. For PSA core files, some code needs
also to be restructured as the key derivation and key agreement code where
support for driver is yet to be added.

The build-time configuration information file for the builtin implementation is
the Mbed TLS one: `include/mbedtls/build_info.h`. It is based on the
minimalist Mbed TLS configuration file `drivers/builtin/mbedtls_config.h`
(copied by `scrips/psa_crypto.py` into `drivers/builtin/include/mbedtls/` to
overwrite the Mbed TLS default configuration file), that enables only the
two Mbed TLS configuration options MBEDTLS_PSA_CRYPTO_C and
MBEDTLS_PSA_CRYPTO_CONFIG. The other configuration options that need to be
enabled are again enabled by the pre-processor logic in
`drivers/builtin/include/mbedtls/config_psa.h` given `include/psa/crypto_config.h`.

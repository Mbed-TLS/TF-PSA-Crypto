The PSA cryptography repository contains two maintained branches:

- [`development`](https://github.com/Mbed-TLS/psa-crypto/tree/development)
- [`main`](https://github.com/Mbed-TLS/psa-crypto)

The development of the PSA cryptography repository code occurs on the
development branch. No cryptography code development occurs on this branch
though. The development branch just contains a framework, a CMake build system
and scripts to integrate the Mbed TLS implementation of the PSA cryptography
API into this repository. The main branch commits are the results of such
integrations.

The PSA cryptography repository provides a reference implementation of the
PSA cryptography API through its main branch. The main branch is updated
regularly against the head of the Mbed TLS development branch (see
psa-crypto-repository.md for details).

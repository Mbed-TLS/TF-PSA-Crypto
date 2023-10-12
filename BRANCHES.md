The TF-PSA-Crypto repository contains two maintained branches:

- [`development`](https://github.com/Mbed-TLS/TF-PSA-Crypto/tree/development)
- [`main`](https://github.com/Mbed-TLS/TF-PSA-Crypto)

The development of the TF-PSA-Crypto repository code occurs on the development
branch. No cryptography code development occurs on this branch though. The
development branch just contains a framework, a CMake build system and scripts
to integrate the Mbed TLS implementation of the PSA cryptography API into this
repository. The main branch commits are the results of such integrations (see
docs/architecture/tf-psa-crypto-repository.md for more information). 

The TF-PSA-Crypto repository provides an implementation of the PSA cryptography
API through its main branch. The main branch is updated regularly against the
head of the Mbed TLS development branch.

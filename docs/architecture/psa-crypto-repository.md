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

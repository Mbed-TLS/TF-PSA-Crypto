/*
 * Simple program to test that TF-PSA-Crypto builds correctly as an installable
 * CMake package using a custom dispatch implementation.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/crypto.h>

/* Verify that the dispatch implementation is the custom one by linking with
 * a nonstandard symbol. Real custom dispatch implementations should not have
 * nonstandard symbols. */
int verify_custom_dispatch(void);

/* The main reason to build this is for testing the CMake build, so the program
 * doesn't need to do very much. It calls a PSA cryptography API to ensure
 * linkage works, but that is all. */
int main()
{
    psa_crypto_init();

    return verify_custom_dispatch();
}

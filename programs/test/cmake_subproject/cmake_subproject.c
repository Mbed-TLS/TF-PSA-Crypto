/*
 *  Simple program to test that CMake builds with TF-PSA-Crypto as a
 *  subdirectory work correctly.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/crypto.h>
#include <tf_psa_crypto/lms.h>

/* The main reason to build this is for testing the CMake build, so the program
 * doesn't need to do very much. It calls a PSA cryptography API and one that
 * is not part of it, to ensure linkage works, but that is all. */
int main()
{
#if defined(TF_PSA_CRYPTO_WANT_LMS)
    mbedtls_lms_public_t ctx;
#endif

    psa_crypto_init();

#if defined(TF_PSA_CRYPTO_WANT_LMS)
    mbedtls_lms_public_init(&ctx);
#endif

    return 0;
}

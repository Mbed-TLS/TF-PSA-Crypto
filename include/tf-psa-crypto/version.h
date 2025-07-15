/**
 * \file tf-psa-crypto/version.h
 *
 * \brief Run-time version information
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * This set of run-time variables can be used to determine the version number of
 * the Mbed TLS library used. Compile-time version defines for the same can be
 * found in build_info.h
 */
#ifndef TF_PSA_CRYPTO_VERSION_H
#define TF_PSA_CRYPTO_VERSION_H

#include "tf-psa-crypto/build_info.h"

#if defined(TF_PSA_CRYPTO_VERSION)

/**
 * Get the version number.
 *
 * \return          The constructed version number in the format
 *                  MMNNPP00 (Major, Minor, Patch).
 */
unsigned int tf_psa_crypto_version_get_number(void);

/**
 * Get the version string ("x.y.z").
 *
 * \param string    The string that will receive the value.
 *                  (Should be at least 9 bytes in size)
 */
void tf_psa_crypto_version_get_string(char *string);

/**
 * Get the full version string ("TF-PSA-Crypto x.y.z").
 *
 * \param string    The string that will receive the value. The version
 *                  string will use 23 bytes AT MOST including a terminating
 *                  null byte.
 *                  (So the buffer should be at least 23 bytes to receive this
 *                  version string).
 */
void tf_psa_crypto_version_get_string_full(char *string);

#endif /* TF_PSA_CRYPTO_VERSION */

#endif /* TF_PSA_CRYPTO_VERSION_H */

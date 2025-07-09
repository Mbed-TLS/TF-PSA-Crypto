/**
 * \file version.h
 *
 * \brief Run-time version information
 */
/*
 *  Copyright The TF-PSA-Crypto Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * This set of run-time variables can be used to determine the version number of
 * the Mbed TLS library used. Compile-time version defines for the same can be
 * found in build_info.h
 */
#ifndef TF_PSA_CRYPTO_VERSION_H
#define TF_PSA_CRYPTO_VERSION_H

/**
 * The version number x.y.z is split into three parts.
 * Major, Minor, Patchlevel
 */
#define TF_PSA_CRYPTO_VERSION_MAJOR  1
#define TF_PSA_CRYPTO_VERSION_MINOR  0
#define TF_PSA_CRYPTO_VERSION_PATCH  0

#define TENS_DIGIT(x) ((x) / 10)
#define ONES_DIGIT(x) ((x) % 10)
#define BCD(x) ((TENS_DIGIT(x) << 4) | ONES_DIGIT(x))

/**
 * The single version number has the following structure:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define TF_PSA_CRYPTO_VERSION_NUMBER         ((BCD(TF_PSA_CRYPTO_VERSION_MAJOR) << 24) \
                                              | (BCD(TF_PSA_CRYPTO_VERSION_MINOR) << 16) \
                                              | (BCD(TF_PSA_CRYPTO_VERSION_PATCH) << 8))
#define _STRINGIFY(s) #s
#define STRINGIFY(s) _STRINGIFY(s)

#define VERSION_STRING(major, minor, patch) STRINGIFY(major) "." STRINGIFY(minor) "." STRINGIFY( \
        patch)

#define TF_PSA_CRYPTO_VERSION_STRING         VERSION_STRING(TF_PSA_CRYPTO_VERSION_MAJOR, \
                                                            TF_PSA_CRYPTO_VERSION_MINOR, \
                                                            TF_PSA_CRYPTO_VERSION_PATCH)
#define TF_PSA_CRYPTO_VERSION_STRING_FULL    "TF-PSA-Crypto " TF_PSA_CRYPTO_VERSION_STRING

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


#endif /* TF_PSA_CRYPTO_VERSION_H */

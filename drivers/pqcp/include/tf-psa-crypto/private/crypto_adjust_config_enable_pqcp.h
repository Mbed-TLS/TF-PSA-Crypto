/**
 * \file tf-psa-crypto/private/crypto_adjust_config_enable_pqcp.h
 * \brief Adjust PSA configuration: enable the PQCP driver
 *
 * This is an internal header. Do not include it directly.
 *
 * Enable the PQCP driver for the mechanisms that are requested through
 * PSA_WANT_xxx configuration symbols and are not accelerated by another
 * driver.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_PQCP_H
#define TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_PQCP_H

/* Support for an ML-DSA parameter set implies support for the
 * ML-DSA public key type. */
#if defined(PSA_WANT_KEY_TYPE_ML_DSA_87)
#define PSA_WANT_KEY_TYPE_ML_DSA_PUBLIC_KEY 1
#endif

/* The ML-DSA driver is needed if the ML-DSA public key type is requested. */
#if defined(PSA_WANT_KEY_TYPE_ML_DSA_PUBLIC_KEY) || \
    defined(PSA_WANT_KEY_TYPE_ML_DSA_87)
#define TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED
#endif

/* Note: TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED requires
 * TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED, which is guaranteed by the block
 * above. */
#if defined(PSA_WANT_KEY_TYPE_ML_DSA_87)
#define TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED
#endif

#endif /* TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_PQCP_H */

/**
 * \file crypto_adjust_config_enable_pqcp.h
 *
 * \brief Enable configurations for MLDSA-87 support.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_PQCP_H
#define TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_PQCP_H

#if defined(PSA_WANT_KEY_TYPE_ML_DSA_PUBLIC_KEY) && PSA_WANT_KEY_TYPE_ML_DSA_PUBLIC_KEY == 1
#define TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED
#endif

#if defined(PSA_WANT_KEY_TYPE_ML_DSA_87) && PSA_WANT_KEY_TYPE_ML_DSA_87 == 1
#define TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED
#endif

#endif /* TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_PQCP_H */

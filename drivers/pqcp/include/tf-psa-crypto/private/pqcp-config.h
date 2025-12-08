/**
 * \file tf-psa-crypto/private/pqcp-config.h
 *
 * \brief Define the mldsa-native configuration from the TF-PSA-Crypto
 *        configuration.
 *
 * This file defines configuration macros of mldsa-native that are
 * independent of the parameter set.
 * It can be set as `MLD_CONFIG_FILE` when building mldsa-native,
 * and can be included before `mldsa_native.c`.
 *
 * In addition, you need to define parameter-set-specific macros:
 * - `MLD_CONFIG_PARAMETER_SET` and `MLD_CONFIG_NAMESPACE_PREFIX` when
 *   building mldsa-native, which needs to be done once per supported
 *   parameter set.
 * - `MLD_CONFIG_API_PARAMETER_SET` and `MLD_CONFIG_API_NAMESPACE_PREFIX`
 *   before including `mldsa_native.h`, which needs to be done once per
 *   supported parameter set.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_PQCP_CONFIG_H
#define TF_PSA_CRYPTO_PRIVATE_PQCP_CONFIG_H

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#  define MLD_CONFIG_INTERNAL_API_QUALIFIER static

//#  define MLD_CONFIG_MULTILEVEL_NO_SHARED

#  define MLD_CONFIG_NO_RANDOMIZED_API

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif  /* tf-psa-crypto/private/pqcp-config.h */

/*
 *  TF-PSA-Crypto configuration checks
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* Consistency checks on the user's configuration.
 * Check that it doesn't define macros that we assume are under full
 * control of the library, or options from past major versions that
 * no longer have any effect.
 * These headers are automatically generated. See
 * framework/scripts/mbedtls_framework/config_checks_generator.py
 */
#include "tf_psa_crypto_config_check_before.h"
#define TF_PSA_CRYPTO_INCLUDE_AFTER_RAW_CONFIG "tf_psa_crypto_config_check_user.h"

#include <tf-psa-crypto/build_info.h>

/* Consistency checks in the configuration: check for incompatible options,
 * missing options when at least one of a set needs to be enabled, etc. */
/* Manually written checks */
#include "tf_psa_crypto_check_config.h"
/* Automatically generated checks */
#include "tf_psa_crypto_config_check_final.h"

/* For MBEDTLS_STATIC_ASSERT */
#include "tf_psa_crypto_common.h"
/* For PSA_HASH_LENGTH */
#include <psa/crypto_sizes.h>

/* Additional domain-specific checks */
#include "psa_crypto_random_impl.h"

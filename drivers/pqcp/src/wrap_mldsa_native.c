/** \brief Simple integration of mldsa-native from PQCP
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <tf-psa-crypto/build_info.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#include <mbedtls/platform_util.h>

#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize_native mbedtls_platform_zeroize

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED)
#  define MLD_CONFIG_PARAMETER_SET 87
#  define MLD_CONFIG_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA87
#  include "mldsa_native.c"
#  undef MLD_CONFIG_PARAMETER_SET
#  undef MLD_CONFIG_NAMESPACE_PREFIX
#endif

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

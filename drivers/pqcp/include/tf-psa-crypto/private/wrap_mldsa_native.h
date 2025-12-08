/** \brief Simple integration of mldsa-native from PQCP
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_WRAP_MLDSA_NATIVE_H
#define TF_PSA_CRYPTO_PRIVATE_WRAP_MLDSA_NATIVE_H

#include <tf-psa-crypto/build_info.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED)
#  define MLD_CONFIG_API_PARAMETER_SET 87
#  define MLD_CONFIG_API_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA87
#  include "mldsa_native.h"
#  undef MLD_CONFIG_API_PARAMETER_SET
#  undef MLD_CONFIG_API_NAMESPACE_PREFIX
#endif

#endif  /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* <tf-psa-CRYPTO/private/wrap_mldsa_native.h> */

/*
 *  Version information
 *
 *  Copyright The TF-PSA-Crypto Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf-psa-crypto/version.h"
#include <string.h>

#if defined(TF_PSA_CRYPTO_VERSION)

unsigned int tf_psa_crypto_version_get_number(void)
{
    return TF_PSA_CRYPTO_VERSION_NUMBER;
}

void tf_psa_crypto_version_get_string(char *string)
{
    memcpy(string, TF_PSA_CRYPTO_VERSION_STRING,
           sizeof(TF_PSA_CRYPTO_VERSION_STRING));
}

void tf_psa_crypto_version_get_string_full(char *string)
{
    memcpy(string, TF_PSA_CRYPTO_VERSION_STRING_FULL,
           sizeof(TF_PSA_CRYPTO_VERSION_STRING_FULL));
}

#endif /* TF_PSA_CRYPTO_VERSION */

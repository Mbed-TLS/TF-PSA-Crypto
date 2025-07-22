/*
 *  TF-PSA-Crypto configuration checks
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <tf-psa-crypto/build_info.h>

/* Consistency checks in the configuration: check for incompatible options,
 * missing options when at least one of a set needs to be enabled, etc. */
#include "tf_psa_crypto_check_config.h"

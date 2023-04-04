/**
 * \file build_info.h
 *
 * \brief Build-time configuration info
 *
 *  Include this file if you need to depend on the
 *  configuration options defined in crypto_config.h or PSA_CRYPTO_CONFIG_FILE.
 */
 /*
  *  Copyright The Mbed TLS Contributors
  *  SPDX-License-Identifier: Apache-2.0
  *
  *  Licensed under the Apache License, Version 2.0 (the "License"); you may
  *  not use this file except in compliance with the License.
  *  You may obtain a copy of the License at
  *
  *  http://www.apache.org/licenses/LICENSE-2.0
  *
  *  Unless required by applicable law or agreed to in writing, software
  *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  *  See the License for the specific language governing permissions and
  *  limitations under the License.
  */

#ifndef PSA_CRYPTO_BUILD_INFO_H
#define PSA_CRYPTO_BUILD_INFO_H

/* Define `inline` on some non-C99-compliant compilers. */
#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * Configuration of the PSA cryptographic mechanisms to include in the PSA
 * cryptography interface.
 */
#if !defined(PSA_CRYPTO_CONFIG_FILE)
#include "psa/crypto_config.h"
#else
#include PSA_CRYPTO_CONFIG_FILE
#endif

/*
 * Patch the configuration defined by `"psa/crypto_config.h"` or
 * #PSA_CRYPTO_CONFIG_FILE.
 */
#if defined(PSA_CRYPTO_CONFIG_PATCH)
#include PSA_CRYPTO_CONFIG_PATCH
#endif

/*
 * Compute Mbed TLS configuration options from the PSA-Crypto ones as
 * PSA headers and core depends on some of them.
 */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CONFIG
#include "mbedtls/config_psa.h"

#endif /* PSA_CRYPTO_BUILD_INFO_H */

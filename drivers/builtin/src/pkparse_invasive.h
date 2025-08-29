/**
 * \file pkparse_invasive.h
 *
 * \brief PK Parse module: interfaces for invasive testing only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They SHOULD NOT be made available in library integrations except when
 * building the library for testing.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PKPARSE_INVASIVE_H
#define MBEDTLS_PKPARSE_INVASIVE_H

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_PK_PARSE_C)

MBEDTLS_STATIC_TESTABLE int pk_parse_key_pkcs8_unencrypted_der(mbedtls_pk_context *pk,
                                                     const unsigned char *key,
                                                     size_t keylen);

#endif

#endif /* MBEDTLS_PKPARSE_INVASIVE_H */

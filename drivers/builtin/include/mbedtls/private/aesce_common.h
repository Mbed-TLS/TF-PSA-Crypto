/**
 * \file aesce_common.h
 *
 * \brief This file contains AESCE definitions and functions common to
 * both the AESCE and GCM modules.
 *
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_MBEDTLS_PRIVATE_AESCE_H
#define TF_PSA_CRYPTO_MBEDTLS_PRIVATE_AESCE_H

/*
 * If set to 1, this saves around 800b of code size for AESCE AES-GCM.
 */
#if !defined(MBEDTLS_AESCE_OPTIMISE_FOR_SIZE)
#define MBEDTLS_AESCE_OPTIMISE_FOR_SIZE 0
#endif

#endif // TF_PSA_CRYPTO_MBEDTLS_PRIVATE_AESCE_H

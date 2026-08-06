/*
 *  PSA key wrapping entry points and associated auxiliary functions
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PSA_CRYPTO_WRAP_H
#define TF_PSA_CRYPTO_PSA_CRYPTO_WRAP_H

#include <psa/crypto.h>

psa_status_t mbedtls_psa_key_wrap(const psa_key_attributes_t *wrapping_key_attributes,
                                  const uint8_t *wrapping_key_buffer,
                                  size_t wrapping_key_buffer_size,
                                  const psa_key_attributes_t *key_attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *output_length);

psa_status_t mbedtls_psa_key_unwrap(const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length);

#endif /* TF_PSA_CRYPTO_PSA_CRYPTO_WRAP_H */

/**
 * \file blake2.h
 *
 * \brief This file contains context types and functions for the BLAKE2
 *        cryptographic hash and keyed-hash (MAC) algorithms.
 *
 *        BLAKE2 is described in
 *        <em>RFC 7693: The BLAKE2 Cryptographic Hash and Message
 *        Authentication Code (MAC)</em>. This file provides BLAKE2s, which
 *        produces digests of up to 32 bytes, and BLAKE2b, which produces
 *        digests of up to 64 bytes.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_BLAKE2_H
#define TF_PSA_CRYPTO_PRIVATE_BLAKE2_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>
#include <stdint.h>

#include "psa/crypto_values.h"

/** Invalid input data, such as an invalid output length or key length. */
#define TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA    PSA_ERROR_INVALID_ARGUMENT
/** The output buffer is too small to hold the requested digest. */
#define TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL  PSA_ERROR_BUFFER_TOO_SMALL

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The BLAKE2s context structure.
 */
typedef struct tf_psa_crypto_blake2s_context {
    uint8_t MBEDTLS_PRIVATE(buf[64]);              /*!< The data block being processed. */
    uint32_t MBEDTLS_PRIVATE(state[8]);            /*!< The intermediate digest state. */
    uint32_t MBEDTLS_PRIVATE(processed_bytes)[2];  /*!< The number of bytes processed, as a
                                                      64-bit little-endian counter split
                                                      into two 32-bit words. */
    size_t MBEDTLS_PRIVATE(buf_idx);               /*!< The number of bytes currently held in
                                                      \c buf. */
    size_t MBEDTLS_PRIVATE(outlen);                /*!< The configured digest length, in bytes. */
} tf_psa_crypto_blake2s_context;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256)

/**
 * \brief          This function initializes a BLAKE2s context and starts a
 *                 new hash or HMAC operation.
 *
 *                 It must be the first API called before using the context,
 *                 and it must be called again before starting a new
 *                 operation with the same context.
 *
 * \param ctx      The BLAKE2s context to initialize. This must not be
 *                 \c NULL.
 * \param outlen   The desired length of the digest, in bytes. This must be
 *                 greater than \c 0 and at most \c 32.
 * \param key      The key used in case of HMAC operation. This can be \c NULL
 *                 if \p keylen is \c 0, in which case an unkeyed hash is
 *                 computed. Otherwise this must be a readable buffer of
 *                 length \p keylen bytes.
 * \param keylen   The length of \p key in bytes. This must be at most
 *                 \c 32. Use \c 0 for an unkeyed hash.
 *
 * \return         \c 0 on success.
 * \return         #TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA if \p outlen or
 *                 \p keylen is invalid.
 */
int tf_psa_crypto_blake2s_init(tf_psa_crypto_blake2s_context *ctx, size_t outlen,
                               const void *key, size_t keylen);

/**
 * \brief          This function clears the specified BLAKE2s context.
 *
 * \param ctx      The BLAKE2s context to clear.
 *                 If this is \c NULL, this function does nothing.
 */
void tf_psa_crypto_blake2s_free(tf_psa_crypto_blake2s_context *ctx);

/**
 * \brief          This function clones the state of a BLAKE2s context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void tf_psa_crypto_blake2s_clone(tf_psa_crypto_blake2s_context *dst,
                                 const tf_psa_crypto_blake2s_context *src);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 BLAKE2s hash or HMAC operation.
 *
 *                 It can be called repeatedly to process a message
 *                 incrementally.
 *
 * \param ctx      The BLAKE2s context. This must be initialized.
 * \param in       The buffer holding the data. This must be a readable
 *                 buffer of length \p inlen bytes.
 * \param inlen    The length of the input data in bytes.
 */
void tf_psa_crypto_blake2s_update(tf_psa_crypto_blake2s_context *ctx,
                                  const uint8_t *in, size_t inlen);

/**
 * \brief          This function finishes a BLAKE2s operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The BLAKE2s context. This must be initialized.
 * \param out      The buffer to which the digest is written.
 *                 This must be a writable buffer of length \p outlen
 *                 bytes.
 * \param outlen   The size of the \p out buffer in bytes. This must be at
 *                 least the digest length that was passed to
 *                 tf_psa_crypto_blake2s_init().
 *
 * \return         \c 0 on success.
 * \return         #TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL if \p outlen is
 *                 smaller than the digest length configured at
 *                 initialization time.
 */
int tf_psa_crypto_blake2s_finish(tf_psa_crypto_blake2s_context *ctx,
                                 uint8_t *out, size_t outlen);

/**
 * \brief          This function calculates the BLAKE2s hash or HMAC of the
 *                 given buffer.
 *
 * \param in       The buffer holding the data. This must be a readable
 *                 buffer of length \p inlen bytes.
 * \param inlen    The length of the input data in bytes.
 * \param key      The key used for a keyed HMAC. This may be \c NULL
 *                 if \p keylen is \c 0, in which case an unkeyed hash is
 *                 computed. Otherwise this must be a readable buffer of
 *                 length \p keylen bytes.
 * \param keylen   The length of \p key in bytes. This must be at most
 *                 \c 32. Use \c 0 for an unkeyed hash.
 * \param out      The buffer to which the digest is written.
 *                 This must be a writable buffer of length \p outlen
 *                 bytes.
 * \param outlen   The desired length of the digest, in bytes. This must be
 *                 greater than \c 0 and at most \c 32.
 *
 * \return         \c 0 on success.
 * \return         #TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA if \p outlen or
 *                 \p keylen is invalid.
 */
int tf_psa_crypto_blake2s(const uint8_t *in, size_t inlen,
                          const void *key, size_t keylen,
                          uint8_t *out, size_t outlen);

#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256 */

/**
 * \brief          The BLAKE2b context structure.
 */
typedef struct tf_psa_crypto_blake2b_context {
    uint8_t MBEDTLS_PRIVATE(buf[128]);              /*!< The data block being processed. */
    uint64_t MBEDTLS_PRIVATE(state[8]);             /*!< The intermediate digest state. */
    uint64_t MBEDTLS_PRIVATE(processed_bytes[2]);   /*!< The number of Bytes processed, as a
                                                       128-bit little-endian counter split
                                                       into two 64-bit words. */
    size_t MBEDTLS_PRIVATE(buf_idx);                /*!< The number of bytes currently held
                                                       in \c buf. */
    size_t MBEDTLS_PRIVATE(outlen);                 /*!< The configured digest length, in
                                                       bytes. */
} tf_psa_crypto_blake2b_context;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512)

/**
 * \brief          This function initializes a BLAKE2s context and starts a
 *                 new hash or HMAC operation.
 *
 *                 It must be the first API called before using the context,
 *                 and it must be called again before starting a new
 *                 operation with the same context.
 *
 * \param ctx      The BLAKE2s context to initialize. This must not be
 *                 \c NULL.
 * \param outlen   The desired length of the digest, in bytes. This must be
 *                 greater than \c 0 and at most \c 64.
 * \param key      The key used in case of HMAC operation. This can be \c NULL
 *                 if \p keylen is \c 0, in which case an unkeyed hash is
 *                 computed. Otherwise this must be a readable buffer of
 *                 length \p keylen bytes.
 * \param keylen   The length of \p key in bytes. This must be at most
 *                 \c 64. Use \c 0 for an unkeyed hash.
 *
 * \return         \c 0 on success.
 * \return         #TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA if \p outlen or
 *                 \p keylen is invalid.
 */
int tf_psa_crypto_blake2b_init(tf_psa_crypto_blake2b_context *ctx, size_t outlen,
                               const void *key, size_t keylen);

/**
 * \brief          This function releases and clears the specified BLAKE2b
 *                 context.
 *
 * \param ctx      The BLAKE2b context to clear.
 *                 If this is \c NULL, this function does nothing.
 *                 Otherwise, the context must have been at least
 *                 initialized.
 */
void tf_psa_crypto_blake2b_free(tf_psa_crypto_blake2b_context *ctx);

/**
 * \brief          This function clones the state of a BLAKE2b context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void tf_psa_crypto_blake2b_clone(tf_psa_crypto_blake2b_context *dst,
                                 const tf_psa_crypto_blake2b_context *src);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 BLAKE2b hash or HMAC operation.
 *
 *                 It can be called repeatedly to process a message
 *                 incrementally.
 *
 * \param ctx      The BLAKE2b context. This must be initialized.
 * \param in       The buffer holding the data. This must be a readable
 *                 buffer of length \p inlen bytes.
 * \param inlen    The length of the input data in bytes.
 */
void tf_psa_crypto_blake2b_update(tf_psa_crypto_blake2b_context *ctx,
                                  const uint8_t *in, size_t inlen);

/**
 * \brief          This function finishes a BLAKE2b operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The BLAKE2b context. This must be initialized.
 * \param out      The buffer to which the digest is written.
 *                 This must be a writable buffer of length \p outlen
 *                 bytes.
 * \param outlen   The size of the \p out buffer in bytes. This must be at
 *                 least the digest length that was passed to
 *                 tf_psa_crypto_blake2b_init().
 *
 * \return         \c 0 on success.
 * \return         #TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL if \p outlen is
 *                 smaller than the digest length configured at
 *                 initialization time.
 */
int tf_psa_crypto_blake2b_finish(tf_psa_crypto_blake2b_context *ctx,
                                 uint8_t *out, size_t outlen);

/**
 * \brief          This function calculates the BLAKE2b hash or HMAC of the
 *                 given buffer.
 *
 * \param in       The buffer holding the data. This must be a readable
 *                 buffer of length \p inlen bytes.
 * \param inlen    The length of the input data in bytes.
 * \param key      The key used for a keyed HMAC. This may be \c NULL
 *                 if \p keylen is \c 0, in which case an unkeyed hash is
 *                 computed. Otherwise this must be a readable buffer of
 *                 length \p keylen bytes.
 * \param keylen   The length of \p key in bytes. This must be at most
 *                 \c 64. Use \c 0 for an unkeyed hash.
 * \param out      The buffer to which the digest is written.
 *                 This must be a writable buffer of length \p outlen
 *                 bytes.
 * \param outlen   The desired length of the digest, in bytes. This must be
 *                 greater than \c 0 and at most \c 64.
 *
 * \return         \c 0 on success.
 * \return         #TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA if \p outlen or
 *                 \p keylen is invalid.
 */
int tf_psa_crypto_blake2b(const uint8_t *in, size_t inlen,
                          const void *key, size_t keylen,
                          uint8_t *out, size_t outlen);

#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512 */

#ifdef __cplusplus
}
#endif

#endif /* TF_PSA_CRYPTO_PRIVATE_BLAKE2_H */

#ifndef MBEDTLS_PSA_CRYPTO_ASYNC_HARDWARE_H
#define MBEDTLS_PSA_CRYPTO_ASYNC_HARDWARE_H

#include <psa/crypto_values.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t mbedtls_psa_async_crypto_capability_t;

#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE ((mbedtls_psa_async_crypto_capability_t) 0)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RANDOM ((mbedtls_psa_async_crypto_capability_t) 1 << 0)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_ECB ((mbedtls_psa_async_crypto_capability_t) 1 << 1)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CBC ((mbedtls_psa_async_crypto_capability_t) 1 << 2)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CTR ((mbedtls_psa_async_crypto_capability_t) 1 << 3)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CCM ((mbedtls_psa_async_crypto_capability_t) 1 << 4)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_GCM ((mbedtls_psa_async_crypto_capability_t) 1 << 5)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_GHASH                                              \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 6)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_SHA_1 ((mbedtls_psa_async_crypto_capability_t) 1 << 7)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_SHA_224 ((mbedtls_psa_async_crypto_capability_t) 1 << 8)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_SHA_256 ((mbedtls_psa_async_crypto_capability_t) 1 << 9)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_HMAC_SHA_1                                             \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 10)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_HMAC_SHA_224                                           \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 11)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_HMAC_SHA_256                                           \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 12)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDH ((mbedtls_psa_async_crypto_capability_t) 1 << 13)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDSA ((mbedtls_psa_async_crypto_capability_t) 1 << 14)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RSA ((mbedtls_psa_async_crypto_capability_t) 1 << 15)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RSA_CRT ((mbedtls_psa_async_crypto_capability_t) 1 << \
                                                     16)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDH_GF2N                                              \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 17)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDSA_GF2N                                             \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 18)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CFB ((mbedtls_psa_async_crypto_capability_t) 1 << \
                                                     19)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_OFB ((mbedtls_psa_async_crypto_capability_t) 1 << \
                                                     20)
#define MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_EXPORT_PUBLIC_KEY                                      \
    ((mbedtls_psa_async_crypto_capability_t) 1 << 21)

#define MBEDTLS_PSA_ASYNC_CRYPTO_MAX_INPUT_SEGMENTS 7

typedef enum mbedtls_psa_async_crypto_operation_kind_e {
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM = 0,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_CIPHER = 1,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AEAD = 2,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_SIGN_HASH = 3,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_VERIFY_HASH = 4,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_KEY_AGREEMENT = 5,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA = 6,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RSA_CRT = 7,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_EXPORT_PUBLIC_KEY = 8,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HASH = 9,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HMAC = 10,
    MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AES_GHASH = 11
} mbedtls_psa_async_crypto_operation_kind_t;

typedef enum mbedtls_psa_async_crypto_direction_e {
    MBEDTLS_PSA_ASYNC_CRYPTO_DECRYPT = 0,
    MBEDTLS_PSA_ASYNC_CRYPTO_ENCRYPT = 1
} mbedtls_psa_async_crypto_direction_t;

typedef enum mbedtls_psa_async_crypto_rsa_mode_e {
    MBEDTLS_PSA_ASYNC_CRYPTO_RSA_MODE_REGULAR = 0,
    MBEDTLS_PSA_ASYNC_CRYPTO_RSA_MODE_FAST = 1
} mbedtls_psa_async_crypto_rsa_mode_t;

typedef enum mbedtls_psa_async_crypto_rsa_window_e {
    MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_1 = 1,
    MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_2 = 2,
    MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_3 = 3,
    MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_4 = 4
} mbedtls_psa_async_crypto_rsa_window_t;

typedef struct mbedtls_psa_async_crypto_const_buffer_s {
    const uint8_t *data;
    size_t length;
} mbedtls_psa_async_crypto_const_buffer_t;

typedef struct mbedtls_psa_async_crypto_buffer_s {
    uint8_t *data;
    size_t length;
} mbedtls_psa_async_crypto_buffer_t;

typedef struct mbedtls_psa_async_crypto_prime_curve_s {
    mbedtls_psa_async_crypto_const_buffer_t prime;
    mbedtls_psa_async_crypto_const_buffer_t order;
    mbedtls_psa_async_crypto_const_buffer_t a;
    mbedtls_psa_async_crypto_const_buffer_t b;
    mbedtls_psa_async_crypto_const_buffer_t gx;
    mbedtls_psa_async_crypto_const_buffer_t gy;
    size_t hash_length;
} mbedtls_psa_async_crypto_prime_curve_t;

typedef struct mbedtls_psa_async_crypto_binary_curve_s {
    mbedtls_psa_async_crypto_const_buffer_t polynomial;
    mbedtls_psa_async_crypto_const_buffer_t order;
    mbedtls_psa_async_crypto_const_buffer_t a;
    mbedtls_psa_async_crypto_const_buffer_t b;
    mbedtls_psa_async_crypto_const_buffer_t gx;
    mbedtls_psa_async_crypto_const_buffer_t gy;
    size_t hash_length;
} mbedtls_psa_async_crypto_binary_curve_t;

typedef struct mbedtls_psa_async_crypto_request_s {
    mbedtls_psa_async_crypto_operation_kind_t operation;
    psa_key_type_t key_type;
    size_t key_bits;
    psa_algorithm_t alg;
    mbedtls_psa_async_crypto_direction_t direction;
    mbedtls_psa_async_crypto_const_buffer_t key;
    mbedtls_psa_async_crypto_const_buffer_t iv;
    mbedtls_psa_async_crypto_const_buffer_t nonce;
    mbedtls_psa_async_crypto_const_buffer_t additional_data;
    mbedtls_psa_async_crypto_const_buffer_t input;
    const mbedtls_psa_async_crypto_const_buffer_t *input_segments;
    size_t input_segment_count;
    mbedtls_psa_async_crypto_buffer_t output;
    mbedtls_psa_async_crypto_const_buffer_t input_tag;
    mbedtls_psa_async_crypto_buffer_t output_tag;
    mbedtls_psa_async_crypto_const_buffer_t modulus;
    mbedtls_psa_async_crypto_const_buffer_t exponent;
    mbedtls_psa_async_crypto_const_buffer_t prime_p;
    mbedtls_psa_async_crypto_const_buffer_t prime_q;
    mbedtls_psa_async_crypto_const_buffer_t exponent_p;
    mbedtls_psa_async_crypto_const_buffer_t exponent_q;
    mbedtls_psa_async_crypto_const_buffer_t q_inverse;
    mbedtls_psa_async_crypto_const_buffer_t private_key;
    mbedtls_psa_async_crypto_const_buffer_t public_key;
    mbedtls_psa_async_crypto_const_buffer_t nonce_scalar;
    mbedtls_psa_async_crypto_const_buffer_t peer_key;
    mbedtls_psa_async_crypto_const_buffer_t hash;
    mbedtls_psa_async_crypto_buffer_t signature;
    mbedtls_psa_async_crypto_buffer_t shared_secret;
    mbedtls_psa_async_crypto_buffer_t public_key_output;
    const mbedtls_psa_async_crypto_prime_curve_t *prime_curve;
    const mbedtls_psa_async_crypto_binary_curve_t *binary_curve;
    mbedtls_psa_async_crypto_rsa_mode_t rsa_mode;
    mbedtls_psa_async_crypto_rsa_window_t rsa_window;
    uint32_t blinding;
} mbedtls_psa_async_crypto_request_t;

typedef void (*mbedtls_psa_async_crypto_hardware_callback_t)(psa_status_t status,
                                                             void *callback_context);

typedef struct mbedtls_psa_async_crypto_hardware_completion_s {
    mbedtls_psa_async_crypto_hardware_callback_t callback;
    void *context;
} mbedtls_psa_async_crypto_hardware_completion_t;

typedef psa_status_t (*mbedtls_psa_async_crypto_hardware_operation_t)(
    void *hardware_context, const mbedtls_psa_async_crypto_request_t *request,
    mbedtls_psa_async_crypto_hardware_completion_t *completion);

typedef struct mbedtls_psa_async_crypto_hardware_functions_s {
    mbedtls_psa_async_crypto_capability_t (*get_capabilities)(void *hardware_context);
    mbedtls_psa_async_crypto_hardware_operation_t generate_random;
    mbedtls_psa_async_crypto_hardware_operation_t cipher;
    mbedtls_psa_async_crypto_hardware_operation_t aead;
    mbedtls_psa_async_crypto_hardware_operation_t aes_ghash;
    mbedtls_psa_async_crypto_hardware_operation_t hash;
    mbedtls_psa_async_crypto_hardware_operation_t hmac;
    mbedtls_psa_async_crypto_hardware_operation_t sign_hash;
    mbedtls_psa_async_crypto_hardware_operation_t verify_hash;
    mbedtls_psa_async_crypto_hardware_operation_t key_agreement;
    mbedtls_psa_async_crypto_hardware_operation_t export_public_key;
    mbedtls_psa_async_crypto_hardware_operation_t raw_rsa;
    mbedtls_psa_async_crypto_hardware_operation_t rsa_crt;
} mbedtls_psa_async_crypto_hardware_functions_t;

typedef struct mbedtls_psa_async_crypto_hardware_s {
    const mbedtls_psa_async_crypto_hardware_functions_t *functions;
    void *context;
} mbedtls_psa_async_crypto_hardware_t;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PSA_CRYPTO_ASYNC_HARDWARE_H */

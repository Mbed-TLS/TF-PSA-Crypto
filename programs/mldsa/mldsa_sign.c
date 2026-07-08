#include <stdio.h>

#include <tf-psa-crypto/build_info.h>

#include "wrap_mldsa_native.h"
#include "psa_crypto_mldsa.h"
#include "mbedtls/platform.h"
#include "mldsa_constants.h"
#include "asn1_file_io.h"
#include "psa/crypto.h"

int main(void)
{
#if !defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED) || \
    !defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED) || \
    !defined(MBEDTLS_PSA_BUILTIN_GET_ENTROPY) || \
    !defined(MBEDTLS_ASN1_WRITE_C) || \
    defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS) || \
    defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    puts(
        "These programs require TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED MBEDTLS_ASN1_WRITE_C !MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS !MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG to be enabled in crypto_config.h");
    return 0;
#else

    uint8_t signature[MLDSA_BYTES(KEY_LENGTH)];
    size_t signature_length = 0;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_crypto_init();

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&attributes, KEY_LENGTH);

    /* Sign into an exact-size buffer */
    if (tf_psa_crypto_mldsa_sign_message(&attributes, seed, sizeof(seed),
                                         PSA_ALG_DETERMINISTIC_ML_DSA,
                                         message, sizeof(message),
                                         signature, MLDSA_BYTES(KEY_LENGTH),
                                         &signature_length) != 0) {
        mbedtls_printf("sign failed\n");
        return 1;
    }

    if (signature_length != sizeof(signature) ||
        asn1_write_octet_string_file(signature_file, signature, signature_length) != PSA_SUCCESS) {
        mbedtls_printf("signature export failed\n");
        return 1;
    }
#endif
}

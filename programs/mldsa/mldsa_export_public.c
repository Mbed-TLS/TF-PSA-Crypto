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

    uint8_t public_key[MLDSA_PUBLICKEYBYTES(KEY_LENGTH)];

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t public_key_length = SIZE_MAX;

    psa_crypto_init();

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&attributes, KEY_LENGTH);

    /* Export into an exact-size buffer */
    if (tf_psa_crypto_mldsa_export_public_key(&attributes,
                                              seed, sizeof(seed),
                                              public_key,
                                              MLDSA_PUBLICKEYBYTES(KEY_LENGTH),
                                              &public_key_length) != PSA_SUCCESS) {
        mbedtls_printf("key generation failed\n");
        return 1;
    }

    if (asn1_write_octet_string_file(pub_key_file, public_key, public_key_length) != 0) {
        mbedtls_printf("key export failed\n");
        return 1;
    }
#endif
}

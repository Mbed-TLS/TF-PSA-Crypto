/*
 *  RFC 9180 compliant HPKE implementation.
 
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

 /**
  * This implementation is based on the following standards: https://datatracker.ietf.org/doc/rfc9180/ 
  * 
  */

#define PSA_HPKE_C
#if defined(PSA_HPKE_C)

#include <math.h>
#include <stdlib.h>
#include <string.h>


#include "tf_psa_crypto_common.h"
#include "mbedtls/private_access.h"
#include "mbedtls/private/hpke.h"

#include "psa/crypto.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_aead.h"
#include "psa_crypto_hash.h"

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"




psa_status_t psa_hpke_setup_parameters(enum PSA_HPKE_algo_id selected, uint8_t mode, char* psk, size_t psk_len, psa_hpke_params *params){
    if(mode !=PSA_HPKE_MODE_BASE){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    uint16_t kem_id=0;
    uint16_t kdf_id=0;
    uint16_t aead_id=0;


    if(selected==PSA_HPKE_KEM32_SHA256_AES128GCM){
        kem_id = 32; 
        kdf_id =  1; 
        aead_id = 1; 

    }
    else if(selected==PSA_HPKE_KEM32_SHA256_CHACHAPOLY1305){
        kem_id = 32; 
        kdf_id =  1; 
        aead_id = 3;
        return PSA_HPKE_ERR_NOT_SUPPORTED;

    }
    else if(selected==PSA_HPKE_KEM16_SHA256_AES128GCM){
        kem_id = 16; 
        kdf_id =  1; 
        aead_id = 1; 
        return PSA_HPKE_ERR_NOT_SUPPORTED;

    }
    else if(selected==PSA_HPKE_KEM16_SHA512_AES128GCM){
        kem_id = 16; 
        kdf_id =  3; 
        aead_id = 1; 
        return PSA_HPKE_ERR_NOT_SUPPORTED;

    }
    else if(selected==PSA_HPKE_KEM16_SHA256_CHACHAPOLY1305){
        kem_id = 16; 
        kdf_id =  1; 
        aead_id = 3; 
        return PSA_HPKE_ERR_NOT_SUPPORTED;

    }
    else if(selected==PSA_HPKE_KEM18_SHA512_AES256GCM){
        kem_id = 18; 
        kdf_id =  3; 
        aead_id = 2; 
    }else{
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    return psa_hpke_setup_parameters_extended(kem_id, kdf_id, aead_id, mode, psk, psk_len, params);

}



psa_status_t psa_hpke_setup_parameters_extended(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id, uint8_t mode, char* psk,size_t psk_len, psa_hpke_params *params){

    if(psk!= NULL || psk_len !=0){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    if(kem_id!=16 && kem_id!=17 && kem_id!=18 && kem_id!=32 && kem_id!=33){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    if(kdf_id!=1 && kdf_id!=2 && kdf_id!=3){
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(aead_id!=1 && aead_id!=2 && aead_id!=3){
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    
    if(mode !=PSA_HPKE_MODE_BASE){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    params->PSA_HPKE_MODE = mode;
    params->PSA_HPKE_KEM_ID = kem_id; 
    params->PSA_HPKE_KDF_ID = kdf_id; 
    params->PSA_HPKE_AEAD_ID= aead_id; 

    


    //setting KEM related parameters
    if(params->PSA_HPKE_KEM_ID == 16){
        //DHKEM(P-256, HKDF-SHA256)
        params->PSA_HPKE_KEM_NSECRET=(uint16_t) 32; //The length in bytes of a KEM shared secret produced by this KEM.
        params->PSA_HPKE_KEM_NENC=(uint16_t) 65; //The length in bytes of an encapsulated key produced by this KEM.
        params->PSA_HPKE_KEM_NPK=(uint16_t) 65; // The length in bytes of an encoded public key for this KEM.
        params->PSA_HPKE_KEM_NSK=(uint16_t) 32; //The length in bytes of an encoded private key for this KEM.

        params->PSA_HPKE_KEM_NDH =(uint16_t) 32; // the size of the Diffie-Hellman shared secret for P-256 in byte
        params->PSA_HPKE_KEM_KDF=PSA_ALG_SHA_256;
        params->PSA_HPKE_KEM_KDF_NH=(uint16_t)32;
        params->PSA_HPKE_KEM_CURVE_ID=MBEDTLS_ECP_DP_SECP256R1;
        params->PSA_HPKE_KEM_KEY_TYPE=PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        params->PSA_HPKE_KEM_KEY_ALG=PSA_ALG_ECDH;
    }
    else if(params->PSA_HPKE_KEM_ID == 17){
        //DHKEM(P-384, HKDF-SHA256)
        params->PSA_HPKE_KEM_NSECRET=(uint16_t) 48; //The length in bytes of a KEM shared secret produced by this KEM.
        params->PSA_HPKE_KEM_NENC=(uint16_t) 97; //The length in bytes of an encapsulated key produced by this KEM.
        params->PSA_HPKE_KEM_NPK=(uint16_t) 97; // The length in bytes of an encoded public key for this KEM.
        params->PSA_HPKE_KEM_NSK=(uint16_t) 48; //The length in bytes of an encoded private key for this KEM.
        
        params->PSA_HPKE_KEM_NDH =(uint16_t) 48; // the size of the Diffie-Hellman shared secret for P-384 in byte
        params->PSA_HPKE_KEM_KDF=PSA_ALG_SHA_256;
        params->PSA_HPKE_KEM_KDF_NH=(uint16_t)32;
        params->PSA_HPKE_KEM_CURVE_ID=MBEDTLS_ECP_DP_SECP384R1;
        params->PSA_HPKE_KEM_KEY_TYPE=PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        params->PSA_HPKE_KEM_KEY_ALG=PSA_ALG_ECDH;

    }
    else if(params->PSA_HPKE_KEM_ID ==18){
        //DHKEM(P-521, HKDF-SHA512)
        params->PSA_HPKE_KEM_NSECRET=(uint16_t) 64; //The length in bytes of a KEM shared secret produced by this KEM.
        params->PSA_HPKE_KEM_NENC=(uint16_t) 133; //The length in bytes of an encapsulated key produced by this KEM.
        params->PSA_HPKE_KEM_NPK=(uint16_t) 133; // The length in bytes of an encoded public key for this KEM.
        params->PSA_HPKE_KEM_NSK=(uint16_t) 66; //The length in bytes of an encoded private key for this KEM.
        
        params->PSA_HPKE_KEM_NDH =(uint16_t) 66; // the size of the Diffie-Hellman shared secret for P-521 in byte
        params->PSA_HPKE_KEM_KDF=PSA_ALG_SHA_512;
        params->PSA_HPKE_KEM_KDF_NH=(uint16_t)64;
        params->PSA_HPKE_KEM_CURVE_ID=MBEDTLS_ECP_DP_SECP521R1;
        params->PSA_HPKE_KEM_KEY_TYPE=PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        params->PSA_HPKE_KEM_KEY_ALG=PSA_ALG_ECDH;


    }
    else if(params->PSA_HPKE_KEM_ID ==32){
        //DHKEM(X25519, HKDF-SHA256)
        params->PSA_HPKE_KEM_NSECRET=(uint16_t) 32; //The length in bytes of a KEM shared secret produced by this KEM.
        params->PSA_HPKE_KEM_NENC=(uint16_t) 32; //The length in bytes of an encapsulated key produced by this KEM.
        params->PSA_HPKE_KEM_NPK=(uint16_t) 32; // The length in bytes of an encoded public key for this KEM.
        params->PSA_HPKE_KEM_NSK=(uint16_t) 32; //The length in bytes of an encoded private key for this KEM.
        
        params->PSA_HPKE_KEM_NDH =(uint16_t) 32; // the size of the Diffie-Hellman shared secret for X25519
        params->PSA_HPKE_KEM_KDF=PSA_ALG_SHA_256;
        params->PSA_HPKE_KEM_KDF_NH=(uint16_t)32;
        params->PSA_HPKE_KEM_CURVE_ID=MBEDTLS_ECP_DP_CURVE25519;
        params->PSA_HPKE_KEM_KEY_TYPE=PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        params->PSA_HPKE_KEM_KEY_ALG=PSA_ALG_ECDH;

    }
    else if(params->PSA_HPKE_KEM_ID == 33){
        //DHKEM(X448, HKDF-SHA512)
        params->PSA_HPKE_KEM_NSECRET=(uint16_t) 64; //The length in bytes of a KEM shared secret produced by this KEM.
        params->PSA_HPKE_KEM_NENC=(uint16_t) 56; //The length in bytes of an encapsulated key produced by this KEM.
        params->PSA_HPKE_KEM_NPK=(uint16_t) 56; // The length in bytes of an encoded public key for this KEM.
        params->PSA_HPKE_KEM_NSK=(uint16_t) 56; //The length in bytes of an encoded private key for this KEM.
        
        params->PSA_HPKE_KEM_NDH =(uint16_t) 56; // the size of the Diffie-Hellman shared secret for X448
        params->PSA_HPKE_KEM_KDF=PSA_ALG_SHA_512;
        params->PSA_HPKE_KEM_KDF_NH=(uint16_t)64;
        params->PSA_HPKE_KEM_CURVE_ID=MBEDTLS_ECP_DP_CURVE448;
        params->PSA_HPKE_KEM_KEY_TYPE=PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        params->PSA_HPKE_KEM_KEY_ALG=PSA_ALG_ECDH;


    }else{
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    //Setting KDF related parameters
    if(params->PSA_HPKE_KDF_ID== 1){
        params->PSA_HPKE_KDF=PSA_ALG_SHA_256;
        params->PSA_HPKE_KDF_NH=(uint16_t) 32; // Given in Table 3 of RFC for HKDF-SHA256. The output size of the Extract() function of the KDF in bytes.
        params->PSA_HPKE_INPUT_LIMITS_PSK=(size_t) (pow(2, 61) - 88); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_PSK_ID=(size_t) (pow(2, 61) - 93); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_INFO=(size_t) (pow(2, 61) - 91); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT =(size_t) (pow(2, 61) - 120); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_IKM=(size_t) (pow(2, 61) - 84); //in bytes. Given in Table 4 of the RFC
        
    }else if(params->PSA_HPKE_KDF_ID==2){
        params->PSA_HPKE_KDF=PSA_ALG_SHA_384;
        params->PSA_HPKE_KDF_NH=(uint16_t) 48; // Given in Table 3 of RFC for HKDF-SHA384. The output size of the Extract() function of the KDF in bytes.
        params->PSA_HPKE_INPUT_LIMITS_PSK=(size_t) (pow(2, 125) - 152); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_PSK_ID=(size_t) (pow(2, 125) - 157); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_INFO=(size_t) (pow(2, 125) - 155); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT =(size_t) (pow(2, 125) - 200); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_IKM=(size_t) (pow(2, 125) - 148); //in bytes. Given in Table 4 of the RFC
    
        
    }else if(params->PSA_HPKE_KDF_ID==3){
        params->PSA_HPKE_KDF=PSA_ALG_SHA_512;
        params->PSA_HPKE_KDF_NH=(uint16_t) 64; // Given in Table 3 of RFC for HKDF-SHA512. The output size of the Extract() function of the KDF in bytes.
        params->PSA_HPKE_INPUT_LIMITS_PSK=(size_t) (pow(2, 125) - 152); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_PSK_ID=(size_t) (pow(2, 125) - 157); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_INFO=(size_t) (pow(2, 125) - 155); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT =(size_t) (pow(2, 125) - 216); //in bytes. Given in Table 4 of the RFC
        params->PSA_HPKE_INPUT_LIMITS_IKM=(size_t) (pow(2, 125) - 148); //in bytes. Given in Table 4 of the RFC
    
    }else{
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }


    //setting AEAD related parameters
    if(params->PSA_HPKE_AEAD_ID==1){
        //AES-128-GCM
        params->PSA_HPKE_AEAD_NK=(uint16_t) 16; // Given in Table 5 of the RFC for AES-128-GCM. The length in bytes of a key for the AEAD algorithm.
        params->PSA_HPKE_AEAD_NN= (uint16_t) 12; // Given in Table 5 of the RFC for AES-128-GCM. The length in bytes of a nonce for the AEAD algorithm.
        params->PSA_HPKE_AEAD_NT= (uint16_t) 16; // Given in Table 5 of the RFC for AES-128-GCM. The length in bytes of the authentication tag for AEAD algorithm.
        params->PSA_HPKE_AEAD_KEY_TYPE= PSA_KEY_TYPE_AES;
        params->PSA_HPKE_AEAD_ALGO= PSA_ALG_GCM;
    
    }
    else if(params->PSA_HPKE_AEAD_ID==2){
        //AES-256-GCM
        params->PSA_HPKE_AEAD_NK= (uint16_t) 32; // Given in Table 5 of the RFC for AES-256-GCM. The length in bytes of a key for the AEAD algorithm.
        params->PSA_HPKE_AEAD_NN= (uint16_t) 12; // Given in Table 5 of the RFC for AES-256-GCM. The length in bytes of a nonce for the AEAD algorithm.
        params->PSA_HPKE_AEAD_NT= (uint16_t) 16; // Given in Table 5 of the RFC for AES-256-GCM. The length in bytes of the authentication tag for AEAD algorithm.
        params->PSA_HPKE_AEAD_KEY_TYPE= PSA_KEY_TYPE_AES;
        params->PSA_HPKE_AEAD_ALGO= PSA_ALG_GCM;
    }
    else if(params->PSA_HPKE_AEAD_ID==3){
        //ChaCha20Poly1305
        params->PSA_HPKE_AEAD_NK= (uint16_t) 32; // Given in Table 5 of the RFC for ChaCha20Poly1305. The length in bytes of a key for the AEAD algorithm.
        params->PSA_HPKE_AEAD_NN= (uint16_t) 12; // Given in Table 5 of the RFC for ChaCha20Poly1305. The length in bytes of a nonce for the AEAD algorithm.
        params->PSA_HPKE_AEAD_NT= (uint16_t) 16; // Given in Table 5 of the RFC for ChaCha20Poly1305. The length in bytes of the authentication tag for AEAD algorithm.
        params->PSA_HPKE_AEAD_KEY_TYPE= PSA_KEY_TYPE_CHACHA20;
        params->PSA_HPKE_AEAD_ALGO= PSA_ALG_CHACHA20_POLY1305;
    }
    else{
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;


}




psa_status_t psa_hpke_create_hpke_context(psa_hpke_params *params,enum PSA_HPKE_role_t role, 
                                              unsigned char *kem_shared_secret, 
                                              unsigned char *info, size_t info_size,
                                              psa_hpke_context_t *ctx)
{
    if (params->PSA_HPKE_MODE != PSA_HPKE_MODE_BASE) {
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (params->PSA_HPKE_KDF_NH > PSA_HPKE_MAX_KDF_NH || params->PSA_HPKE_AEAD_NK > PSA_HPKE_MAX_AEAD_NK) {
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    unsigned char psk_hash[PSA_HPKE_MAX_KDF_NH];
    unsigned char info_hash[PSA_HPKE_MAX_KDF_NH];
    size_t key_schedule_context_len = 2*params->PSA_HPKE_KDF_NH+1;
    unsigned char key_schedule_context[PSA_HPKE_MAX_KEY_SCHEDULE_CONTEXT_LEN];
    unsigned char secret[PSA_HPKE_MAX_KDF_NH];
    unsigned char key[PSA_HPKE_MAX_AEAD_NK];

    ctx->role = role;

    // Initialize the embedded structures in the context
    mbedtls_mpi_init(&ctx->sequence_number);
    mbedtls_mpi_init(&ctx->max_value);

    status = mbedtls_mpi_lset(&ctx->sequence_number, 0);
    if (status != PSA_SUCCESS) {
        mbedtls_mpi_free(&ctx->sequence_number);
        mbedtls_mpi_free(&ctx->max_value);
        return status;
    }

    mbedtls_mpi temp;
    mbedtls_mpi_init(&temp);
    size_t pos = 8*params->PSA_HPKE_AEAD_NN;
    status = mbedtls_mpi_set_bit(&temp, pos, 1);
    if (status != PSA_SUCCESS) {
        mbedtls_mpi_free(&ctx->sequence_number);
        mbedtls_mpi_free(&ctx->max_value);
        mbedtls_mpi_free(&temp);
        return status;
    }
    mbedtls_mpi_sub_int(&ctx->max_value, &temp, 1); //max_value=temp-1
    if (status != PSA_SUCCESS) {
        mbedtls_mpi_free(&ctx->sequence_number);
        mbedtls_mpi_free(&ctx->max_value);
        mbedtls_mpi_free(&temp);
        return status;
    }
    mbedtls_mpi_free(&temp);

    // Initialize the embedded arrays to zero
    unsigned char *base_nonce = mbedtls_calloc(params->PSA_HPKE_AEAD_NN, 1);
    if (base_nonce == NULL) {
        return PSA_HPKE_INSUFFICIENT_MEMORY;
    }
    ctx->base_nonce = base_nonce;
    ctx->base_nonce_len = params->PSA_HPKE_AEAD_NN;

    unsigned char *exporter_secret = mbedtls_calloc(params->PSA_HPKE_KDF_NH, 1);
    if (exporter_secret == NULL) {
        return PSA_HPKE_INSUFFICIENT_MEMORY;
    }
    ctx->exporter_secret = exporter_secret;
    ctx->exporter_secret_len = params->PSA_HPKE_KDF_NH;

    //calculating psk id hash
    const unsigned char *salt = NULL;
    const unsigned char label_info[] = { 'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h' };
    uint8_t is_KEM = 0;
    status = psa_hpke_hkdf_labeledExtract(params, salt,
                                                    0,
                                                    label_info,
                                                    9,
                                                    info,
                                                    info_size,
                                                    is_KEM,
                                                    info_hash,
                                                    params->PSA_HPKE_KDF_NH);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    const unsigned char *psk_id=NULL;
    const unsigned char label_psk[] = { 'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h' };
    status = psa_hpke_hkdf_labeledExtract(params, 
                                                    salt,
                                                    0,
                                                    label_psk,
                                                    sizeof(label_psk),
                                                    psk_id,
                                                    0,
                                                    is_KEM,
                                                    psk_hash,
                                                    params->PSA_HPKE_KDF_NH);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    //create key_schedule_context without preshared key
    size_t offset = 0;
    memcpy(key_schedule_context, &params->PSA_HPKE_MODE, 1);
    offset += 1;
    memcpy(key_schedule_context + offset, psk_hash, params->PSA_HPKE_KDF_NH);
    offset += params->PSA_HPKE_KDF_NH;
    memcpy(key_schedule_context + offset, info_hash, params->PSA_HPKE_KDF_NH);




    //generate a secret without psk
    const unsigned char label_secret[] = { 's', 'e', 'c', 'r', 'e', 't' };
    const unsigned char *psk=NULL;
    status = psa_hpke_hkdf_labeledExtract(params, 
                                                kem_shared_secret, 
                                                params->PSA_HPKE_KEM_NSECRET,
                                                label_secret, 
                                                6, 
                                                psk, 
                                                0, 
                                                is_KEM, 
                                                secret,
                                                params->PSA_HPKE_KDF_NH);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }



    //derive symmetric key for HPKE
    const unsigned char label_key[] = { 'k', 'e', 'y' };
    status = psa_hpke_hkdf_labeledExpand(params,
                                                secret, 
                                                params->PSA_HPKE_KDF_NH, 
                                                label_key, 
                                                3,
                                                key_schedule_context, 
                                                key_schedule_context_len,
                                                is_KEM, 
                                                key,  
                                                params->PSA_HPKE_AEAD_NK);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }



    //derive base nonce
    const unsigned char label_base_nonce[] = { 'b', 'a', 's', 'e', '_', 'n', 'o', 'n', 'c', 'e' };
    status = psa_hpke_hkdf_labeledExpand(params, 
                                                    secret,
                                                    params->PSA_HPKE_KDF_NH,
                                                    label_base_nonce,
                                                    10,
                                                    key_schedule_context,
                                                    key_schedule_context_len,
                                                    is_KEM,
                                                    ctx->base_nonce,
                                                    params->PSA_HPKE_AEAD_NN);
                                                   
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }


    //derive exporter secret
    const unsigned char label_exporter_secret[] = { 'e', 'x', 'p' };
    status = psa_hpke_hkdf_labeledExpand(params,
                                                    secret,
                                                    params->PSA_HPKE_KDF_NH,
                                                    label_exporter_secret,
                                                    3,
                                                    key_schedule_context,
                                                    key_schedule_context_len,
                                                    is_KEM,                                                
                                                    ctx->exporter_secret,
                                                    params->PSA_HPKE_KDF_NH);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }


    psa_key_attributes_t aead_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&aead_attr, params->PSA_HPKE_AEAD_KEY_TYPE);
    psa_set_key_algorithm(&aead_attr, params->PSA_HPKE_AEAD_ALGO);
    psa_set_key_usage_flags(&aead_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&aead_attr, key, params->PSA_HPKE_AEAD_NK, &ctx->aead_key_id);
    psa_reset_key_attributes(&aead_attr);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    mbedtls_platform_zeroize(secret, params->PSA_HPKE_KDF_NH);
    mbedtls_platform_zeroize(key, params->PSA_HPKE_AEAD_NK);
    mbedtls_platform_zeroize(psk_hash, params->PSA_HPKE_KDF_NH);
    mbedtls_platform_zeroize(info_hash, params->PSA_HPKE_KDF_NH);
    mbedtls_platform_zeroize(key_schedule_context, key_schedule_context_len);
    return PSA_SUCCESS;

cleanup:
    psa_hpke_context_free(ctx);
    mbedtls_platform_zeroize(key, params->PSA_HPKE_AEAD_NK);
    mbedtls_platform_zeroize(psk_hash, params->PSA_HPKE_KDF_NH);
    mbedtls_platform_zeroize(info_hash, params->PSA_HPKE_KDF_NH);
    mbedtls_platform_zeroize(key_schedule_context, key_schedule_context_len);
    return status;
}



psa_status_t psa_hpke_context_free(psa_hpke_context_t *ctx)
{
    if (ctx == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    psa_destroy_key(ctx->aead_key_id);
    ctx->aead_key_id = PSA_KEY_ID_NULL;
    mbedtls_zeroize_and_free(ctx->base_nonce, ctx->base_nonce_len);
    mbedtls_zeroize_and_free(ctx->exporter_secret, ctx->exporter_secret_len);
    mbedtls_mpi_free(&ctx->sequence_number);
    mbedtls_mpi_free(&ctx->max_value);

    return PSA_SUCCESS;
}

//checked
psa_status_t psa_hpke_baseSetupSender(psa_hpke_params *params,
                                          unsigned char *pubkey_bytes_R,
                                          unsigned char *info,
                                          size_t info_size,
                                          unsigned char *enc,
                                          psa_hpke_context_t *ctx)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    if(params->PSA_HPKE_KEM_NSECRET > PSA_HPKE_MAX_KEM_NSECRET){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    uint16_t shared_secret_len = params->PSA_HPKE_KEM_NSECRET;
    unsigned char shared_secret[PSA_HPKE_MAX_KEM_NSECRET];
    status = psa_hpke_encap(params,  pubkey_bytes_R, enc, shared_secret);

    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(shared_secret, shared_secret_len);
        return  status;
    }

    status = psa_hpke_create_hpke_context(params, 
                                            PSA_HPKE_SENDER,
                                            shared_secret,
                                            info,
                                            info_size,
                                            ctx);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(shared_secret, shared_secret_len);
        return status;
    }
    mbedtls_platform_zeroize(shared_secret, shared_secret_len);
    return status;
}

//checked
psa_status_t psa_hpke_baseSetupReceiver(psa_hpke_params *params, 
                                            unsigned char *enc,
                                            psa_key_id_t* key_id_R,
                                            unsigned char *info,
                                            size_t info_size,
                                            psa_hpke_context_t *ctx)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    if(params->PSA_HPKE_KEM_NSECRET > PSA_HPKE_MAX_KEM_NSECRET){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    uint16_t shared_secret_len = params->PSA_HPKE_KEM_NSECRET;
    unsigned char shared_secret[PSA_HPKE_MAX_KEM_NSECRET];
    status = psa_hpke_decap(params, enc, key_id_R, shared_secret);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(shared_secret, shared_secret_len);
        return status;
    }
    status = psa_hpke_create_hpke_context(params, 
                                              PSA_HPKE_RECEIVER,
                                              shared_secret,
                                              info,
                                              info_size,
                                              ctx);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(shared_secret, shared_secret_len);
        return status;
    }
    mbedtls_platform_zeroize(shared_secret, shared_secret_len);
    return status;
}

//checked
psa_status_t psa_hpke_seal_single_msg(psa_hpke_params *params,
                                          unsigned char *pubkey_bytes_R,
                                          unsigned char *info,
                                          size_t info_size,
                                          unsigned char *aad,
                                          size_t aad_len,
                                          unsigned char *pt,
                                          size_t pt_size,
                                          unsigned char *enc,
                                          unsigned char *tag,
                                          size_t tag_size,
                                          unsigned char *ciphertext,
                                          size_t ciphertext_size)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_hpke_context_t ctx;
    status = psa_hpke_baseSetupSender(params,  pubkey_bytes_R, info, info_size, enc, &ctx);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hpke_context_sender_seal(params, 
                                             &ctx,
                                              aad,
                                              aad_len,
                                              pt,
                                              pt_size,
                                              tag,
                                              tag_size,
                                              ciphertext,
                                              ciphertext_size);
    if (status != PSA_SUCCESS) {
        psa_hpke_context_free(&ctx);
        return status;
    }
    psa_hpke_context_free(&ctx);
    return PSA_SUCCESS;
}


psa_status_t psa_hpke_open_single_msg(psa_hpke_params *params,
                                          unsigned char *enc,
                                          psa_key_id_t* key_id_R,
                                          unsigned char *info,
                                          size_t info_length,
                                          unsigned char *aad,
                                          size_t aad_len,
                                          unsigned char *tag,
                                          size_t tag_len,
                                          unsigned char *ciphertext,
                                          size_t ciphertext_size,
                                          unsigned char *pt,
                                          size_t pt_size)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_hpke_context_t ctx;
    status = psa_hpke_baseSetupReceiver(params,  enc, key_id_R, info, info_length, &ctx);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hpke_context_receiver_open(params,
                                                &ctx,
                                                aad,
                                                aad_len,
                                                tag,
                                                tag_len,
                                                ciphertext,
                                                ciphertext_size,
                                                pt,
                                                pt_size);
    if (status != PSA_SUCCESS) {
        psa_hpke_context_free(&ctx);
        status=PSA_HPKE_ERR_OPEN_FAILED;
        return status;
    }
    psa_hpke_context_free(&ctx);
    return PSA_SUCCESS;
}


//KEM functions


psa_status_t psa_hpke_kem_deriveKeyPair(psa_hpke_params *params,
                                            unsigned char *ikm,
                                            size_t ikm_len,
                                            psa_key_id_t *key_id,
                                            psa_key_attributes_t *attr)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (ikm == NULL || key_id == NULL || attr == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if (ikm_len < params->PSA_HPKE_KEM_NSK) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(ikm_len > params->PSA_HPKE_INPUT_LIMITS_IKM){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    if(params->PSA_HPKE_KEM_NSK > PSA_HPKE_MAX_KEM_NSK){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    uint8_t is_KEM = 1;
    const unsigned char *salt = NULL;
    size_t salt_len = 0;
    const unsigned char label[] = { 'd', 'k', 'p', '_', 'p', 'r', 'k' };
    size_t label_len = 7;

    size_t dkp_prk_len = PSA_HASH_LENGTH(params->PSA_HPKE_KEM_KDF);

    unsigned char dkp_prk[PSA_HPKE_MAX_KDF_NH];
    if (dkp_prk_len != params->PSA_HPKE_KEM_KDF_NH) {
        return PSA_HPKE_SIZE_MISMATCH;
    }

    status = psa_hpke_hkdf_labeledExtract(params,
                                            salt,
                                            salt_len,
                                            label,
                                            label_len,
                                            ikm,
                                            ikm_len,
                                            is_KEM,
                                            dkp_prk,
                                            dkp_prk_len);

    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(dkp_prk, dkp_prk_len);
        return status;
    }
    
    unsigned char sk[PSA_HPKE_MAX_KEM_NSK];
    const unsigned char label_expand[] = { 's', 'k' };
    size_t label_expand_len = 2;
    const unsigned char *info = NULL;
    size_t info_size = 0;
    status = psa_hpke_hkdf_labeledExpand(params, 
                                                    dkp_prk,
                                                    dkp_prk_len,
                                                    label_expand,
                                                    label_expand_len,
                                                    info,
                                                    info_size,
                                                    is_KEM,
                                                    sk,
                                                    params->PSA_HPKE_KEM_NSK);

    mbedtls_platform_zeroize(dkp_prk, dkp_prk_len);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(sk,  params->PSA_HPKE_KEM_NSK);
        return status;
    }

    status = psa_import_key(attr,  sk, (size_t) params->PSA_HPKE_KEM_NSK, key_id);
    if (status != PSA_SUCCESS){
        return status; //<-
    }

    mbedtls_platform_zeroize(sk, params->PSA_HPKE_KEM_NSK);
    return PSA_SUCCESS;
}


//checked
psa_status_t psa_hpke_kem_generateKeyPair(psa_hpke_params *params,
                                    psa_key_id_t *key_id, psa_key_attributes_t *attr)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    if(params->PSA_HPKE_KEM_NSK > PSA_HPKE_MAX_KEM_NSK){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    size_t ikm_len = params->PSA_HPKE_KEM_NSK; //at least this size is required
    unsigned char ikm[PSA_HPKE_MAX_KEM_NSK];

    status = psa_generate_random(ikm, ikm_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hpke_kem_deriveKeyPair(params, ikm, ikm_len, key_id, attr);
    mbedtls_platform_zeroize(ikm, ikm_len);
    return status;
}


//AEAD functions


psa_status_t psa_hpke_context_sender_seal(psa_hpke_params *params,
                                              psa_hpke_context_t *ctx,
                                              unsigned char *aad, size_t aad_len,
                                              unsigned char *pt, size_t pt_len,
                                              unsigned char *tag, size_t tag_size,
                                              unsigned char *ciphertext, size_t ciphertext_size)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    if (tag_size != params->PSA_HPKE_AEAD_NT) {        
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if (ciphertext_size < pt_len) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if (params->PSA_HPKE_AEAD_NN > PSA_HPKE_MAX_AEAD_NN) {
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    //generating fresh nonce
    size_t nonce_len = params->PSA_HPKE_AEAD_NN;
    unsigned char nonce[PSA_HPKE_MAX_AEAD_NN];
    status = psa_hpke_computeNonce(params, ctx, nonce);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(nonce, nonce_len);
        return status;
    }

    //seal the plaintext using the PSA AEAD API
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    status = psa_aead_encrypt_setup(&aead_op, ctx->aead_key_id, params->PSA_HPKE_AEAD_ALGO);
    if (status != PSA_SUCCESS) {
        goto cleanup; 
    }
    status = psa_aead_set_nonce(&aead_op, nonce, nonce_len);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    status = psa_aead_update_ad(&aead_op, aad, aad_len);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    size_t ct_written = 0;
    status = psa_aead_update(&aead_op, pt, pt_len, ciphertext, ciphertext_size, &ct_written);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    size_t final_ct_len = 0;
    size_t tag_written = 0;
    status = psa_aead_finish(&aead_op, ciphertext + ct_written, ciphertext_size - ct_written,
                             &final_ct_len, tag, tag_size, &tag_written);

    if( status!= PSA_SUCCESS){
        psa_aead_abort(&aead_op);
        goto cleanup;
    }
    if(tag_written != tag_size){
        goto cleanup;
    }
    if(final_ct_len != pt_len){
        goto cleanup;
    }


    //increment sequence number
    status = psa_hpke_incrementSeq(ctx);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

cleanup:
    mbedtls_platform_zeroize(nonce, nonce_len);
    return status;
}



psa_status_t psa_hpke_context_receiver_open(psa_hpke_params *params,
                                                psa_hpke_context_t *ctx,
                                                unsigned char *aad, size_t aad_len,
                                                unsigned char *tag,  size_t tag_len,
                                                unsigned char *ciphertext, size_t ciphertext_size,
                                                unsigned char *pt, size_t pt_size)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (pt_size < ciphertext_size - tag_len) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if (tag_len != params->PSA_HPKE_AEAD_NT) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if (params->PSA_HPKE_AEAD_NN > PSA_HPKE_MAX_AEAD_NN) {
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }  

    //generating fresh nonce
    size_t nonce_len = params->PSA_HPKE_AEAD_NN;
    unsigned char nonce[PSA_HPKE_MAX_AEAD_NN];
    status = psa_hpke_computeNonce(params,ctx, nonce);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }


    //decrypt using the PSA AEAD API
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    status = psa_aead_decrypt_setup(&aead_op, ctx->aead_key_id, params->PSA_HPKE_AEAD_ALGO);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    status = psa_aead_set_nonce(&aead_op, nonce, nonce_len);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    status = psa_aead_update_ad(&aead_op, aad, aad_len);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    size_t pt_written = 0;
    status = psa_aead_update(&aead_op, ciphertext, ciphertext_size, pt, pt_size, &pt_written);
    if (status != PSA_SUCCESS) { 
        psa_aead_abort(&aead_op);
        goto cleanup; 
    }
    size_t out_verify = 0;
    status = psa_aead_verify(&aead_op, pt + pt_written, pt_size - pt_written,
                             &out_verify, tag, tag_len);
    if (status != PSA_SUCCESS) {
        status=PSA_HPKE_ERR_OPEN_FAILED;
        psa_aead_abort(&aead_op);
        goto cleanup;
    }
    if((pt_written + out_verify) != (ciphertext_size)){
        status= PSA_HPKE_ERR_OPEN_FAILED;
        psa_aead_abort(&aead_op);
        goto cleanup;
    }

    //increment sequence number
    status = psa_hpke_incrementSeq(ctx);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

cleanup:
    mbedtls_platform_zeroize(nonce, nonce_len);
    return status;
}

//KDF Functions

//Checked
psa_status_t  psa_hpke_encap(psa_hpke_params *params,
                                 unsigned char *pubkey_bytes_R, 
                                 unsigned char *enc,
                                 unsigned char *shared_secret)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (shared_secret == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(pubkey_bytes_R == NULL){
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(enc == NULL){
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(params->PSA_HPKE_KEM_NDH > PSA_HPKE_MAX_KEM_NDH) {
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    if(params->PSA_HPKE_KEM_NPK > PSA_HPKE_MAX_KEM_NPK) {
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    
    psa_key_attributes_t attr_R = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id_pub_R = PSA_KEY_ID_NULL;
    psa_key_attributes_t attr_E = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id_E = PSA_KEY_ID_NULL;

    unsigned char dh[PSA_HPKE_MAX_KEM_NDH];
    size_t kem_context_len = params->PSA_HPKE_KEM_NPK*2;
    unsigned char kem_context[PSA_HPKE_MAX_KEM_NPK*2];
    unsigned char pkRm[PSA_HPKE_MAX_KEM_NPK];
    unsigned char all_zeros[PSA_HPKE_MAX_KEM_NSECRET] = { 0 }; 


    psa_set_key_type(&attr_E, params->PSA_HPKE_KEM_KEY_TYPE);
    psa_set_key_algorithm(&attr_E, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr_E, PSA_KEY_USAGE_DERIVE);

    status = psa_hpke_kem_generateKeyPair(params, &key_id_E, &attr_E);
    if (status != PSA_SUCCESS) {
        return status;
    }
    psa_reset_key_attributes(&attr_E);

    psa_set_key_type(&attr_R, PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(params->PSA_HPKE_KEM_KEY_TYPE));
    psa_set_key_algorithm(&attr_R, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr_R, PSA_KEY_USAGE_DERIVE);

    //defense in depth: validate the public key
    status = psa_import_key(&attr_R, pubkey_bytes_R, (size_t) params->PSA_HPKE_KEM_NPK, &key_id_pub_R);
    if (status != PSA_SUCCESS) {
        status=  PSA_HPKE_ERR_DESERIALIZATION_FAILURE;
        goto cleanup;
    }


    //Deriving the diffi-hellman shared secret, labled "dh" as by the IETF HPKE standard algorithm
    size_t olen=0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                    key_id_E,
                                    pubkey_bytes_R,
                                    params->PSA_HPKE_KEM_NPK,
                                    dh,
                                    params->PSA_HPKE_KEM_NDH,
                                    &olen);
    if(status!=PSA_SUCCESS || olen != params->PSA_HPKE_KEM_NDH){
        status=PSA_HPKE_ENCAPSULATION_FAILURE;
        psa_destroy_key(key_id_E);
        psa_destroy_key(key_id_pub_R);
        mbedtls_platform_zeroize(dh, params->PSA_HPKE_KEM_NDH);
        goto cleanup;
    }

    //serializing pk_E and storing it in the buffer enc as by the IETF standard algorithm
    status = psa_hpke_serializePublicKey(params, key_id_E, enc);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }


    //pkRm is pubkey_bytes_R already serialized - copy directly
    memcpy(pkRm, pubkey_bytes_R, params->PSA_HPKE_KEM_NPK);

    //build kem_context
    size_t offset = 0;
    memcpy(kem_context, enc, params->PSA_HPKE_KEM_NPK);
    offset += params->PSA_HPKE_KEM_NPK;
    memcpy(kem_context + offset, pkRm, params->PSA_HPKE_KEM_NPK);

    //create HPKE shared secret via extract and exand of KDF
    status = psa_hpke_extract_and_expand(params, dh, params->PSA_HPKE_KEM_NDH,
                                             kem_context, kem_context_len,
                                             shared_secret, params->PSA_HPKE_KEM_NSECRET);
    if (status != PSA_SUCCESS) {
        status= PSA_HPKE_ENCAPSULATION_FAILURE;
        goto cleanup;
    }

    //verify shared secret, ensure that it is not all zeros
    if (memcmp(shared_secret, all_zeros, params->PSA_HPKE_KEM_NSECRET) == 0) {
        status = PSA_HPKE_ENCAPSULATION_FAILURE;
        goto cleanup;
    }


cleanup:
    psa_destroy_key(key_id_E);
    psa_destroy_key(key_id_pub_R);
    mbedtls_platform_zeroize(dh, params->PSA_HPKE_KEM_NDH);
    mbedtls_platform_zeroize(kem_context, kem_context_len);
    return status;
}

//Checked
psa_status_t  psa_hpke_encap_with_senderKeys(psa_hpke_params *params,
                                unsigned char *pubkey_bytes_R,
                                 unsigned char *enc,
                                 unsigned char *shared_secret, 
                                psa_key_id_t key_id_E)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (shared_secret == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(pubkey_bytes_R == NULL){
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(enc == NULL){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    if(params->PSA_HPKE_KEM_NDH > PSA_HPKE_MAX_KEM_NDH){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    if(params->PSA_HPKE_KEM_NPK > PSA_HPKE_MAX_KEM_NPK){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    size_t kem_context_len = params->PSA_HPKE_KEM_NPK*2;
    if(kem_context_len > PSA_HPKE_MAX_KEM_CONTEXT_LEN){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    

    unsigned char dh[PSA_HPKE_MAX_KEM_NDH];
    unsigned char kem_context[PSA_HPKE_MAX_KEM_NPK*2];
    unsigned char all_zeros[PSA_HPKE_MAX_KEM_NSECRET] = { 0 }; 

    
    //Deriving the diffi-hellman shared secret, labled "dh" as by the IETF HPKE standard algorithm
    size_t olen=0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                    key_id_E,
                                    pubkey_bytes_R,
                                    params->PSA_HPKE_KEM_NPK,
                                    dh,
                                    params->PSA_HPKE_KEM_NDH,
                                    &olen);
    if(status!=PSA_SUCCESS || olen != params->PSA_HPKE_KEM_NDH){
        status=PSA_HPKE_ENCAPSULATION_FAILURE;
        mbedtls_platform_zeroize(dh, params->PSA_HPKE_KEM_NDH);
        goto cleanup;
    }

    //serializing pk_E and storing it in the buffer enc as by the IETF standard algorithm
    status = psa_hpke_serializePublicKey(params, key_id_E, enc);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }


    //build kem_context
    size_t offset = 0;
    memcpy(kem_context, enc, params->PSA_HPKE_KEM_NPK);
    offset += params->PSA_HPKE_KEM_NPK;
    memcpy(kem_context + offset, pubkey_bytes_R, params->PSA_HPKE_KEM_NPK);

    //create HPKE shared secret via extract and exand of KDF
    status = psa_hpke_extract_and_expand(params, dh, params->PSA_HPKE_KEM_NDH,
                                             kem_context, kem_context_len,
                                             shared_secret, params->PSA_HPKE_KEM_NSECRET);
    if (status != PSA_SUCCESS) {
        status=PSA_HPKE_ENCAPSULATION_FAILURE;
        goto cleanup;
    }

    //verify shared secret, ensure that it is not all zeros
    if (memcmp(shared_secret, all_zeros, params->PSA_HPKE_KEM_NSECRET) == 0) {
        status = PSA_HPKE_ENCAPSULATION_FAILURE;
        goto cleanup;
    }


cleanup:
    mbedtls_platform_zeroize(dh, params->PSA_HPKE_KEM_NDH);
    mbedtls_platform_zeroize(kem_context, kem_context_len);
    return status;
}


//Checked
psa_status_t psa_hpke_decap(psa_hpke_params *params,
                                unsigned char *enc,
                                psa_key_id_t *key_id_R,
                                unsigned char *shared_secret)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
   
    if(enc == NULL || key_id_R == NULL || shared_secret == NULL){
        return PSA_HPKE_INVALID_ARGUMENT;
    }
   
    if(params->PSA_HPKE_KEM_NDH > PSA_HPKE_MAX_KEM_NDH){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    if(params->PSA_HPKE_KEM_NPK > PSA_HPKE_MAX_KEM_NPK){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }
    size_t kem_context_len = params->PSA_HPKE_KEM_NPK*2;
    if(kem_context_len > PSA_HPKE_MAX_KEM_CONTEXT_LEN){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }

    unsigned char dh[PSA_HPKE_MAX_KEM_NDH];
    unsigned char pkRm[PSA_HPKE_MAX_KEM_NPK];
    unsigned char kem_context[PSA_HPKE_MAX_KEM_CONTEXT_LEN];
    unsigned char all_zeros[PSA_HPKE_MAX_KEM_NSECRET] = { 0 }; // maximum size of NSECRET is 64


    psa_key_id_t key_id_pub_E = PSA_KEY_ID_NULL;
    psa_key_attributes_t attr_E = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr_E, params->PSA_HPKE_KEM_KEY_TYPE);
    psa_set_key_algorithm(&attr_E, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr_E, PSA_KEY_USAGE_DERIVE);


    //defense in depth: validate the public key
    status = psa_import_key(&attr_E, enc, (size_t) params->PSA_HPKE_KEM_NPK, &key_id_pub_E);
    psa_destroy_key(key_id_pub_E); 
    if (status != PSA_SUCCESS) {
        status=  PSA_HPKE_ERR_DESERIALIZATION_FAILURE;
        goto cleanup;
    }

    //Deriving the diffi-hellman shared secret, labled "dh" as by the IETF HPKE standard algorithm
    // key_id_pub_E was validated by psa_hpke_deserializePublicKey above
    size_t olen=0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                    *key_id_R,
                                    enc,
                                    params->PSA_HPKE_KEM_NPK,
                                    dh,
                                    params->PSA_HPKE_KEM_NDH,
                                    &olen);
    if(status!=PSA_SUCCESS || olen != params->PSA_HPKE_KEM_NDH){
        status=PSA_HPKE_ENCAPSULATION_FAILURE;
        goto cleanup;
    }


    //serializing pk_R and storing it in the buffer pkRm
    status = psa_hpke_serializePublicKey(params, *key_id_R, pkRm);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    //create kem_context
    size_t offset = 0;
    memcpy(kem_context, enc, params->PSA_HPKE_KEM_NPK);
    offset += params->PSA_HPKE_KEM_NPK;
    memcpy(kem_context + offset, pkRm, params->PSA_HPKE_KEM_NPK);

    //create shared_secret by extract and expand KDF
    status = psa_hpke_extract_and_expand(params, dh, params->PSA_HPKE_KEM_NDH,
                                             kem_context, kem_context_len,
                                             shared_secret, params->PSA_HPKE_KEM_NSECRET);
    if (status != PSA_SUCCESS) {
        status=PSA_HPKE_DECAPSULATION_FAILURE;
         mbedtls_platform_zeroize(pkRm, params->PSA_HPKE_KEM_NPK);
   
        goto cleanup;
    }

    //verify shared secret, ensure that it is not all zeros
    if (memcmp(shared_secret, all_zeros, params->PSA_HPKE_KEM_NSECRET) == 0) {
        status = PSA_HPKE_DECAPSULATION_FAILURE;
        mbedtls_platform_zeroize(pkRm, params->PSA_HPKE_KEM_NPK);
        goto cleanup;
    }

cleanup:
    psa_destroy_key(key_id_pub_E);
    mbedtls_platform_zeroize(dh, params->PSA_HPKE_KEM_NDH);
    mbedtls_platform_zeroize(kem_context, kem_context_len);
    return status;

}

//Checked
psa_status_t psa_hpke_hkdf_labeledExtract(psa_hpke_params *params,
                                                    const unsigned char *salt, 
                                                    size_t salt_len,
                                                     const unsigned char *label, 
                                                     size_t label_len,
                                                     const unsigned char *ikm, 
                                                     size_t ikm_len,
                                                     uint8_t is_KEM,
                                                     unsigned char *prk, 
                                                     size_t prk_len)
{

    psa_status_t status =PSA_ERROR_CORRUPTION_DETECTED;

    if (label == NULL|| prk == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(ikm == NULL && ikm_len >0){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    // Build suite_id
    unsigned char suite_id[10];
    size_t suite_id_len = 0;
    psa_hpke_get_suite_id(params, is_KEM, &suite_id_len, suite_id);

    // Calculate labeled_ikm length: "HPKE-v1" + suite_id + label + ikm
    const unsigned char version_prefix[] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };
    size_t version_len = sizeof(version_prefix); // strlen("HPKE-v1")
    size_t labeled_ikm_len = version_len + suite_id_len + label_len + ikm_len;

    // Allocate memory for labeled_ikm
    unsigned char *labeled_ikm = mbedtls_calloc(labeled_ikm_len, 1);
    if (labeled_ikm == NULL) {
        return PSA_HPKE_INSUFFICIENT_MEMORY;
    }

    size_t offset = 0;
    // Build labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
    memcpy(labeled_ikm + offset, version_prefix, version_len);
    offset += version_len;
    memcpy(labeled_ikm + offset, suite_id, suite_id_len);
    offset += suite_id_len;
    if (label_len > 0) {
        memcpy(labeled_ikm + offset, label, label_len);
        offset += label_len;
    }
    if (ikm_len > 0) {
        memcpy(labeled_ikm + offset, ikm, ikm_len);
    }

    //Calls HKDF implementation of library

    size_t capacity;
    psa_algorithm_t hkdf_alg;

    if(is_KEM){
        capacity= params->PSA_HPKE_KEM_KDF_NH;
        if(!PSA_ALG_IS_HASH(params->PSA_HPKE_KEM_KDF)){
            status=PSA_HPKE_INVALID_ARGUMENT;
            goto cleanup;
        }
        hkdf_alg=PSA_ALG_HKDF_EXTRACT(params->PSA_HPKE_KEM_KDF);

    }else{
        capacity= params->PSA_HPKE_KDF_NH;
        if(!PSA_ALG_IS_HASH(params->PSA_HPKE_KDF)){
            status=PSA_HPKE_INVALID_ARGUMENT;
            goto cleanup;
        }
        hkdf_alg=PSA_ALG_HKDF_EXTRACT(params->PSA_HPKE_KDF);
    }

    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&operation,hkdf_alg );
    if( status!=PSA_SUCCESS){
        goto cleanup;
    }
    status=psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len );
    if( status!=PSA_SUCCESS){

        psa_key_derivation_abort(&operation);
        goto cleanup;
    }    

    status=psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SECRET, labeled_ikm, labeled_ikm_len );
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }    

    status= psa_key_derivation_set_capacity(&operation, capacity);
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }

    status= psa_key_derivation_output_bytes(&operation,prk, prk_len);
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }

cleanup:
    mbedtls_zeroize_and_free(labeled_ikm, labeled_ikm_len);
    return status;
}




//Checked
int psa_hpke_hkdf_labeledExpand(psa_hpke_params *params,
                                                    const unsigned char *prk, size_t prk_len,
                                                    const unsigned char *label, size_t label_len,
                                                    const unsigned char *info, size_t info_len,
                                                    uint8_t is_KEM,
                                                    unsigned char *okm, uint16_t okm_len)
{

    int status =PSA_ERROR_CORRUPTION_DETECTED;


    if (prk == NULL || label == NULL || okm == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if( info == NULL && info_len >0){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    size_t l_len = 2;
    unsigned char l_i2osp[2];
    uint8_t *L_array = (uint8_t *) &okm_len;
    l_i2osp[0] = L_array[1];
    l_i2osp[1] = L_array[0];

    // Calculate labeled_ikm length: "HPKE-v1" + suite_id + label + ikm
    const unsigned char version_prefix[] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };
    size_t version_len = 7; // strlen("HPKE-v1")

    // Build suite_id
    unsigned char suite_id[10];
    size_t suite_id_len = 0;
    psa_hpke_get_suite_id(params,is_KEM, &suite_id_len, suite_id);

    // Allocate memory for labeled_info
    size_t labeled_info_size = l_len+version_len + suite_id_len + label_len + info_len;
    unsigned char *labeled_info=mbedtls_calloc(labeled_info_size, 1);
    if (labeled_info == NULL) {
        return PSA_HPKE_INSUFFICIENT_MEMORY;
    }

    size_t offset = 0;
    memcpy(labeled_info + offset, l_i2osp, l_len);
    offset += l_len;
    memcpy(labeled_info + offset, version_prefix, version_len);
    offset += version_len;
    memcpy(labeled_info + offset, suite_id, suite_id_len);
    offset += suite_id_len;
    memcpy(labeled_info + offset, label, label_len);
    offset += label_len;
    memcpy(labeled_info + offset, info, info_len);

    //Calls HKDF implementation of library
    size_t capacity;
    psa_algorithm_t hkdf_alg;

    if(is_KEM){
        capacity= params->PSA_HPKE_KEM_KDF_NH;
        if(!PSA_ALG_IS_HASH(params->PSA_HPKE_KEM_KDF)){
            status=PSA_HPKE_INVALID_ARGUMENT;
            goto cleanup;
        }
        hkdf_alg=PSA_ALG_HKDF_EXPAND(params->PSA_HPKE_KEM_KDF);

    }else{
        capacity= params->PSA_HPKE_KDF_NH;
        if(!PSA_ALG_IS_HASH(params->PSA_HPKE_KDF)){
            status=PSA_HPKE_INVALID_ARGUMENT;
            goto cleanup;
        }
        hkdf_alg=PSA_ALG_HKDF_EXPAND(params->PSA_HPKE_KDF);
    }

    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&operation,hkdf_alg );
    if( status!=PSA_SUCCESS){
        goto cleanup;
    }

    status=psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SECRET, prk, prk_len );
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }    


    status=psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_INFO, labeled_info, labeled_info_size );
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }    


    status= psa_key_derivation_set_capacity(&operation, capacity);
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }

    status= psa_key_derivation_output_bytes(&operation,okm, okm_len);
    if( status!=PSA_SUCCESS){
        psa_key_derivation_abort(&operation);
        goto cleanup;
    }
    
    cleanup:
    mbedtls_zeroize_and_free(labeled_info, labeled_info_size);
    return status;
}


//Checked 
int psa_hpke_extract_and_expand(psa_hpke_params *params, 
                                            const unsigned char *ikm,
                                             size_t ikm_len,
                                             const unsigned char *info,
                                             size_t info_len,
                                             unsigned char *shared_secret,
                                             uint16_t shared_secret_size)
{
    int status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t is_KEM = 1;
    if (shared_secret_size != params->PSA_HPKE_KEM_NSECRET) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    size_t eae_prk_len = PSA_HASH_LENGTH(params->PSA_HPKE_KEM_KDF);
    if (eae_prk_len != params->PSA_HPKE_KEM_KDF_NH) {
        return PSA_HPKE_SIZE_MISMATCH;
    }
    unsigned char eae_prk[PSA_HPKE_MAX_KDF_NH];

    //labled extract without salt, label "eae_prk"
    const unsigned char *salt = NULL;
    size_t salt_len = 0;
    const unsigned char label[] = { 'e', 'a', 'e', '_', 'p', 'r', 'k' };
    size_t label_len = sizeof(label);
    status = psa_hpke_hkdf_labeledExtract(params, salt,
                                                    salt_len,
                                                    label,
                                                    label_len,
                                                    ikm,
                                                    ikm_len,
                                                    is_KEM,
                                                    eae_prk,
                                                    eae_prk_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    const unsigned char label_expand[] = { 's', 'h', 'a', 'r', 'e', 'd', '_', 's', 'e', 'c', 'r',
                                           'e', 't' };
    size_t label_expand_len = sizeof(label_expand);
    status = psa_hpke_hkdf_labeledExpand(params, eae_prk,
                                                    eae_prk_len,
                                                    label_expand,
                                                    label_expand_len,
                                                    info,
                                                    info_len,
                                                    is_KEM,
                                                    shared_secret,
                                                    shared_secret_size);
    mbedtls_platform_zeroize(eae_prk, eae_prk_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return PSA_SUCCESS;
}



//Utility functions

int psa_hpke_computeNonce(psa_hpke_params *params, psa_hpke_context_t *ctx,  unsigned char *nonce)
{

    if(params->PSA_HPKE_AEAD_NN > PSA_HPKE_MAX_AEAD_NN){
        return PSA_HPKE_ERR_NOT_SUPPORTED;
    }   
    unsigned char seq_bytes[PSA_HPKE_MAX_AEAD_NN];
    int status = PSA_ERROR_CORRUPTION_DETECTED;
    status = i2osp_pkcs1_V22(&(ctx->sequence_number), params->PSA_HPKE_AEAD_NN, seq_bytes);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(seq_bytes, params->PSA_HPKE_AEAD_NN);
        return status;
    }

    unsigned char *base_nonce = ctx->base_nonce;
    for (size_t i = 0; i < params->PSA_HPKE_AEAD_NN; i++) {
        nonce[i] = seq_bytes[i]^ base_nonce[i];
    }
    mbedtls_platform_zeroize(seq_bytes, params->PSA_HPKE_AEAD_NN);
    return PSA_SUCCESS;
}


int psa_hpke_incrementSeq(psa_hpke_context_t *ctx)
{
    int comp = mbedtls_mpi_cmp_mpi(&ctx->sequence_number, &ctx->max_value);
    if(comp>=0){
        return PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED;
    }
    mbedtls_mpi temp;
    mbedtls_mpi_init(&temp);
    mbedtls_mpi_copy(&temp, &ctx->sequence_number);
    mbedtls_mpi_add_int(&ctx->sequence_number, &temp, 1);
    mbedtls_mpi_free(&temp);

    return PSA_SUCCESS;
}



int psa_hpke_context_export(psa_hpke_params *params, 
                                        psa_hpke_context_t *ctx,
                                         unsigned char *exporter_context,
                                         size_t exporter_context_len,
                                         unsigned char *export,
                                         uint32_t export_size)
{

    if(export_size > params->PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT ){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    const unsigned char label_exporter_secret[] = { 's', 'e', 'c' };
    uint8_t is_KEM = 0;
    int status = PSA_ERROR_CORRUPTION_DETECTED;
    status= psa_hpke_hkdf_labeledExpand(params, 
                                                ctx->exporter_secret, params->PSA_HPKE_KDF_NH,
                                                label_exporter_secret,3,
                                                exporter_context,exporter_context_len,
                                                is_KEM,
                                                export,
                                                export_size);

    return status;

}


//Checked
int psa_hpke_serializePublicKey(psa_hpke_params *params,
                                             psa_key_id_t key_id,
                                             unsigned char *pubkey_bytes_R)
{
    size_t olen_pkRm;
    int status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_export_public_key(key_id,
                                 pubkey_bytes_R,
                                 (size_t) params->PSA_HPKE_KEM_NPK,
                                 &olen_pkRm);

    if (status != PSA_SUCCESS) {
        return status;
    }
    if (olen_pkRm != params->PSA_HPKE_KEM_NPK) {
        return PSA_HPKE_SIZE_MISMATCH;
    }
    return PSA_SUCCESS;
}


//Checked
int psa_hpke_deserializePublicKey(psa_hpke_params *params, 
                                            const unsigned char *pubkey_bytes_R,
                                            size_t pubkey_bytes_R_len,
                                            psa_key_attributes_t *attr,
                                            psa_key_id_t *key_id)
{
    int status = PSA_ERROR_CORRUPTION_DETECTED;
    if (key_id == NULL || attr == NULL || pubkey_bytes_R == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(pubkey_bytes_R_len != params->PSA_HPKE_KEM_NPK){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    //Verifies keys internally
    status = psa_import_key(attr,  pubkey_bytes_R, (size_t) params->PSA_HPKE_KEM_NPK, key_id);

    if (status != PSA_SUCCESS) {
        return status;
    }
    return PSA_SUCCESS;
}



//Checked
int psa_hpke_serializePrivateKey(psa_hpke_params *params, 
                                psa_key_id_t key_id,
                                unsigned char *private_key_bytes)
{
    if (key_id == 0 || private_key_bytes == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    size_t olen;
    int status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_export_key(key_id,
                                 private_key_bytes,
                                (size_t) params->PSA_HPKE_KEM_NSK,
                                 &olen);

    if (status != PSA_SUCCESS) {
        return status;
    }
    if (olen != params->PSA_HPKE_KEM_NSK) {
        return PSA_HPKE_SIZE_MISMATCH;
    }
    return PSA_SUCCESS;
}

//Checked
int psa_hpke_deserializePrivateKey(psa_hpke_params *params, 
                                            const unsigned char *private_key_bytes,
                                            size_t private_key_bytes_len,
                                            psa_key_attributes_t *attr,
                                            psa_key_id_t *key_id)
{
    int status = PSA_ERROR_CORRUPTION_DETECTED;
    if (key_id == NULL || attr == NULL || private_key_bytes == NULL) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    if(private_key_bytes_len != params->PSA_HPKE_KEM_NSK){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    //Verifies keys internally
    status = psa_import_key(attr, 
        private_key_bytes, 
        (size_t) params->PSA_HPKE_KEM_NSK, 
        key_id);

    if (status != PSA_SUCCESS) {
        return status;
    }
    return PSA_SUCCESS;
}


int i2osp_pkcs1_V22(mbedtls_mpi *x, size_t x_len, unsigned char *output)
{
    if (output == NULL){
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    if(x_len == 0) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }
    

    // Step 1: If x >= 256^xLen, output "integer too large" and stop
    // Check if x >= 256^xLen
    mbedtls_mpi max_value;
    mbedtls_mpi_init(&max_value);
    
    int status= PSA_ERROR_CORRUPTION_DETECTED;
    status= mbedtls_mpi_lset(&max_value, 256);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status=mbedtls_mpi_shift_l(&max_value, x_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    int result = mbedtls_mpi_cmp_mpi(x, &max_value);
    if(result!=-1){
        //this chatches an overflow
        status=PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED;
        goto cleanup;
    }

    // Step 2 & 3: Write x in its unique xLen-digit representation in base 256 and create the octet string
    status= mbedtls_mpi_write_binary(x, output, x_len); //big endian!
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    cleanup: 
    mbedtls_mpi_free(&max_value);
    return status;
}


int os2ip_pkcs1_V22(unsigned char *input, size_t input_length, mbedtls_mpi *output)
{
    if (input == NULL || input_length == 0 || output == NULL || input_length < 8) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    int status= PSA_ERROR_CORRUPTION_DETECTED;
    status= mbedtls_mpi_lset(output, 0);
    if(status != PSA_SUCCESS) {
        return status;
    }
   status = mbedtls_mpi_read_binary(output, input, input_length);
   if(status != PSA_SUCCESS) {
       return status;
   }    
    return PSA_SUCCESS;
}


//Checked
void psa_hpke_get_suite_id(psa_hpke_params *params, uint8_t is_KEM, size_t *o_len, unsigned char *suite_id)
{

    size_t offset = 0;

    if (is_KEM == 1) {
        unsigned char hpke_prefix[] = { 'K', 'E', 'M', };
        size_t hpke_prefix_len = 3;

        memcpy(suite_id, hpke_prefix, hpke_prefix_len);
        offset += hpke_prefix_len;
        suite_id[offset] = (params->PSA_HPKE_KEM_ID >> 8) & 0xFF;
        suite_id[offset + 1] = params->PSA_HPKE_KEM_ID & 0xFF;
        *o_len = hpke_prefix_len+2; //is 5 for DHKEM as expected

    } else {
        unsigned char hpke_prefix[] = { 'H', 'P', 'K', 'E', };
        size_t hpke_prefix_len = 4;

        memcpy(suite_id, hpke_prefix, hpke_prefix_len);
        offset += hpke_prefix_len;
        suite_id[offset] = (params->PSA_HPKE_KEM_ID >> 8) & 0xFF;
        suite_id[offset + 1] = params->PSA_HPKE_KEM_ID & 0xFF;
        offset += 2;
        suite_id[offset] = (params->PSA_HPKE_KDF_ID >> 8) & 0xFF;
        suite_id[offset + 1] = params->PSA_HPKE_KDF_ID & 0xFF;
        offset += 2;
        suite_id[offset] = (params->PSA_HPKE_AEAD_ID >> 8) & 0xFF;
        suite_id[offset + 1] = params->PSA_HPKE_AEAD_ID & 0xFF;

        *o_len = hpke_prefix_len+3*2; //is 10 as expected for remainder of HPKE

    }
}

/*int clamping_X25519_PrivateKey(unsigned char *private_key_bytes, size_t private_key_bytes_len)
{
    if (private_key_bytes == NULL || private_key_bytes_len != 32) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    // Clamping the private key as per RFC 7748
    private_key_bytes[0] &= 248;  
    private_key_bytes[31] &= 127;  
    private_key_bytes[31] |= 64;  

    return 0;
}*/

/*int clamping_X448_PrivateKey(unsigned char *private_key_bytes, size_t private_key_bytes_len)
{
    if (private_key_bytes == NULL || private_key_bytes_len != 56) {
        return PSA_HPKE_INVALID_ARGUMENT;
    }

    // Clamping the private key as per RFC 7748
    private_key_bytes[0] &= 252;   // Clear the 3 least significant bits
    private_key_bytes[55] |= 128;  // Clear the most significant bit

    return 0;
}*/


#endif

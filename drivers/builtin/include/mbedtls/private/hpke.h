/**
 * \file hpke.h
 *
 * \brief   This file contains HPKE definitions and functions.
 *
 *          The Hybrid Public Key Encryption (HPKE) specifies a RFC 9180 compliant
 *          cryptographic algorithm that can be used to protect electronic
 *          data.
 *          Supports HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
 *          See https://datatracker.ietf.org/doc/rfc9180/ . 
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_MBEDTLS_PRIVATE_HPKE_H
#define TF_PSA_CRYPTO_MBEDTLS_PRIVATE_HPKE_H


#include "mbedtls/private_access.h"
#include "mbedtls/private/error_common.h"
#include "mbedtls/private/gcm.h"
#include "bignum_internal.h"
#include "psa_crypto_ecp.h"


#define PSA_HPKE_MODE_BASE 0x00
#define PSA_HPKE_MODE_PSK 0x01
#define PSA_HPKE_MODE_AUT 0x02
#define PSA_HPKE_MODE_AUTH_PSK 0x03

/** The requested mode or algorithm is not supported. */
#define PSA_HPKE_ERR_NOT_SUPPORTED -0x5301
/** Validation of a public or private key failed. */
#define PSA_HPKE_ERR_IMPORT_OR_VALIDATION_ERROR -0x5304
/** Deserialization of a key failed. */
#define PSA_HPKE_ERR_DESERIALIZATION_FAILURE -0x5302
/** Derivation of a keypair failed for DHKEM Curve P-256, P-384, or P-521. */
#define PSA_HPKE_DERIVE_KEYPAIR_FAILURE -0x5308
/** Opening a sealed message failed. */
#define PSA_HPKE_ERR_OPEN_FAILED -0x5303
/**  A key could not be encapsulated.*/
#define PSA_HPKE_ENCAPSULATION_FAILURE -0x5304
/** A key could not be decapsulated. */
#define PSA_HPKE_DECAPSULATION_FAILURE -0x5305
/** Insufficient memory to complete the operation. */
#define PSA_HPKE_INSUFFICIENT_MEMORY -0x5306
/** An invalid argument was provided. */
#define PSA_HPKE_INVALID_ARGUMENT PSA_ERROR_INVALID_ARGUMENT
/** The size of the output provided by a function did not match the expected size. */
#define PSA_HPKE_SIZE_MISMATCH -0x5309
/** The HPKE sequence number overflowed. */
#define PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED -0x530A


#define PSA_HPKE_MAX_KEM_NSECRET    64u
#define PSA_HPKE_MAX_KEM_NENC       133u
#define PSA_HPKE_MAX_KEM_NPK        133u
#define PSA_HPKE_MAX_KEM_NSK        66u

#define PSA_HPKE_MAX_KEM_NDH        66u
#define PSA_HPKE_MAX_KEM_KDF_NH     64u

#define PSA_HPKE_MAX_KDF_NH         64u
#define PSA_HPKE_MAX_AEAD_NK        32u
#define PSA_HPKE_MAX_AEAD_NN        12u
#define PSA_HPKE_MAX_AEAD_NT        16u

#define PSA_HPKE_MAX_KEY_SCHEDULE_CONTEXT_LEN       (2u * PSA_HPKE_MAX_KDF_NH + 1u)
#define PSA_HPKE_MAX_KEM_CONTEXT_LEN                (2u * PSA_HPKE_MAX_KEM_NPK) 
#define PSA_HPKE_MAX_LABELED_IKM_LEN_EXTRACT        (sizeof("HPKE-v1") - 1u + 10+ 11+ PSA_HPKE_MAX_KEM_NDH)
#define PSA_HPKE_MAX_LABELED_IKM_LEN_EXPAND         2+(sizeof("HPKE-v1") - 1u + 10+ 13+ )


/**
 * \brief   This struct contains the relevant HPKE parameters for the selected algorithm after if has been initalized.
 *          Values are taken from RFC 9180.
 *          Values are given in bytes. 
 */
typedef struct{
    uint8_t PSA_HPKE_MODE;
    uint16_t PSA_HPKE_KEM_ID;
    uint16_t PSA_HPKE_KDF_ID;
    uint16_t PSA_HPKE_AEAD_ID;
    psa_algorithm_t PSA_HPKE_KEM_KDF;// KDF used by the KEM, this can be different from the outer HPKE KDF 
    uint16_t PSA_HPKE_KEM_KDF_NH; 
    mbedtls_ecp_group_id PSA_HPKE_KEM_CURVE_ID; //the curve used in the DH of the KEM

    uint16_t PSA_HPKE_KEM_NSECRET; //The length of a KEM shared secret produced by this KEM in byte.   
    uint16_t PSA_HPKE_KEM_NENC; //The length of an encapsulated key produced by this KEM in byte.
    uint16_t PSA_HPKE_KEM_NPK; // The length of an encoded public key for this KEM in byte.
    uint16_t PSA_HPKE_KEM_NSK; //The length of an encoded private key for this KEM in byte.
    uint16_t PSA_HPKE_KEM_NDH; // The size of the Diffie-Hellman shared secret 
    psa_key_type_t PSA_HPKE_KEM_KEY_TYPE;
    psa_algorithm_t PSA_HPKE_KEM_KEY_ALG;
 
    psa_algorithm_t PSA_HPKE_KDF;
    uint16_t PSA_HPKE_KDF_NH; // Given in Table 3 of RFC.

    uint16_t PSA_HPKE_AEAD_NK;// Given in Table 5 of the RFC. In bytes.
    uint16_t PSA_HPKE_AEAD_NN;// Given in Table 5 of the RFC. In bytes.
    uint16_t PSA_HPKE_AEAD_NT;// Given in Table 5 of the RFC. In bytes.
    psa_key_type_t PSA_HPKE_AEAD_KEY_TYPE;
    psa_algorithm_t PSA_HPKE_AEAD_ALGO;

    size_t PSA_HPKE_INPUT_LIMITS_PSK; // Given in Table 4 of the RFC .  In bytes.
    size_t PSA_HPKE_INPUT_LIMITS_PSK_ID; //Given in Table 4 of the RFC. In bytes.
    size_t PSA_HPKE_INPUT_LIMITS_INFO;// Given in Table 4 of the RFC. In bytes.
    size_t PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT; // Given in Table 4 of the RFC. In bytes.
    size_t PSA_HPKE_INPUT_LIMITS_IKM; // Given in Table 4 of the RFC. In bytes.
    size_t PSA_HPKE_EXPORT_LEN; // Given in Table 4 of the RFC and depends on the selected KDF. In bytes.

} psa_hpke_params; 

//Valid algorithm combinations as per RFC.
enum PSA_HPKE_algo_id {
    PSA_HPKE_KEM32_SHA256_AES128GCM = 1,        //DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    PSA_HPKE_KEM32_SHA256_CHACHAPOLY1305 = 2,   //DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
    PSA_HPKE_KEM16_SHA256_AES128GCM = 3,        //DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    PSA_HPKE_KEM16_SHA512_AES128GCM = 4,        //DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
    PSA_HPKE_KEM16_SHA256_CHACHAPOLY1305 = 5,   //DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
    PSA_HPKE_KEM18_SHA512_AES256GCM= 6          //DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
};

enum PSA_HPKE_role_t {
    PSA_HPKE_SENDER=1,
    PSA_HPKE_RECEIVER=2
};

/**
 * \brief Context used by the HPKE algorithm to store secrets.
 */
typedef struct {
    enum PSA_HPKE_role_t role;

    //ignored because optional
    //char* psk;
    //char psk_id;

    //following are only known to the holder of the recipient private key, and the entity that used the KEM to generate shared_secret and enc.
    psa_key_id_t aead_key_id;
    unsigned char *base_nonce;
    mbedtls_mpi sequence_number;
    unsigned char *exporter_secret;
    mbedtls_mpi max_value;
    size_t base_nonce_len;
    size_t exporter_secret_len;

} psa_hpke_context_t;



/**
 * \brief Sets the correct parameters for a HPKE algorithm given by a PSA_HPKE_algo_id.
 * 
 * \param selected Selected HPKE algorithm
 * \param mode HPKE mode (only base mode is supported here)
 * \param psk pre-shared key (not yet supported in this implementation)
 * \param psk_len size of psk array
 * \param info preallocated output structure. When the function returns, this structure will contain the parameters for the selected algorithm 
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_ERR_NOT_SUPPORTED if selected algorithm is not supported. 
 */
psa_status_t psa_hpke_setup_parameters(enum PSA_HPKE_algo_id algo_id, uint8_t mode, char* psk, size_t psk_len, psa_hpke_params *params);



/**
 * \brief Sets the correct parameters for a  HPKE algorithm given by a set of identifiers for KEM, KDF and AEAD. See RFC 9180 for valid combinations.
 * 
 * \param selected Selected HPKE algorithm
 * \param mode HPKE mode (only base mode is supported here)
 * \param psk pre-shared key (not supported in this implementation)
 * \param info preallocated output structure. When the function returns, this structure will contain the parameters for the selected algorithm 
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_ERR_NOT_SUPPORTED if selected algorithm or mode is not supported.
 * \return #PSA_HPKE_INVALID_ARGUMENT if one of the provided algorithm identifiers is invalid.
 */
psa_status_t psa_hpke_setup_parameters_extended(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id, uint8_t mode, char* psk, size_t psk_len, psa_hpke_params *params);





/**
 * \brief Function to create the HPKE context and setting up the HPKE key schedule.
 *        This corresponds to the key schedule function in the RFC and follows the description of KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id).
 *        Preshared keys are not implemented at the moment.
 *
 * \param params HPKE parameters for selected algorithm
 * \param role Indicates whether the context is being created for a sender or a receiver
 * \param kem_shared_secret A KEM shared secret generated for this transaction
 * \param info Application-supplied information (optional; default value "").
 * \param info_size Size of info in bytes
 * \param ctx Pointer to the HPKE context to be initialized. Will contain key,base_nonce and exporter_secret for holder of recipient private key
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_ERR_NOT_SUPPORTED if selected mode is not supported.
 * \return #PSA_HPKE_INSUFFICIENT_MEMORY if memory allocation failed.
 * \return  Negative error code on other kinds of failure.
 */
psa_status_t psa_hpke_create_hpke_context(psa_hpke_params *params,
                                              enum PSA_HPKE_role_t role,
                                              unsigned char *kem_shared_secret,
                                              unsigned char *info,
                                              size_t info_size,
                                              psa_hpke_context_t *ctx);


/**
 * \brief Frees all allocated data associated with an HPKE context that has been initialized.
 *
 * \param ctx Context to be freed
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if ctx is NULL.
 */
psa_status_t psa_hpke_context_free(psa_hpke_context_t *ctx);

/**
 * \brief Sets up HPKE context for sender.
 *
 * \param params HPKE parameters for selected algorithm
 * \param pubkey_R keypair containing public key of receiver
 * \param info associated info, optional
 * \param info_size size of info
 * \param enc Preallocated output array of size PSA_HPKE_KEM_NPK
 * \param ctx pointer to uninitialized HPKE context for output
 * \return \c PSA_SUCCESS if successful.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_baseSetupSender(psa_hpke_params *params,
                                          unsigned char *pubkey_R,
                                          unsigned char *info,
                                          size_t info_size,
                                          unsigned char *enc,
                                          psa_hpke_context_t *ctx);


/**
 * \brief Setup HPKE context for receiver.
 *
 * \param params HPKE parameters for selected algorithm
 * \param enc byte array containing the serialized public key of the Sender pkE
 * \param key_id_R key id referencing the public and private key of the receiver
 * \param info associated information (optional)
 * \param info_size size of info
 * \param ctx pointer to uninitialized HPKE context for output
 * \return \c PSA_SUCCESS if successful.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_baseSetupReceiver(psa_hpke_params *params,
                                            unsigned char *enc,
                                            psa_key_id_t* key_id_R,
                                            unsigned char *info,
                                            size_t info_size,
                                            psa_hpke_context_t *ctx);


/**
 * \brief Sealing for HPKE for single message ("single shot" setup).
 *
 * \param params HPKE parameters for selected algorithm
 * \param pubkey_bytes_R public key of the recipient
 * \param info information to be used additionally by the KEM (optional)
 * \param info_size size of info
 * \param aad associated data
 * \param aad_len length of aad data
 * \param pt plaintext
 * \param pt_len length of pt data
 * \param enc preallocated output array of  size at least PSA_HPKE_KEM_NPK
 * \param tag preallocated output array for tag
 * \param tag_size size of tag array
 * \param ciphertext preallocated output array for ciphertext (it must be the same size as the plaintext)
 * \param ciphertext_size size of ciphertext array
 * \return \c PSA_SUCCESS if successful.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_seal_single_msg(psa_hpke_params *params,
                                          unsigned char *pubkey_bytes_R,
                                          unsigned char *info, size_t info_size,
                                          unsigned char *aad, size_t aad_len,
                                          unsigned char *pt,  size_t pt_len,
                                          unsigned char *enc, 
                                          unsigned char *tag, size_t tag_size,
                                          unsigned char *ciphertext, size_t ciphertext_size);

/**
 * \brief Opening a single HPKE message ("single shot" setup).
 *
 * \param params HPKE parameters for selected algorithm
 * \param enc byte array containing the serialized public key of the Sender pkE
 * \param key_id_R key id referencing the public and private key of the receiver
 * \param info associated information (optional)
 * \param info_len length of info data
 * \param aad length of associated data
 * \param aad_len length of aad data
 * \param tag authentication tag 
 * \param tag_len length of tag data
 * \param ciphertext ciphertext
 * \param ciphertext_size size of ciphertext 
 * \param pt preallocated array for output plaintext
 * \param pt_size size of pt array
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_ERR_OPEN_FAILED if decryption or authentication of message failed.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_open_single_msg(psa_hpke_params *params,
                                          unsigned char *enc,
                                          psa_key_id_t* key_id_R,
                                          unsigned char *info, size_t info_size,
                                          unsigned char *aad, size_t aad_len,
                                          unsigned char *tag,  size_t tag_len,
                                          unsigned char *ciphertext, size_t ciphertext_size,
                                          unsigned char *pt, size_t pt_size);


//AEAD functions
/**
 * \brief  This function implements a deterministic algorithm to derive a keypair from inital key material (ikm). 
 * The ikm must have at least PSA_HPKE_KEM_NSK bytes of entropy. 
 * Only X25519 and X448 supported at the moment.
 *
 * \param params HPKE parameters for selected algorithm
 * \param ikm should have at least PSA_HPKE_KEM_NSK bytes of entropy.
 * \param ikm_len length of ikm data
 * \param sk preallocated array for secret key
 * \param pk preallocated array for public key
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if ikm is NULL or keypair is NULL or ikm_len is too small or too large or ECP key can not be read. 
 * \return #PSA_HPKE_ERR_NOT_SUPPORTED if the selected KEM curve is not supported.
 * \return #PSA_HPKE_SIZE_MISMATCH if internal state regarding hash function is inconsistent.
 * \return #PSA_HPKE_DERIVE_KEYPAIR_FAILURE if keypair generation fails (not for X25519 and X448).
 * \return Another negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_kem_deriveKeyPair(psa_hpke_params *params,
                                            unsigned char *ikm,
                                            size_t ikm_len,
                                            psa_key_id_t *key_id,
                                            psa_key_attributes_t *attr);

/**
 * \brief This functions generates public key by genrating fresh, random initial key material and then calling psa_hpke_kem_deriveKeyPair.
 *
 * \param params HPKE parameters for selected algorithm
 * \param sk preallocated array for secret key
 * \param pk preallocated array for public key
 * \return \c PSA_SUCCESS if successful.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_kem_generateKeyPair( psa_hpke_params *params,
                                            psa_key_id_t *key_id,
                                            psa_key_attributes_t *attr);




/**
 * \brief   This function seal an plaintext for a given HPKE context and associated data (aad). 
 *          If successful, the ciphertext and authentication tag are written to the provided output buffers.
 *          It creates a fresh nonce every time.
 *
 * \param params HPKE parameters for selected algorithm
 * \param ctx Initialized mbedtls_gcm context that contains a symmetric key for AES-128-GCM
 * \param aad  associated data
 * \param aad_len  length of aad data
 * \param pt  input plaintext
 * \param pt_len  length of pt data
 * \param tag  preallocated array for authentication tag with size PSA_HPKE_AEAD_NT(output)
 * \param tag_size  size of tag array
 * \param ciphertext   preallocated array for ciphertext, size at least pt_len + PSA_HPKE_AEAD_NT (output)
 * \param ciphertext_size Size of ciphertext array, needs to be at least pt_len + PSA_HPKE_AEAD_NT
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if tag len is too small or ciphertext_size is too small.
 * \return #PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED if sequence number overflowes.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_context_sender_seal(psa_hpke_params *params,
                                              psa_hpke_context_t *ctx,
                                              unsigned char *aad, size_t aad_len,
                                              unsigned char *pt, size_t pt_len,
                                              unsigned char *tag, size_t tag_size,
                                              unsigned char *ciphertext, size_t ciphertext_size);

/**
 * \brief   This function opens a ciphertext for a given HPKE contex, associated data (aad), and authentication tag.
 *          IF successful, the plaintext is written to the provided output buffer. 
 *
 * \param params HPKE parameters for selected algorithm
 * \param ctx Initialized mbedtls_gcm context 
 * \param aad associated data
 * \param aad_len length of aad data
 * \param tag  preallocated array containing authentication tag
 * \param tag_length length of tag data
 * \param ciphertext preallocated array for ciphertext
 * \param ciphertext_size size of ciphertext
 * \param pt preallocated array for plaintext
 * \param pt_size size of pt array
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if length of pre-allocated pt is too small or tag_size is incorrect.
 * \return #PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED if sequence number overflowes.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_context_receiver_open(psa_hpke_params *params,
                                                psa_hpke_context_t *ctx,
                                                unsigned char *aad, size_t aad_len,
                                                unsigned char *tag,  size_t tag_size,
                                                unsigned char *ciphertext, size_t ciphertext_size,
                                                unsigned char *pt, size_t pt_len);


//KEM Functions
/**
 * \brief   This function generate an ephemeral, fixed-length symmetric key (the KEM's "shared secret") via a Diffie-Hellman key exchange and a encapsulation of that symmetric key using the public key of the receiver.
 *          The shared secret and the encapsulated key enc are written to the provided output buffers.
 * 
 * \param params HPKE parameters for selected algorithm
 * \param pubkey_bytes_R Public key of receiver as byte array
 * \param enc preallocated output array of size at least PSA_HPKE_KEM_NPK
 * \param shared_secret preallocated output array of size at least PSA_HPKE_KEM_NSECRET
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if enc or shared_secret is NULL.
 * \return #PSA_HPKE_ERR_VALIDATION_FAILURE if pubkey_R is invalid.
 * \return #PSA_HPKE_ENCAPSULATION_FAILURE on general errors.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_encap(psa_hpke_params *params,
                                 unsigned char *pubkey_bytes_R, 
                                 unsigned char *enc,
                                 unsigned char *shared_secret);


/**
 * \brief For TESTING PURPOSES ONLY. The sender's key (key_id_E) should be recomputed every time.
 * 
 * \param params HPKE parameters for selected algorithm
 * \param pubkey_bytes_R Public key of receiver as byte array
 * \param enc preallocated output array of size at least PSA_HPKE_KEM_NPK
 * \param shared_secret preallocated output array of size at least PSA_HPKE_KEM_NSECRET
 * \param key_id_E Key ID of the sender. Should be recomputed every time.
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if enc or shared_secret is NULL.
 * \return #PSA_HPKE_ERR_VALIDATION_FAILURE if pubkey_R is invalid.
 * \return #PSA_HPKE_ENCAPSULATION_FAILURE  on general errors.
 * \return Negative error code from subfunction on failure. 
 */
psa_status_t psa_hpke_encap_with_senderKeys(psa_hpke_params *params,
                                unsigned char *pubkey_bytes_R,
                                unsigned char *enc,
                                unsigned char *shared_secret,
                                psa_key_id_t key_id_E);



/**
 * \brief   Function to recover the ephemeral symmetric key (the KEM shared secret) from its encapsulated representation enc using the private key of the receiver.
 *          The shared secret is written to the provided output buffer.
 *
 * \param params HPKE parameters for selected algorithm
 * \param enc contains a serialized version of the senders public key pkE
 * \param key_id_R key identifier for the private key of the receiver of the HPKE message
 * \param shared_secret pre-allocated output array for shared secret of size PSA_HPKE_KEM_NSECRET
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_ERR_DESERIALIZATION_FAILURE if enc can not be deserialized.
 * \return #PSA_HPKE_ERR_VALIDATION_FAILURE if the deserialized public key is invalid.
 * \return #PSA_HPKE_DECAPSULATION_FAILURE on general errors.
 * \return Other negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_decap(psa_hpke_params *params,
                                unsigned char *enc,
                                psa_key_id_t *key_id_R,
                                unsigned char *shared_secret);



//KDF functions
/**
 * \brief   This function expands a pseudorandom key prk using a label and optional string ikm and returns pseudo random key prk.
 *          The label value greatly depends on the caller.  
 * 
 * \param params HPKE parameters for selected algorithm
 * \param salt Optional. If NULL, no salt is used.
 * \param salt_len length of salt data
 * \param label Label that will be used to extend the key ikm.
 * \param label_len length of label data
 * \param ikm input keying material.
 * \param ikm_len length of ikm data
 * \param is_KEM Indicates whether the function is called from the KEM context or the HPKE context.
 * \param prk Output. An array of size at least PSA_HPKE_KDF_(KEM)_NH
 * \param prk_len len of prk
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if ikm is NULL or label or prk is NULL.
 * \return #PSA_HPKE_SIZE_MISMATCH if output of hash function does not match expected size.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_hkdf_labeledExtract(psa_hpke_params *params,  
                                                    const unsigned char *salt, size_t salt_len,
                                                    const unsigned char *label, size_t label_len,
                                                    const unsigned char *ikm, size_t ikm_len,
                                                    uint8_t is_KEM,
                                                    unsigned char *prk,
                                                    size_t prk_len);

/**
 * \brief   This functions expands a pseudorandom key prk using a label and an optional string info.
 *          It proves okm_len bytes of output keying material which is written to the provided output buffer okm. 
 *          The label value greatly depends on the caller.
 *
 * \param params HPKE parameters for selected algorithm
 * \param prk Pseudorandom key
 * \param prk_len Length of prk data
 * \param label Label
 * \param label_len Length of label data
 * \param info Info string
 * \param info_len Length of info data
 * \param is_KEM Indicates whether the function is called from the KEM context or the HPKE context.
 * \param okm output keying material, preallocated array of size at least okm_len bytes
 * \param okm_len requested length of output keying material, provided by caller
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if prk is NULL or label or okm is NULL or info is NULL. 
 *          Also returned if okm_len is larger than the maximum allowed output length (255*Nh).
 */
psa_status_t psa_hpke_hkdf_labeledExpand(psa_hpke_params *params, 
                                                    const unsigned char *prk, size_t prk_len,
                                                    const unsigned char *label, size_t label_len,
                                                    const unsigned char *info, size_t info_len,
                                                    uint8_t is_KEM,
                                                    unsigned char *okm,
                                                    uint16_t okm_len);


/**
 * \brief   This function calles labed extract and labled expand to create a shared secret.
 *          Inital key material ikm and info string can be provided by the caller. 
 *          The info string is optional. 
 * 
 *          Referencing the pseudocode in the RFC 9180 on page 10:
 *              - "dh" corresponds to ikm and its length is ikm_len.
 *              - "KEM context" corresponds to "info" and "info_size".
 *              - "shared_secret" as a string is the label from which label_len is derived.
 *
 * \param params HPKE parameters for selected algorithm
 * \param ikm inital keying material
 * \param ikm_len length of ikm
 * \param info Info string (optional)
 * \param info_len length of info
 * \param shared_secret Is a pre-allocated buffer of size PSA_HPKE_KEM_NSECRET and will contain the returned results.
 * \param shared_secret_size Size of shared_secret buffer 
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if shared_secret_size is incorrect.
 * \return #PSA_HPKE_SIZE_MISMATCH if output length of hash function does not match expected size.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_extract_and_expand(psa_hpke_params *params, 
                                            const unsigned char *ikm,
                                             size_t ikm_len,
                                             const unsigned char *info,
                                             size_t info_len,
                                             unsigned char *shared_secret,
                                             uint16_t shared_secret_size);


//utility functions

/**
 * \brief   This function computes a new nonce based on the sequence number and the base nonce (both stored in the HPKE context).
 *          The new nonce is written to the provided output buffer.
 * \param params HPKE parameters for selected algorithm
 * \param ctx  initalized HPKE context
 * \param nonce preallocated array for returned nonce  
 * \return \c PSA_SUCCESS if successful.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_computeNonce(psa_hpke_params *params, psa_hpke_context_t *ctx, unsigned char *nonce);

/**
 * \brief Increments sequence number in the HPKE context by one and throw error if maximal value is reached.

 * \param ctx initalized HPKE context
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED if maximal value for sequence number is reached.
 */
psa_status_t psa_hpke_incrementSeq(psa_hpke_context_t *ctx);

/**
 * \brief   This function allows to export the context of an HPKE setup.
 *          The exporter context is an optional string that can be provided by the caller to bind the exported keying material to specific context information.
 *          The export is derived from the exporter secret and a key derivation function.
 *          The export size is given by the caller and should be at most PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT. 
 *          The exported keying material is written to the provided output buffer export.
 *       
 *
 * \param params HPKE parameters for selected algorithm
 * \param ctx initalized HPKE context
 * \param exporter_context context string provided by the caller
 * \param exporter_context_len length of exporter_context data
 * \param export  preallocated output array, should be at most PSA_HPKE_INPUT_LIMITS_EXPORT_CONTEXT
 * \param export_size size of export array
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if export_size is larger than maximum allowed output length.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_context_export(psa_hpke_params *params, 
                                        psa_hpke_context_t *ctx,
                                         unsigned char *exporter_context,
                                         size_t exporter_context_len,  unsigned char *export,
                                         uint32_t export_size);


/**
 * \brief   This function produces a byte string of length NPK encoding a public key. 
 *
 * \param params HPKE parameters for selected algorithm
 * \param key_id key_id of the public key to be serialized
 * \param pubkey_bytes_R output array of sufficient length, preallocated
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_SIZE_MISMATCH if length of serialized bytes does not match expected length.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_serializePublicKey(psa_hpke_params *params, 
                                            psa_key_id_t key_id,
                                            unsigned char *pubkey_bytes_R);

/**
 * \brief   This function parses a serialized public key to recover a public key from bytes.
 *          The public key will be imported and can be accessed via its key_id.  
 *          Keys are checked for their validity when being imported.
 *
 * \param params HPKE parameters for selected algorithm
 * \param pubkey_bytes_R input bytes
 * \param pubkey_bytes_R_len length of pubkey_bytes_R data
 * \param attr attributes for the imported public key
 * \param key_id key_id for the imported public key, used for future access to the key
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if keypair is NULL or pubkey_bytes_R is NULL or pubkey_bytes_R does not match expected length or if ECP curve can not be loaded or 
 * \returns #PSA_HPKE_ERR_DESERIALIZATION_FAILURE if public key is can not be parsed or set.
 * \returns #PSA_HPKE_ERR_VALIDATION_FAILURE if public key is invalid.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_deserializePublicKey(psa_hpke_params *params, 
                                                const unsigned char *pubkey_bytes_R,
                                                size_t pubkey_bytes_R_len,
                                                psa_key_attributes_t *attr,
                                                psa_key_id_t *key_id);



/**
 * \brief This function serializes the private key given by a key_id and writes it to the provided output buffer.
 *          The keys policy must allow PSA_KEY_USAGE_EXPORT.
 * 
 * \param params HPKE parameters for selected algorithm
 * \param key_id key_id of the private key to be serialized
 * \param private_key_bytes output array, preallocated
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if keypair is NULL or private_key_bytes is NULL.
 * \return #PSA_HPKE_SIZE_MISMATCH if length of serialized bytes does not match expected length.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_serializePrivateKey(psa_hpke_params *params, 
                                            psa_key_id_t key_id,
                                            unsigned char *private_key_bytes);

/**
 * \brief This function deserializes the private key from a byte array.
 *        
 * \param params HPKE parameters for selected algorithm
 * \param private_key_bytes array congtaining the private key bytes
 * \param private_key_bytes_len length of private_key_bytes data
 * \param attr attributes for the imported private key
 * \param key_id key_id for the imported private key, used for future access to the key
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if keypair is NULL or private_key_bytes is NULL or if private_key_bytes_len does not have the expected value.
 * \return #PSA_HPKE_ERR_DESERIALIZATION_FAILURE if private key can not be parsed or set.
 * \return #PSA_HPKE_ERR_VALIDATION_FAILURE if private key is invalid.
 * \return Negative error code from subfunction on failure.
 */
psa_status_t psa_hpke_deserializePrivateKey(psa_hpke_params *params,
                                                const unsigned char *private_key_bytes,
                                                size_t private_key_bytes_len,
                                                psa_key_attributes_t *attr,
                                                psa_key_id_t *key_id);

/**
 * \brief   This function converts a nonnegative integer to an octet string of a specified length.
 *          Following RFC 8017 PKCS #1 v2.2 specification.
 *
 * \param x      nonnegative integer to be converted
 * \param x_len   intended length of the resulting octet string
 * \param output initalized buffer to store the resulting octet string (must be at least xLen bytes, must be zero-initialized)
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if output is NULL or x_len is zero.
 * \return #PSA_HPKE_ERR_MESSAGE_LIMIT_REACHED if x >= 256^x_len
 * \return Negative error code from subfunction on failure, i.e. from the mbedtls_mpi submodule.
 */
psa_status_t i2osp_pkcs1_V22(mbedtls_mpi *x, size_t x_len, unsigned char *output);

/**
 *  \brief  This function converts a byte string x to a non-negative integer, as described in RFC 8017 , assuming big-endian byte order.
 *          Only handles input arrays of size <= 8 as output is 64 bit.
 * 
 * \param input      input byte string
 * \param input_length length of input data
 * \param output     resulting non-negative integer
 * \return \c PSA_SUCCESS if successful.
 * \return #PSA_HPKE_INVALID_ARGUMENT if input is NULL or input_length is zero or output is NULL or if input_length < 8.
 * \return Negative error code from subfunction on failure, i.e. from the mbedtls_mpi submodule.
 */
psa_status_t os2ip_pkcs1_V22(unsigned char *input, size_t input_length, mbedtls_mpi *output);


/**
 * \brief Helper function to set the correct suite_id for HPKE and the HPKE's KEM. 
 *
 * \param params HPKE parameters for selected algorithm
 * \param is_KEM Parameter signifying if the function is called from KEM context or a HPKE context.
 * \param o_len lenght of the content in suite_id after function returns
 * \param suite_id preallocated output array of size at least 13
 * \return 
 */
void psa_hpke_get_suite_id(psa_hpke_params *params, uint8_t is_KEM, size_t *o_len, unsigned char *suite_id);

#endif

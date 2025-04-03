## RNG removal

### Public functions no longer take a RNG callback

The `f_rng` and `p_rng` arguments have been removed from the LMS, LMOTS, PK, X509 and SSL modules. All calls to `f_rng` have then been replaced by a call to `psa_generate_random` and all software utilising these modules will now require a call to `psa_crypto_init` prior to calling them. 

### Changes in LMS

The following function calls have been changed in LMS:

```c
int mbedtls_lms_generate_private_key(mbedtls_lms_private_t *ctx, mbedtls_lms_algorithm_type_t type, mbedtls_lmots_algorithm_type_t otstype,
                                     int (*f_rng)(void *, unsigned char *, size_t), 
                                     void *p_rng, 
                                     const unsigned char *seed, size_t seed_size);
```

```c
int mbedtls_lms_sign(mbedtls_lms_private_t *ctx,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng, 
                     const unsigned char *msg, unsigned int msg_size, unsigned char *sig, size_t sig_size, size_t *sig_len);

to

```c
int mbedtls_lms_generate_private_key(mbedtls_lms_private_t *ctx, mbedtls_lms_algorithm_type_t type, mbedtls_lmots_algorithm_type_t otstype,
                                     const unsigned char *seed, size_t seed_size);
```

```c
int mbedtls_lms_sign(mbedtls_lms_private_t *ctx,
                     const unsigned char *msg, unsigned int msg_size, unsigned char *sig, size_t sig_size, size_t *sig_len);
```


### Changes in x509

The following function calls have been changed in x509:

```c
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
```

```c
int mbedtls_x509write_crt_pem(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
```

```c
int mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
```

```c
int mbedtls_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
```

to

```c
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size);
```

```c
int mbedtls_x509write_crt_pem(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size);
```

```c
int mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size);
```

```c
int mbedtls_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size);
```

### Changes in PK

The following function calls have been changed in PK:

```c
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), 
                                void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx);
```

```c
int mbedtls_pk_check_pair(const mbedtls_pk_context *pub, const mbedtls_pk_context *prv,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);
```

```c
int mbedtls_pk_decrypt(mbedtls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

```c
int mbedtls_pk_encrypt(mbedtls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

```c
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

```c
int mbedtls_pk_sign_ext(mbedtls_pk_type_t pk_type, mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);
```

```c
int mbedtls_pk_parse_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

```c
int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx, const char *path, const char *password,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

```c
typedef int (*mbedtls_pk_rsa_alt_sign_func)(void *ctx,
                                            int (*f_rng)(void *, unsigned char *, size_t),
                                            void *p_rng,
                                            mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash, unsigned char *sig);
```

to

```c
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, 
                                 mbedtls_pk_restart_ctx *rs_ctx);
```

```c
int mbedtls_pk_check_pair(const mbedtls_pk_context *pub, const mbedtls_pk_context *prv);
```

```c
int mbedtls_pk_decrypt(mbedtls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);
```

```c
int mbedtls_pk_encrypt(mbedtls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);
```

```c
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len);
```

```c
int mbedtls_pk_sign_ext(mbedtls_pk_type_t pk_type, mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len);
```

```c
int mbedtls_pk_parse_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen);
```

```c
int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx, const char *path, const char *password);
```

```c
typedef int (*mbedtls_pk_rsa_alt_sign_func)(void *ctx,
                                            mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash, unsigned char *sig);
```

### Changes in SSL

The following function calls have been changed in SSL:

```c
int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                             psa_algorithm_t alg, psa_key_type_t key_type, psa_key_bits_t key_bits, uint32_t lifetime);
```

```c
int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
```

to

```c
int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             psa_algorithm_t alg, psa_key_type_t key_type, psa_key_bits_t key_bits, uint32_t lifetime);
```

```c
int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx);
```

The following structs have also been changed in SSL

```c
typedef struct mbedtls_ssl_ticket_context {
    mbedtls_ssl_ticket_key MBEDTLS_PRIVATE(keys)[2]; /*!< ticket protection keys             */
    unsigned char MBEDTLS_PRIVATE(active);           /*!< index of the currently active key  */

    uint32_t MBEDTLS_PRIVATE(ticket_lifetime);       /*!< lifetime of tickets in seconds     */

    /** Callback for getting (pseudo-)random numbers                        */
    int(*MBEDTLS_PRIVATE(f_rng))(void *, unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_rng);                    /*!< context for the RNG function       */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_ssl_ticket_context;
```


to

```c
typedef struct mbedtls_ssl_ticket_context {
    mbedtls_ssl_ticket_key MBEDTLS_PRIVATE(keys)[2]; /*!< ticket protection keys             */
    unsigned char MBEDTLS_PRIVATE(active);           /*!< index of the currently active key  */

    uint32_t MBEDTLS_PRIVATE(ticket_lifetime);       /*!< lifetime of tickets in seconds     */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_ssl_ticket_context;

### Removal of `mbedtls_ssl_conf_rng`

`mbedtls_ssl_conf_rng` has been removed from the library as its sole purpose is to configure RNG for ssl and this is no longer required.
```

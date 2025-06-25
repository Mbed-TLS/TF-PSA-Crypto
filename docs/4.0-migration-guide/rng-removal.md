## RNG removal

### Public functions no longer take a RNG callback

The `f_rng` and `p_rng` arguments have been removed from the LMS, LMOTS and PK modules. All calls to `f_rng` have then been replaced by a call to `psa_generate_random` and all software utilising these modules will now require a call to `psa_crypto_init` prior to calling them. 

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
```


to

```c
int mbedtls_lms_generate_private_key(mbedtls_lms_private_t *ctx, mbedtls_lms_algorithm_type_t type, mbedtls_lmots_algorithm_type_t otstype,
                                     const unsigned char *seed, size_t seed_size);
```

```c
int mbedtls_lms_sign(mbedtls_lms_private_t *ctx,
                     const unsigned char *msg, unsigned int msg_size, unsigned char *sig, size_t sig_size, size_t *sig_len);
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

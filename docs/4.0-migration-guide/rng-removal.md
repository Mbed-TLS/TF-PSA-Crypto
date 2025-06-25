## RNG removal

### Public functions no longer take a RNG callback

Functions that need randomness no longer take an RNG callback in the form of `f_rng, p_rng` arguments. Instead, they use the PSA Crypto random generator (accessible as `psa_generate_random()`). All software using the LMS or PK modules must call `psa_crypto_init()` before calling any of the functions listed here.

### Changes in LMS

The following function prototypes have been changed in `mbedtls/lms.h`:

```c
int mbedtls_lms_generate_private_key(mbedtls_lms_private_t *ctx, mbedtls_lms_algorithm_type_t type, mbedtls_lmots_algorithm_type_t otstype,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng,
                                     const unsigned char *seed, size_t seed_size);

int mbedtls_lms_sign(mbedtls_lms_private_t *ctx,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng,
                     const unsigned char *msg, unsigned int msg_size, unsigned char *sig, size_t sig_size, size_t *sig_len);
```


to

```c
int mbedtls_lms_generate_private_key(mbedtls_lms_private_t *ctx, mbedtls_lms_algorithm_type_t type, mbedtls_lmots_algorithm_type_t otstype,
                                     const unsigned char *seed, size_t seed_size);

int mbedtls_lms_sign(mbedtls_lms_private_t *ctx,
                     const unsigned char *msg, unsigned int msg_size, unsigned char *sig, size_t sig_size, size_t *sig_len);
```

### Changes in PK

The following function prototypes have been changed in `mbedtls/pk.h`:

```c
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx);

int mbedtls_pk_check_pair(const mbedtls_pk_context *pub, const mbedtls_pk_context *prv,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);

int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_pk_sign_ext(mbedtls_pk_type_t pk_type, mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

int mbedtls_pk_parse_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx, const char *path, const char *password,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

typedef int (*mbedtls_pk_rsa_alt_sign_func)(void *ctx,
                                            int (*f_rng)(void *, unsigned char *, size_t),
                                            void *p_rng,
                                            mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash, unsigned char *sig);
```

to

```c
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                                 mbedtls_pk_restart_ctx *rs_ctx);

int mbedtls_pk_check_pair(const mbedtls_pk_context *pub, const mbedtls_pk_context *prv);

int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len);

int mbedtls_pk_sign_ext(mbedtls_pk_type_t pk_type, mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len);

int mbedtls_pk_parse_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen);

int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx, const char *path, const char *password);

typedef int (*mbedtls_pk_rsa_alt_sign_func)(void *ctx,
                                            mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash, unsigned char *sig);
```

## Changes to the PAKE interface

The PAKE interface in TF-PSA-Crypto 1.0 has been updates to match PSA Crypto API [1.2 Final](https://arm-software.github.io/psa-api/crypto/1.2/ext-pake/) PAKE extension, which is the same version that has been integrated into the main specification of PSA Crypto [version 1.3](https://arm-software.github.io/psa-api/crypto/1.3/).

In Mbed TLS 3.6, the PAKE interface implemented version [1.1 Beta](https://arm-software.github.io/psa-api/crypto/1.1/ext-pake/) of the PAKE extension. There has been a number of [changes between the beta and the final version](https://arm-software.github.io/psa-api/crypto/1.2/ext-pake/appendix/history.html#changes-between-beta-1-and-final) of the API. The changes that require applications to update their code are detailed in the following subsections.

Note that TF-PSA-Crypto 1.0 still only implements `PSA_ALG_JPAKE` (and only on elliptic curves, specifically only on secp256r1). Support for SPAKE2+ is likely to be added in a future version but is not there yet.

### Combine `psa_pake_set_password_key()` with `psa_pake_setup()`

The function `psa_pake_set_password_key()` has been removed. Its `key` argument is now passed to `psa_pake_setup()` which has gained a new `key` parameter.

Before:

```
status = psa_pake_setup(&operation, &cipher_suite);
if (status != PSA_SUCCESS) // error handling ommited for brevity
status = psa_pake_set_password_key(&operation, key);
if (status != PSA_SUCCESS) // error handling ommited for brevity
```

Now:

```
status = psa_pake_setup(&operation, key, &cipher_suite);
if (status != PSA_SUCCESS) // error handling ommited for brevity
```

### Move the hash algorithm parameter into the algorithm identifier

The function `psa_pake_cs_set_hash()` has been removed. Its `hash` argument is now passed to `PSA_ALG_JPAKE()` which is now a function-like macro with one parameter.

Before:

```
psa_pake_cs_set_algorithm(&cipher_suite, PSA_ALG_JPAKE);
psa_pake_cs_set_hash(&cipher_suite, PSA_ALG_SHA_256);
```

Now:

```
psa_pake_cs_set_algorithm(&cipher_suite, PSA_ALG_JPAKE(PSA_ALG_SHA_256));
```

To check if a given algorithm is J-PAKE, the new `PSA_ALG_IS_JPAKE()` macro has been added.

Before: `if (alg == PSA_ALG_JPAKE)`

Now: `if (PSA_ALG_IS_JPAKE(alg))`

The function `psa_pake_cs_get_hash()` has also been removed.

### Replace `psa_pake_get_implicit_key()` with `psa_pake_get_shared_key()`

The function `psa_pake_get_implicit_key()`, which injects the shared secret into a key derivation operation, has been removed. Its replacement is `psa_pake_get_shared_key()` which stores the shared secret in a new key. That new key can then be used as part of a key derivation operation.

Before:

```
status = psa_pake_get_implicit_key(&pake_op, &derivation_op);
if (status != PSA_SUCCESS) // error handling ommited for brevity
```

Now:

```
psa_key_id_t shared_key_id = (psa_key_id_t) 0;

psa_key_attributes_t shared_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_usage_flags(&shared_key_attributes, PSA_KEY_USAGE_DERIVE);
psa_set_key_algorithm(&shared_key_attributes, alg);
psa_set_key_type(&shared_key_attributes, PSA_KEY_TYPE_DERIVE);

status = psa_pake_get_shared_key(&pake_op,
                                 &shared_key_attributes,
                                 &shared_key_id);
if (status != PSA_SUCCESS) // error handling ommited for brevity

status = psa_key_derivation_input_key(&derivation_op,
                                      PSA_KEY_DERIVATION_INPUT_SECRET,
                                      shared_key_id);
if (status != PSA_SUCCESS) // error handling ommited for brevity

psa_reset_key_attributes(&shared_key_attributes);
psa_destroy_key(shared_key_id);
```

## Platform-specific Entropy Gathering

`MBEDTLS_ENTROPY_HARDWARE_ALT` has been renamed to `MBEDTLS_PLATFORM_GET_ENTROPY_ALT`.
The prototype for the custom entropy callback function changed from:

```c
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen);
```

to:

```c
int mbedtls_platform_get_entropy(unsigned char *output, size_t output_size,
                                 size_t *output_len, size_t *entropy_content);
```

This new prototype is placed in the public header `mbedtls/platform.h` instead
of the private `library/entropy_poll.h` one as it was previously.

The `data` parameter was previously always `NULL`, and has been removed.

The new `entropy_content` parameter measures (in bit) the amount of entropy
contained in the returned `output` buffer.
For the time being, TF-PSA-Crypto only supports callbacks that provide full
entropy. That means that the content of the output buffer must be uniformly
random, allowing you to report that `entropy_content = 8 * *output_len`.
Typically `*output_len == output_size`, but if it is smaller, the library will
call the callback again in a loop.

If you implement this callback for hardware that delivers partial entropy, a
typical technique is to gather enough entropy then hash the result. Hashing does
not increase the entropy, but it distributes it throughout the buffer. For
example, suppose your hardware has a 32-bit register which is documented as
having a single bit of entropy each time it is read after calling a priming
function. The following code snippet collects 8 bits of entropy and outputs it
in one byte.

```c
int mbedtls_platform_get_entropy(unsigned char *output, size_t output_size,
                                 size_t *output_len, size_t *entropy_content) {
    uint32_t reads[8];
    uint8_t hash[32];
    int ret;
    psa_status_t status;
    (void) output_size;

    for (int i = 0; i < 8; i++) {
        ret = myhardware_prime_magic_random_register();
        if (ret != 0) {
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        reads[i] = myhardware_magic_random_register_read();
    }
    size_t hash_len;

    status = psa_hash_compute(PSA_ALG_SHA_256, (uint_t*) reads, sizeof(reads),
                              hash, sizeof(hash), &hash_len);
    if (ret != PSA_SUCCESS) {
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }

    output[0] = hash[0];
    *output_len = 1;
    *entropy_content = 8;

    return 0;
}
```

`MBEDTLS_ENTROPY_MIN_HARDWARE` is also removed and the entropy module assumes
that 32 bytes are enough to declare the hardware entropy polling completed.
This value is not user configurable.

The option MBEDTLS_PLATFORM_GET_ENTROPY_ALT disables the built-in entropy
sources, unlike its predecessor MBEDTLS_ENTROPY_HARDWARE_ALT, because one
entropy source is generally sufficient. If you want to add a custom entropy
source while retaining the platform's default source, call the platform's
default source in your callback.

The option MBEDTLS_NO_PLATFORM_ENTROPY is removed. TF-PSA-Crypto 1.0 no longer
supports platforms without an entropy source. This ability will be reintroduced
in a future minor release.

## Platform-specific Entropy Gathering

`MBEDTLS_ENTROPY_HARDWARE_ALT` has been renamed to `MBEDTLS_PLATFORM_GET_ENTROPY_ALT`.
The prototype for the custom defined hardware entropy polling function changed
from:

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

The new `entropy_content` parameter measures (in bit) the amount of entropy
contained in the returned `output` buffer. For the time being only full entropy
sources are allowed (i.e. `entropy_content = 8 * *output_len`), but this can
change in the future.

`MBEDTLS_ENTROPY_MIN_HARDWARE` is also removed and the entropy module assumes
that 32 bytes are enough to declare the hardware entropy polling completed.
This value is not user configurable.

While up to Mbed TLS 3.6 Platform and Hardware entropy sources could be
independently enabled, starting from TF-PSA-Crypto 1.0 they become mutually
exclusive. `MBEDTLS_NO_PLATFORM_ENTROPY` is therefore removed as
`MBEDTLS_PLATFORM_GET_ENTROPY_ALT` can be used to switch between Platform
and Hardware entropy polling.

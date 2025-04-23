## Platform-specific Entropy Gathering

### Disclaimer

All the following sections refer to the case where entropy module uses default
entropy sources, i.e. `MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES` is not defined.

### Background

Up to Mbed TLS 3.6 entropy module supported 3 entropy sources by default:

- Platform
  - Enabled by default it could be disabled through `MBEDTLS_NO_PLATFORM_ENTROPY`.
  - It used platform-specific sources such as getrandom(), /dev/urandom or
    BCryptGenRandom() to gather entropy data.
  - Only useful when running on high level OSes, not in baremetal projects.

- Hardware
  - Disabled by default, it could be enabled through `MBEDTLS_ENTROPY_HARDWARE_ALT`.
  - It allowed the user to define a custom function named `mbedtls_hardware_poll()`
    to gather entropy data from some hardware source.
  - Very useful for baremetal projects.
  - Unfortunately the prototype for the function was in a private header file.

- NV seed
  - Disabled by default, it could be enabled through `MBEDTLS_ENTROPY_NV_SEED`.
  - It allowed the user to store an entropy seed on a non-volatile (NV) memory
    (ex: filesystem).
  - This is crucial on systems that do not have a cryptographic entropy source
    available through the previous 2 options.

Up to Mbed TLS 3.6 all these 3 build symbols could be enabled independently.

### Reasons to change

Platform and Hardware entropy sources are most of the times mutually exclusive,
so that the user will either use one or the other, but it's very unlikely to
enable both. Therefore it's better to unify them under a single build symbol
and to use a gathering function with the same name. Moreover this function must
have the prototype in some public header so that the user can easily integrate
it in their source code.

### What changes in TF-PSA-Crypto 1.0?

The following build symbols are removed:

- `MBEDTLS_ENTROPY_HARDWARE_ALT`,
- `MBEDTLS_ENTROPY_MIN_HARDWARE`,
- `MBEDTLS_NO_PLATFORM_ENTROPY`.

By default entropy module uses Platform entropy source to gather entropy data.
However the user can enable `MBEDTLS_PLATFORM_GET_ENTROPY_ALT` to define their
own custom implementation of the entropy gathering function and this will
exclude the Platform one (alternate implementation).
The prototype of this function can be found in `mbedtls/platform.h` and it's as
follows:

```c
int mbedtls_platform_get_entropy(void *data, unsigned char *output, size_t len, size_t *olen);
```

See documentation of this function for futher details about input parameters and
return values.

## Entropy configuration

TF-PSA-Crypto does not expose an entropy interface to applications. The entropy module of Mbed TLS 3.6 is now for internal use only. As a consequence, its configuration has changed, both to simplify it and to prepare for PSA entropy drivers which will be added in a future minor release.

### Entropy sources and random generation

Many cryptographic mechanisms require a strong random generator. The overall structure of the random generator in TF-PSA-Crypto is the same as in Mbed TLS 3.x, namely:

* If you have a fast, cryptographic-quality source of random data, enable `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG`, and do not enable `MBEDTLS_ENTROPY_C`.
* Otherwise, enable `MBEDTLS_ENTROPY_C`, at least one entropy source and one of the DRBG modules (`MBEDTLS_CTR_DRBG_C` or `MBEDTLS_HMAC_DRBG_C`).

### Configuration of entropy sources

TF-PSA-Crypto 1.0 supports the same entropy sources as Mbed TLS 3.6, but the way to configure them has changed.

* The negative option `MBEDTLS_NO_PLATFORM_ENTROPY` to disable the default entropy collector for Unix-like and Windows platforms no longer exists. It has been replaced by the positive option `MBEDTLS_PSA_BUILTIN_GET_ENTROPY`, which is enabled by default.
* The option `MBEDTLS_ENTROPY_HARDWARE_ALT`, which allows you to provide a custom entropy collector, has been renamed to `MBEDTLS_PSA_DRIVER_GET_ENTROPY`. This replaces `MBEDTLS_ENTROPY_HARDWARE_ALT`. The callback has a different name and prototype as described in “[Custom hardware collector](#custom-entropy-collector)”.
* The option `MBEDTLS_ENTROPY_NV_SEED` to enable a nonvolatile seed is unchanged. However, if this is your only entropy source, you must now enable the new option `MBEDTLS_ENTROPY_NO_SOURCES_OK`.

The following table describes common configurations.

<table>
  <tr valign="top">
    <th align="left">Configuration</th>
    <th align="left">Mbed TLS 3.6</th>
    <th align="left">TF-PSA-Crypto 1.0</th>
  </tr>

  <tr valign="top">
    <td><strong>Unix, Linux, Windows</strong></td>
    <td>(default)</td>
    <td>(default)</td>
  </tr>

  <tr valign="top">
    <td><strong>Embedded platform</strong></td>
    <td>
      <pre>
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT
      </pre>
    </td>
    <td>
      <pre>
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY
      </pre>
    </td>
  </tr>

  <tr valign="top">
    <td><strong>Fast external crypto RNG</strong></td>
    <td>
      <pre>
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#undef MBEDTLS_ENTROPY_C
#undef MBEDTLS_CTR_DRBG_C
      </pre>
    </td>
    <td>
      <pre>
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#undef MBEDTLS_ENTROPY_C
#undef MBEDTLS_CTR_DRBG_C
      </pre>
    </td>
  </tr>

  <tr valign="top">
    <td><strong>NV seed only</strong></td>
    <td>
      <pre>
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_NV_SEED
      </pre>
    </td>
    <td>
      <pre>
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_ENTROPY_NV_SEED
#define MBEDTLS_ENTROPY_NO_SOURCES_OK
      </pre>
    </td>
  </tr>

  <tr valign="top">
    <td><strong>No entropy at all</strong></td>
    <td>
      <pre>
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
      </pre>
    </td>
    <td>
      <em>not supported</em>
    </td>
  </tr>
</table>

### Custom entropy collector

The custom entropy collector callback function has changed, to make it match the upcoming PSA entropy driver specification.

Formerly, the callback was enabled by `MBEDTLS_ENTROPY_HARDWARE_ALT` and had the following prototype:
```c
// from <entropy_poll.h>
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen);
```

The new callback is enabled by `MBEDTLS_PSA_DRIVER_GET_ENTROPY` and has the following prototype:
```c
```

to:

```c
// from <mbedtls/platform.h>
int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
                                 size_t *estimate_bits,
                                 unsigned char *output, size_t output_size);
```

The `data` parameter was previously always `NULL`, and has been removed.

The new parameter `flags` is a bit-mask of flags that allows the caller to request special behaviors, such as avoiding blocking. The callback should return `PSA_ERROR_NOT_SUPPORTED` if it sees a flag that it does not support. As of TF-PSA-Crypto 1.0, `flags` is always 0.

The former callback could return less entropy than expected by only filling part of the buffer, and setting `*olen` to a value that is less than `output_size`. The new callback does not have an `olen` parameter, and the caller now reads the whole buffer. The new parameter `estimate_bits` is intended to allow the callback to report that it has accumulated less entropy than expected. However, this is not supported yet in TF-PSA-Crypto 1.0.

The new output parameter `estimate_bits` is the amount of entropy that the callback has placed in the output buffer. As of TF-PSA-Crypto 1.0, the output must have full entropy, thus `estimate_bits` must be equal to `8 * output_size`. A future version of TF-PSA-Crypto will allow entropy sources to report smaller amounts.

To indicate that entropy is not currently available, the legacy error code `MBEDTLS_ERR_ENTROPY_SOURCE_FAILED` has been replaced by `PSA_ERROR_INSUFFICIENT_ENTROPY`.

### Removed entropy options

The option `MBEDTLS_ENTROPY_MIN_HARDWARE` has been removed. The entropy module requests the amount that it needs for the chosen security strength.

The option `MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES` has removed since it is no longer meaningful, now that the entropy module is private. TF-PSA-Crypto 1.0 does not support platforms without an entropy source. This ability will be reintroduced in a future minor release.

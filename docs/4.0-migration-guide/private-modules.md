## Low-level crypto functions are no longer part of the public API

Low-level crypto functions, that is, all non-PSA crypto functions except a few
that don't have a proper PSA replacement yet, have been removed from the public
API.

If your application was using those functions, please see
`docs/psa-transition.md` (currently in the Mbed TLS repo) for ways to migrate to
the PSA API instead.

Some of the associated types (for example, `mbedtls_aes_context`) still need to
be visible to the compiler, so the headers declaring them (for example, `aes.h`)
are still on the default include path, but we recommend you no longer include
them directly.

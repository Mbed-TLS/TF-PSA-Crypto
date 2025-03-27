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

Sample programs have not been fully updated yet and some of them might still
use APIs that are no longer public. You can recognize them by the fact that they
define the macro `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` (or
`MBEDTLS_ALLOW_PRIVATE_ACCESS`) at the very top (before including headers). When
you see one of these two macros in a sample program, be aware it has not been
updated and parts of it do not demonstrate current practice.

We strongly recommend against defining `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` or
`MBEDTLS_ALLOW_PRIVATE_ACCESS` in your own application. If you do so, your code
may not compile or work with future minor releases. If there's something you
want to do that you feel can only be achieved by using one of these two macros,
please reach out on github or the mailing list.

The following modules had functions removed from the public API:
- see private-decls/ subdirectory for now - one file per header, to avoid
  conflicts caused by all PRs editing the same place in this file, to be merged
  at the end as part of https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/232
- also do one brief ChangeLog entry per PR, with a name starting with privatize
  (eg privatize-aes.txt), also to be merged at the end as part of 232.

## Threading platform abstraction

The threading abstraction now includes primitives for condition variables in addition to mutexes.

The type of mutex objects provided by the platform functions is now called `mbedtls_platform_mutex_t`, distinct from the API type `mbedtls_threading_mutex_t`.

As before, implementations of `MBEDTLS_THREADING_ALT` need to provide a header file `"threading_alt.h"`, and to call the function `mbedtls_threading_set_alt()` before any call to other TF-PSA-Crypto or Mbed TLS functions. The header file `"threading_alt.h"` now needs to define the following elements:

* The type `mbedtls_platform_mutex_t`, which is the type of mutex arguments passed to the platform functions. This type is now distinct from the type `mbedtls_threading_mutex_t` which library code and applications use.
* The type `mbedtls_platform_condition_variable_t`, which is the type of condition variable arguments passed to the platform functions.

The documentation in `include/mbedtls/threading.h` now clarifies the expectations on mutex primitives. These expectations are unchanged from what they were in previous versions, they have just been made explicit.

Platform threading primitives should now return the following error codes:

* `MBEDTLS_ERR_THREADING_USAGE_ERROR` to report a runtime failure (renamed from `MBEDTLS_ERR_THREADING_MUTEX_ERROR`, which is now an alias provided only for backward compatibility).
* `PSA_ERROR_BAD_STATE` only to report a library state error. If an error is detected in the state of a synchronization object, please return `MBEDTLS_ERR_THREADING_USAGE_ERROR` instead.
* `PSA_ERROR_INSUFFICIENT_MEMORY` to report resource exhaustion.

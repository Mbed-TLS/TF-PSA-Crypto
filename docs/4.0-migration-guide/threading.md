## Threading interface

### Changes to the application interface for threading

#### Mutex interface changes

TODO: not implemented yet

The function `mbedtls_mutex_init()`, which returns `void`, has been replaced by `mbedtls_mutex_setup()` which is similar, but returns an error code if it fails.

#### Mutex interface clarifications

The documentation of the mutex functions now specifies usage constraints. These constraints already applied to previous versions of Mbed TLS, but were not documented.

#### New condition variable interface

The new functions `mbedtls_condition_variable_setup()`, `mbedtls_condition_variable_destroy()`, `mbedtls_condition_variable_signal()`, `mbedtls_condition_variable_broadcast()` and `mbedtls_condition_variable_wait()` provide an interface for condition variables. They can be used together with the mutex interface to perform synchronization in more general ways.

### Changes to the platform interface for threading

The platform interface for threading, enabled by `MBEDTLS_THREADING_ALT`, has been overhauled to provide a larger scope, more flexibility where needed and less complexity where not needed.

#### Decoupling of threading interfaces

The platform interface and the application interfaces have been decoupled: the functions that the platform interface must provide are no longer called directly by applications. The new header `<mbedtls/threading_platform.h>` documents the interfaces that the platform must provide.

#### The threading abstraction is now static

The platform must now provide actual functions, not pointers to functions. They can be either inline functions defined in `"threading_alt.h"`, or linkable functions. Either way the functions are declared in `<mbedtls/threading_platform.h>`.

The function `mbedtls_threading_set_alt()` no longer exists.

#### Mutex abstraction changes

The documentation of the mutex platform functions now specifies usage constraints. These constraints already applied to previous versions of Mbed TLS, but were not documented.

The following table summarizes the changes to individual elements in the mutex abstraction.

| Element | Old name | New name | Change summary |
| ------- | -------- | -------- | -------------- |
| type | `mbedtls_threading_mutex_t` | `mbedtls_platform_mutex_t` | Renamed |
| init | `mbedtls_mutex_init` | `mbedtls_platform_mutex_setup` | Renamed; now returns a status |
| destroy | `mbedtls_mutex_free` | `mbedtls_platform_mutex_destroy` | Renamed |
| lock | `mbedtls_mutex_lock` | `mbedtls_platform_mutex_lock` | Renamed |
| unlock | `mbedtls_mutex_unlock` | `mbedtls_platform_mutex_unlock` | Renamed |

#### New condition variable abstraction

The new functions `mbedtls_platform_condition_variable_setup()`, `mbedtls_platform_condition_variable_destroy()`, `mbedtls_platform_condition_variable_signal()`, `mbedtls_platform_condition_variable_broadcast()` and `mbedtls_platform_condition_variable_wait()` provide an abstraction for condition variables.

#### New thread management abstraction

The new functions `mbedtls_platform_thread_create()` and `mbedtls_platform_thread_join()` provide a way to create and destroy threads dynamically.

These functions are optional: we do not intend to call them from TF-PSA-Crypto 1.x or Mbed TLS 4.x. However, they are required to build the tests in TF-PSA-Crypto 1.0. They may also be required to build sample programs in the future.

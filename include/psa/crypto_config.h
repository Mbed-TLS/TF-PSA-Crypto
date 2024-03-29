/**
 * \file psa/crypto_config.h
 * \brief TF-PSA-Crypto configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef TF_PSA_CRYPTO_CONFIG_H
#define TF_PSA_CRYPTO_CONFIG_H

/**
 * \name SECTION: General configuration options.
 *
 * This section contains the options that are not related to a specific part
 * of the implementation of the PSA Cryptography API.
 * \{
 */

/** \def TF_PSA_CRYPTO_CONFIG_FILE
 *
 * If defined, this is a header which will be included instead of
 * `"psa/crypto_config.h"`.
 * This header file specifies the compile-time configuration of PSA
 * cryptography. Unlike other configuration options, this one must be defined
 * on the compiler command line: a definition in `crypto_config.h` would have
 * no effect.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define TF_PSA_CRYPTO_CONFIG_FILE "psa/crypto_config.h"

/** \def TF_PSA_CRYPTO_CONFIG_PATCH
 *
 * If defined, this is a header which will be included after
 * `"psa/crypto_config.h"` or #TF_PSA_CRYPTO_CONFIG_FILE.
 * This allows you to modify the configuration as defined by
 * `"psa/crypto_config.h"` or #TF_PSA_CRYPTO_CONFIG_FILE., including the ability
 * to undefine options that are enabled.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define TF_PSA_CRYPTO_CONFIG_PATCH "/dev/null"

/** \def TF_PSA_CRYPTO_SPM
 *
 * When TF_PSA_CRYPTO_SPM is defined, the code is built for SPM (Secure Partition
 * Manager) integration which separates the code into two parts: a NSPE
 * (Non-Secure Process Environment) and an SPE (Secure Process Environment).
 *
 */
//#define TF_PSA_CRYPTO_SPM

/**
 * \def TF_PSA_CRYPTO_STD_FUNCTIONS
 *
 * If this option is enabled then most of the platform abstraction functions,
 * as defined in include/tf_psa_crypto/platform.h are provided by the library.
 * They are aliases to standard C library functions or their implementation is
 * based on standard C library functions.
 *
 * Uncomment to provide your own implementations of the platform abstraction
 * functions.
 */
#define TF_PSA_CRYPTO_STD_FUNCTIONS

/**
 * \def TF_PSA_CRYPTO_FS_IO
 *
 * Enable functions that use the file system. The file system is accessed
 * through the standard C library file functions like fopen(), fclose() ...
 *
 * Uncomment if there is no file system that can be accessed through the
 * standard C library file functions.
 */
#define TF_PSA_CRYPTO_FS_IO

/**
 * \def TF_PSA_CRYPTO_MEMORY_BUFFER_ALLOC
 *
 * Enable the buffer allocator implementation that makes use of a (stack)
 * based buffer to 'allocate' dynamic memory. (replaces calloc() and free()
 * calls)
 *
 * \note This configuration option does not have any effect on the build if
 *       the configuration option TF_PSA_CRYPTO_STD_FUNCTIONS is enabled.
 */
//#define TF_PSA_CRYPTO_MEMORY_BUFFER_ALLOC

/**
 * Uncomment the macro to let TF-PSA-Crypto use your alternate implementation
 * of tf_psa_crypto_platform_zeroize() instead of the default implementation.
 *
 * tf_psa_crypto_platform_zeroize() is a widely used function across the library
 * to zero a block of memory. The implementation is expected to be secure in the
 * sense that it has been written to prevent the compiler from removing calls
 * to tf_psa_crypto_platform_zeroize() as part of redundant code elimination
 * optimizations. However, it is difficult to guarantee that calls to
 * tf_psa_crypto_platform_zeroize() will not be optimized by the compiler as
 * older versions of the C language standards do not provide a secure
 * implementation of memset(). Therefore, TF_PSA_CRYPTO_PLATFORM_ZEROIZE
 * enables users to provide their own implementation of
 * tf_psa_crypto_platform_zeroize(), for example by using directives specific
 * to their compiler.
 */
//#define TF_PSA_CRYPTO_PLATFORM_ZEROIZE

/** \} name SECTION: General configuration options */

/**
 * \name SECTION: PSA cryptography interface configuration
 *
 * This section allows for configuring the parts of the PSA Cryptography API
 * to enable as specified in psa-conditional-inclusion-c.md.
 *
 * \{
 */

/*
 * CBC-MAC is not yet supported via the PSA API in Mbed TLS.
 */
//#define PSA_WANT_ALG_CBC_MAC                    1
#define PSA_WANT_ALG_CBC_NO_PADDING             1
#define PSA_WANT_ALG_CBC_PKCS7                  1
#define PSA_WANT_ALG_CCM                        1
#define PSA_WANT_ALG_CCM_STAR_NO_TAG            1
#define PSA_WANT_ALG_CMAC                       1
#define PSA_WANT_ALG_CFB                        1
#define PSA_WANT_ALG_CHACHA20_POLY1305          1
#define PSA_WANT_ALG_CTR                        1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ALG_ECB_NO_PADDING             1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_FFDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_JPAKE                      1
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_HKDF                       1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_MD5                        1
#define PSA_WANT_ALG_OFB                        1
#define PSA_WANT_ALG_PBKDF2_HMAC                1
#define PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128    1
#define PSA_WANT_ALG_RIPEMD160                  1
#define PSA_WANT_ALG_RSA_OAEP                   1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
#define PSA_WANT_ALG_RSA_PSS                    1
#define PSA_WANT_ALG_SHA_1                      1
#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_SHA_512                    1
#define PSA_WANT_ALG_SHA3_224                   1
#define PSA_WANT_ALG_SHA3_256                   1
#define PSA_WANT_ALG_SHA3_384                   1
#define PSA_WANT_ALG_SHA3_512                   1
#define PSA_WANT_ALG_STREAM_CIPHER              1
#define PSA_WANT_ALG_TLS12_PRF                  1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS            1
#define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS       1

/* XTS is not yet supported via the PSA API in Mbed TLS.
 * Note: when adding support, also adjust include/mbedtls/config_psa.h */
//#define PSA_WANT_ALG_XTS                        1

#define PSA_WANT_ECC_BRAINPOOL_P_R1_256         1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_384         1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_512         1
#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_ECC_MONTGOMERY_448             1
#define PSA_WANT_ECC_SECP_K1_192                1
/*
 * SECP224K1 is buggy via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/3541). Thus, do not enable it by
 * default.
 */
//#define PSA_WANT_ECC_SECP_K1_224                1
#define PSA_WANT_ECC_SECP_K1_256                1
#define PSA_WANT_ECC_SECP_R1_192                1
#define PSA_WANT_ECC_SECP_R1_224                1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_ECC_SECP_R1_384                1
#define PSA_WANT_ECC_SECP_R1_521                1

#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_PASSWORD              1
#define PSA_WANT_KEY_TYPE_PASSWORD_HASH         1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_ARIA                  1
#define PSA_WANT_KEY_TYPE_CAMELLIA              1
#define PSA_WANT_KEY_TYPE_CHACHA20              1
#define PSA_WANT_KEY_TYPE_DES                   1
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY         1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1

/*
 * The following symbols extend and deprecate the legacy
 * PSA_WANT_KEY_TYPE_xxx_KEY_PAIR ones. They include the usage of that key in
 * the name's suffix. "_USE" is the most generic and it can be used to describe
 * a generic suport, whereas other ones add more features on top of that and
 * they are more specific.
 */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC      1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1

#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC      1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE   1 /* Not supported */

#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC       1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT    1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT    1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE  1
//#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE    1 /* Not supported */

/** \} name SECTION: PSA cryptography interface configuration */

/**
 * \name SECTION: PSA cryptography core configuration options
 *
 * This section allows for the configuration of the PSA cryptography core
 * which provides the key management, the generation of random numbers and
 * the dispatch to drivers.
 * \{
 */

/** \def TF_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
 *
 * Enable key identifiers that encode a key owner identifier.
 *
 * The owner of a key is identified by a value of type ::psa_crypto_key_owner_id_t
 * which is currently hard-coded to be int32_t.
 *
 * Note that this option is meant for internal use only and may be removed
 * without notice.
 */
//#define TF_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

/** \def TF_PSA_CRYPTO_BUILTIN_KEYS
 *
 * Enable support for platform built-in keys. If you enable this feature,
 * you must implement the function psa_platform_get_builtin_key().
 * See the documentation of that function for more information.
 *
 * Built-in keys are typically derived from a hardware unique key or
 * stored in a secure element.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
//#define TF_PSA_CRYPTO_BUILTIN_KEYS

/** \def TF_PSA_CRYPTO_EXTERNAL_RNG
 *
 * Use an external random generator provided by a driver, instead of the
 * builtin entropy and DRBG modules.
 *
 * \note This random generator must deliver random numbers with cryptographic
 *       quality and high performance. It must supply unpredictable numbers
 *       with a uniform distribution. The implementation of this function
 *       is responsible for ensuring that the random generator is seeded
 *       with sufficient entropy. If you have a hardware TRNG which is slow
 *       or delivers non-uniform output, you should not enable this option.
 *
 * If you enable this option, you must configure the type
 * ::psa_crypto_external_random_context_t in psa/crypto_platform.h
 * and define a function called psa_crypto_external_get_random()
 * with the following prototype:
 * ```
 * psa_status_t psa_crypto_external_get_random(
 *     psa_crypto_external_random_context_t *context,
 *     uint8_t *output, size_t output_size, size_t *output_length);
 * );
 * ```
 * The \c context value is initialized to 0 before the first call.
 * The function must fill the \c output buffer with \p output_size bytes
 * of random data and set \c *output_length to \p output_size.
 *
 * \note This option is experimental and may be removed without notice.
 */
//#define TF_PSA_CRYPTO_EXTERNAL_RNG

/** \def TF_PSA_CRYPTO_STORAGE_C
 *
 * Enable the Platform Security Architecture persistent key storage.
 *
 * Module:  library/psa_crypto_storage.c
 *
 * Requires: TF_PSA_CRYPTO_ITS_FILE_C or a native implementation of
 *           the PSA ITS interface
 */
#define TF_PSA_CRYPTO_STORAGE_C

/** \def TF_PSA_CRYPTO_ITS_FILE_C
 *
 * Enable the emulation of the Platform Security Architecture
 * Internal Trusted Storage (PSA ITS) over files.
 *
 * Module:  library/psa_its_file.c
 *
 */
#define TF_PSA_CRYPTO_ITS_FILE_C

/** \def TF_PSA_CRYPTO_HMAC_DRBG_HASH
 *
 * Use HMAC_DRBG with the specified hash algorithm for HMAC_DRBG for
 * PSA cryptography.
 *
 * If this option is unset, PSA cryptography uses CTR_DRBG.
 */
//#define TF_PSA_CRYPTO_HMAC_DRBG_HASH PSA_ALG_SHA_256

/** \def TF_PSA_CRYPTO_KEY_SLOT_COUNT
 *
 * Restrict the PSA library to supporting a maximum amount of simultaneously
 * loaded keys. A loaded key is a key stored by the PSA cryptography core as a
 * volatile key, or a persistent key which is loaded temporarily by the
 * library as part of a crypto operation in flight.
 *
 * If this option is unset, the library will fall back to a default value of
 * 32 keys.
 */
//#define TF_PSA_CRYPTO_KEY_SLOT_COUNT 32

/**
 * \def TF_PSA_CRYPTO_PLATFORM_ENTROPY
 *
 * Enable the usage of standard platform entropy functions like /dev/urandom or
 * Windows CryptoAPI as a source of entropy.
 *
 * Comment this macro to disable the usage of standard platform entropy
 * functions as a source of entropy.
 *
 */
#define TF_PSA_CRYPTO_PLATFORM_ENTROPY

/**
 * \def TF_PSA_CRYPTO_HARDWARE_ENTROPY
 *
 * Uncomment the macro to let TF-PSA-Crypto use your own hardware entropy
 * collector.
 *
 * Your hardware entropy collector function must be called
 * \c tf_psa_crypto_hardware_entropy(), see include/tf_psa_crypto/platform.h
 * for its prototype.
 */
//#define TF_PSA_CRYPTO_HARDWARE_ENTROPY

/**
 * \def TF_PSA_CRYPTO_ENTROPY_NV_SEED
 *
 * Enable the non-volatile (NV) seed entropy source.
 * (Also enables the NV seed read/write functions in the platform abstraction
 *  layer)
 *
 * This is crucial, or maybe even required, to enable a non-volatile seed
 * entropy source on systems that do not have a cryptographic entropy source
 * (in hardware or kernel) available.
 *
 * \note If you use the library default functions that read a seed file
 *       with regular fopen() (TF_PSA_CRYPTO_STD_FUNCTIONS and TF_PSA_CRYPTO_FS_IO
 *       enabled), please make sure you make a seed file with the proper name
 *       (defined by TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE) and at least
 *       TF_PSA_CRYPTO_ENTROPY_BLOCK_SIZE bytes in size that can be read from
 *       and written to or you will get an entropy source error. The default
 *       functions will only use the first TF_PSA_CRYPTO_ENTROPY_BLOCK_SIZE bytes
 *       from the file.
 *
 * \note The entropy collector will write to the seed file before entropy is
 *       given to an external source, to update it.
 */
//#define TF_PSA_CRYPTO_ENTROPY_NV_SEED

/**
 * \def TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE
 *
 * Define the path to the file to be used as non-volatile seed entropy source.
 *
 * \note See the TF_PSA_CRYPTO_ENTROPY_NV_SEED configuration option for more
 *       information.
 *
 * \note If TF_PSA_CRYPTO_ENTROPY_NV_SEED or TF_PSA_CRYPTO_STD_FUNCTIONS or
 *       TF_PSA_CRYPTO_FS_IO is disabled, this option does not have any effect on
 *       the build.
 */
#define TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE "seedfile"

/** \} name SECTION: PSA cryptography core configuration options */

/**
 * \name SECTION: PSA driver interface implementation configuration options
 *
 * This section allows for the configuration of the built-in implementation of
 * the PSA driver interface as defined in psa-driver-interface.md. The
 * configuration options in the section are mostly non-functional,
 * related to performance/size trade-offs and platform specific features like
 * processor specific instructions.
 *
 * \{
 */

/** \def TF_PSA_CRYPTO_HAVE_ASM
 *
 * The compiler has support for asm().
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      builtin/src/aesni.h
 *      builtin/src/aria.c
 *      builtin/src/bn_mul.h
 *      builtin/src/constant_time.c
 *
 * Comment to disable the use of assembly code.
 */
#define TF_PSA_CRYPTO_HAVE_ASM

/**
 * \def TF_PSA_CRYPTO_AESNI_C
 *
 * Enable AES-NI support on x86-64 or x86-32.
 *
 * \note AESNI is only supported with certain compilers and target options:
 * - Visual Studio 2013: supported.
 * - GCC, x86-64, target not explicitly supporting AESNI:
 *   requires MBEDTLS_HAVE_ASM.
 * - GCC, x86-32, target not explicitly supporting AESNI:
 *   not supported.
 * - GCC, x86-64 or x86-32, target supporting AESNI: supported.
 *   For this assembly-less implementation, you must currently compile
 *   `library/aesni.c` and `library/aes.c` with machine options to enable
 *   SSE2 and AESNI instructions: `gcc -msse2 -maes -mpclmul` or
 *   `clang -maes -mpclmul`.
 * - Non-x86 targets: this option is silently ignored.
 * - Other compilers: this option is silently ignored.
 *
 * \note
 * Above, "GCC" includes compatible compilers such as Clang.
 * The limitations on target support are likely to be relaxed in the future.
 *
 * Module:  builtin/src/aesni.c
 * Caller:  builtin/src/aes.c
 *
 * Requires: TF_PSA_CRYPTO_HAVE_ASM (on some platforms, see note)
 *
 * This modules adds support for the AES-NI instructions on x86.
 */
#define TF_PSA_CRYPTO_AESNI_C

/**
 * \def TF_PSA_CRYPTO_AESCE_C
 *
 * Enable AES cryptographic extension support on 64-bit Arm.
 *
 * Module:  builtin/src/aesce.c
 * Caller:  builtin/src/aes.c
 *
 * Requires: PSA_WANT_KEY_TYPE_AES
 *
 * \warning Runtime detection only works on Linux. For non-Linux operating
 *          system, Armv8-A Cryptographic Extensions must be supported by
 *          the CPU when this option is enabled.
 *
 * \note    Minimum compiler versions for this feature are Clang 4.0,
 *          armclang 6.6, GCC 6.0 or MSVC 2019 version 16.11.2.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8-a+crypto for
 * armclang <= 6.9
 *
 * This module adds support for the AES Armv8-A Cryptographic Extensions on Aarch64 systems.
 */
#define TF_PSA_CRYPTO_AESCE_C

/** \def TF_PSA_CRYPTO_NO_UDBL_DIVISION
 *
 * The platform lacks support for double-width integer division (64-bit
 * division on a 32-bit platform, 128-bit division on a 64-bit platform).
 *
 * Used in:
 *      builtin/include/mbedtls/bignum.h
 *      builtin/src/bignum.c
 *
 * The bignum code uses double-width division to speed up some operations.
 * Double-width division is often implemented in software that needs to
 * be linked with the program. The presence of a double-width integer
 * type is usually detected automatically through preprocessor macros,
 * but the automatic detection cannot know whether the code needs to
 * and can be linked with an implementation of division for that type.
 * By default division is assumed to be usable if the type is present.
 * Uncomment this option to prevent the use of double-width division.
 *
 * Note that division for the native integer type is always required.
 * Furthermore, a 64-bit type is always required even on a 32-bit
 * platform, but it need not support multiplication or division. In some
 * cases it is also desirable to disable some double-width operations. For
 * example, if double-width division is implemented in software, disabling
 * it can reduce code size in some embedded targets.
 */
//#define TF_PSA_CRYPTO_NO_UDBL_DIVISION

/** \def TF_PSA_CRYPTO_NO_64BIT_MULTIPLICATION
 *
 * The platform lacks support for 32x32 -> 64-bit multiplication.
 *
 * Used in:
 *      library/poly1305.c
 *
 * Some parts of the library may use multiplication of two unsigned 32-bit
 * operands with a 64-bit result in order to speed up computations. On some
 * platforms, this is not available in hardware and has to be implemented in
 * software, usually in a library provided by the toolchain.
 *
 * Sometimes it is not desirable to have to link to that library. This option
 * removes the dependency of that library on platforms that lack a hardware
 * 64-bit multiplier by embedding a software implementation in Mbed TLS.
 *
 * Note that depending on the compiler, this may decrease performance compared
 * to using the library function provided by the toolchain.
 */
//#define TF_PSA_CRYPTO_NO_64BIT_MULTIPLICATION

/** \def TF_PSA_CRYPTO_AES_ROM_TABLES
 *
 * Use precomputed AES tables stored in ROM.
 *
 * Uncomment this macro to use precomputed AES tables stored in ROM.
 * Comment this macro to generate AES tables in RAM at runtime.
 *
 * Tradeoff: Using precomputed ROM tables reduces RAM usage by ~8kb
 * (or ~2kb if \c TF_PSA_CRYPTO_AES_FEWER_TABLES is used) and reduces the
 * initialization time before the first AES operation can be performed.
 * It comes at the cost of additional ~8kb ROM use (resp. ~2kb if \c
 * TF_PSA_CRYPTO_AES_FEWER_TABLES below is used), and potentially degraded
 * performance if ROM access is slower than RAM access.
 *
 * This option is independent of \c TF_PSA_CRYPTO_AES_FEWER_TABLES.
 *
 */
//#define TF_PSA_CRYPTO_AES_ROM_TABLES

/** \def TF_PSA_CRYPTO_AES_FEWER_TABLES
 *
 * Use less ROM/RAM for AES tables.
 *
 * Uncommenting this macro omits 75% of the AES tables from
 * ROM / RAM (depending on the value of \c TF_PSA_CRYPTO_AES_ROM_TABLES)
 * by computing their values on the fly during operations
 * (the tables are entry-wise rotations of one another).
 *
 * Tradeoff: Uncommenting this reduces the RAM / ROM footprint
 * by ~6kb but at the cost of more arithmetic operations during
 * runtime. Specifically, one has to compare 4 accesses within
 * different tables to 4 accesses with additional arithmetic
 * operations within the same table. The performance gain/loss
 * depends on the system and memory details.
 *
 * This option is independent of \c TF_PSA_CRYPTO_AES_ROM_TABLES.
 *
 */
//#define TF_PSA_CRYPTO_AES_FEWER_TABLES

/** \def TF_PSA_CRYPTO_CAMELLIA_SMALL_MEMORY
 *
 * Use less ROM for the Camellia implementation (saves about 768 bytes).
 *
 * Uncomment this macro to use less memory for Camellia.
 */
//#define TF_PSA_CRYPTO_CAMELLIA_SMALL_MEMORY

/** \def TF_PSA_CRYPTO_ECP_NIST_OPTIM
 *
 * Enable specific 'modulo p' routines for each NIST prime.
 * Depending on the prime and architecture, makes operations 4 to 8 times
 * faster on the corresponding curve.
 *
 * Comment this macro to disable NIST curves optimisation.
 */
#define TF_PSA_CRYPTO_ECP_NIST_OPTIM

/** \def TF_PSA_CRYPTO_SHA256_SMALLER
 *
 * Enable an implementation of SHA-256 that has lower ROM footprint but also
 * lower performance.
 *
 * The default implementation is meant to be a reasonable compromise between
 * performance and size. This version optimizes more aggressively for size at
 * the expense of performance. Eg on Cortex-M4 it reduces the size of
 * mbedtls_sha256_process() from ~2KB to ~0.5KB for a performance hit of about
 * 30%.
 *
 * Uncomment to enable the smaller implementation of SHA256.
 */
//#define TF_PSA_CRYPTO_SHA256_SMALLER

/** \def TF_PSA_CRYPTO_SHA512_SMALLER
 *
 * Enable an implementation of SHA-512 that has lower ROM footprint but also
 * lower performance.
 *
 * Uncomment to enable the smaller implementation of SHA512.
 */
//#define TF_PSA_CRYPTO_SHA512_SMALLER

/** \} name SECTION: PSA driver interface implementation configuration options */

/**
 * \name SECTION: Configuration of cryptographic algorithms and mechanisms
 * beyond the current PSA cryptography API.
 *
 * \{
 */

/**
 * \def TF_PSA_CRYPTO_WANT_LMS
 *
 * Enable the LMS stateful-hash asymmetric signature algorithm.
 *
 * Comment to disable the LMS verification algorithm and public key operations.
 */
#define TF_PSA_CRYPTO_WANT_LMS

/** \} name SECTION: Configuration of cryptographic algorithms and mechanisms not
 * planned to be supported in medium term by the PSA cryptography API */

#endif /* TF_PSA_CRYPTO_CONFIG_H */

/*
 *  Benchmark demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "tf-psa-crypto/build_info.h"

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_HAVE_TIME)
int main(void)
{
    mbedtls_printf("MBEDTLS_HAVE_TIME not defined.\n");
    mbedtls_exit(0);
}
#else

#include <string.h>
#include <stdlib.h>

#include "psa/crypto.h"
#include "psa/crypto_extra.h"

#include "mbedtls/private/md5.h"
#include "mbedtls/private/ripemd160.h"
#include "mbedtls/private/sha1.h"
#include "mbedtls/private/sha256.h"
#include "mbedtls/private/sha512.h"
#include "mbedtls/private/sha3.h"

#include "mbedtls/private/aes.h"
#include "mbedtls/private/aria.h"
#include "mbedtls/private/camellia.h"
#include "mbedtls/private/chacha20.h"
#include "mbedtls/private/gcm.h"
#include "mbedtls/private/ccm.h"
#include "mbedtls/private/chachapoly.h"
#include "mbedtls/private/cmac.h"
#include "mbedtls/private/poly1305.h"

#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/private/hmac_drbg.h"

#include "mbedtls/private/rsa.h"
#include "mbedtls/private/ecdsa.h"

#include "mbedtls/private/error_common.h"

/* *INDENT-OFF* */
#ifndef asm
#define asm __asm
#endif
/* *INDENT-ON* */

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#include <windows.h>
#include <process.h>

struct _hr_time {
    LARGE_INTEGER start;
};

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>

struct _hr_time {
    struct timeval start;
};

#endif /* _WIN32 && !EFIX64 && !EFI32 */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef MBEDTLS_TIMING_ALT
void mbedtls_set_alarm(int seconds);
unsigned long mbedtls_timing_hardclock(void);
extern volatile int mbedtls_timing_alarmed;
#else
static void mbedtls_set_alarm(int seconds);
static unsigned long mbedtls_timing_hardclock(void);
#endif

/*
 * For heap usage estimates, we need an estimate of the overhead per allocated
 * block. ptmalloc2/3 (used in gnu libc for instance) uses 2 size_t per block,
 * so use that as our baseline.
 */
#define MEM_BLOCK_OVERHEAD  (2 * sizeof(size_t))

/*
 * Size to use for the alloc buffer if MEMORY_BUFFER_ALLOC_C is defined.
 */
#define HEAP_SIZE       (1u << 16)  /* 64k */

#define BUFSIZE         1024
#define HEADER_FORMAT   "  %-24s :  "
#define TITLE_LEN       25

#define OPTIONS                                                              \
    "md5, ripemd160, sha1, sha256, sha512,\n"                                \
    "sha3_224, sha3_256, sha3_384, sha3_512,\n"                              \
    "camellia, chacha20,\n"                                       \
    "aes_cbc, aes_cfb128, aes_cfb8, aes_gcm, aes_ccm, aes_xts, chachapoly\n" \
    "aes_cmac, poly1305\n"                                        \
    "ctr_drbg, hmac_drbg\n"                                                  \
    "rsa, ecdsa, ecdh, ffdh.\n"

#if defined(MBEDTLS_ERROR_C)
#define PRINT_ERROR                                                     \
    mbedtls_printf("Error code: %d", ret);
/* mbedtls_strerror(ret, (char *) tmp, sizeof(tmp));          \
   mbedtls_printf("FAILED: %s\n", tmp); */
#else
#define PRINT_ERROR                                                     \
    mbedtls_printf("FAILED: -0x%04x\n", (unsigned int) -ret);
#endif

#define TIME_AND_TSC(TITLE, CODE)                                     \
    do {                                                                    \
        unsigned long ii, jj, tsc;                                          \
        int ret = 0;                                                        \
                                                                        \
        mbedtls_printf(HEADER_FORMAT, TITLE);                             \
        fflush(stdout);                                                   \
                                                                        \
        mbedtls_set_alarm(1);                                             \
        for (ii = 1; ret == 0 && !mbedtls_timing_alarmed; ii++)           \
        {                                                                   \
            ret = CODE;                                                     \
        }                                                                   \
                                                                        \
        tsc = mbedtls_timing_hardclock();                                   \
        for (jj = 0; ret == 0 && jj < 1024; jj++)                          \
        {                                                                   \
            ret = CODE;                                                     \
        }                                                                   \
                                                                        \
        if (ret != 0)                                                      \
        {                                                                   \
            PRINT_ERROR;                                                    \
        }                                                                   \
        else                                                                \
        {                                                                   \
            mbedtls_printf("%9lu KiB/s,  %9lu cycles/byte\n",              \
                           ii * BUFSIZE / 1024,                           \
                           (mbedtls_timing_hardclock() - tsc)           \
                           / (jj * BUFSIZE));                          \
        }                                                                   \
    } while (0)

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)

/* How much space to reserve for the title when printing heap usage results.
 * Updated manually as the output of the following command:
 *
 *  sed -n 's/.*[T]IME_PUBLIC.*"\(.*\)",/\1/p' programs/test/benchmark.c |
 *      awk '{print length+3}' | sort -rn | head -n1
 *
 * This computes the maximum length of a title +3, because we appends "/s" and
 * want at least one space. (If the value is too small, the only consequence
 * is poor alignment.) */
#define TITLE_SPACE 17

#define MEMORY_MEASURE_INIT                                             \
    size_t max_used, max_blocks, max_bytes;                             \
    size_t prv_used, prv_blocks;                                        \
    size_t alloc_cnt, free_cnt, prv_alloc, prv_free;                    \
    mbedtls_memory_buffer_alloc_cur_get(&prv_used, &prv_blocks);      \
    mbedtls_memory_buffer_alloc_max_reset();

#define MEMORY_MEASURE_RESET                                            \
    mbedtls_memory_buffer_alloc_count_get(&prv_alloc, &prv_free);

#define MEMORY_MEASURE_PRINT(title_len)                               \
    mbedtls_memory_buffer_alloc_max_get(&max_used, &max_blocks);      \
    mbedtls_memory_buffer_alloc_count_get(&alloc_cnt, &free_cnt);     \
    ii = TITLE_SPACE > (title_len) ? TITLE_SPACE - (title_len) : 1;     \
    while (ii--) mbedtls_printf(" ");                                \
    max_used -= prv_used;                                               \
    max_blocks -= prv_blocks;                                           \
    max_bytes = max_used + MEM_BLOCK_OVERHEAD * max_blocks;             \
    mbedtls_printf("%6u heap bytes, %6u allocs",                       \
                   (unsigned) max_bytes,                               \
                   (unsigned) (alloc_cnt - prv_alloc));

#else
#define MEMORY_MEASURE_INIT
#define MEMORY_MEASURE_RESET
#define MEMORY_MEASURE_PRINT(title_len)
#endif

#define TIME_PUBLIC(TITLE, TYPE, CODE)                                \
    do {                                                                    \
        unsigned long ii;                                                   \
        int ret;                                                            \
        MEMORY_MEASURE_INIT;                                                \
                                                                        \
        mbedtls_printf(HEADER_FORMAT, TITLE);                             \
        fflush(stdout);                                                   \
        mbedtls_set_alarm(3);                                             \
                                                                        \
        ret = 0;                                                            \
        for (ii = 1; !mbedtls_timing_alarmed && !ret; ii++)             \
        {                                                                   \
            MEMORY_MEASURE_RESET;                                           \
            CODE;                                                           \
        }                                                                   \
                                                                        \
        if (ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED)               \
        {                                                                   \
            mbedtls_printf("Feature Not Supported. Skipping.\n");         \
            ret = 0;                                                        \
        }                                                                   \
        else if (ret != 0)                                                 \
        {                                                                   \
            PRINT_ERROR;                                                    \
        }                                                                   \
        else                                                                \
        {                                                                   \
            mbedtls_printf("%6lu " TYPE "/s", ii / 3);                    \
            MEMORY_MEASURE_PRINT(sizeof(TYPE) + 1);                     \
            mbedtls_printf("\n");                                         \
        }                                                                   \
    } while (0)

#if !defined(MBEDTLS_TIMING_ALT)
#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    (defined(_MSC_VER) && defined(_M_IX86)) || defined(__WATCOMC__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tsc;
    __asm   rdtsc
    __asm   mov[tsc], eax
    return tsc;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          ( _MSC_VER && _M_IX86 ) || __WATCOMC__ */

/* some versions of mingw-64 have 32-bit longs even on x84_64 */
#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__i386__) || (                       \
    (defined(__amd64__) || defined(__x86_64__)) && __SIZEOF_LONG__ == 4))

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return lo;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __i386__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__amd64__) || defined(__x86_64__))

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return lo | (hi << 32);
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __amd64__ || __x86_64__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__powerpc__) || defined(__ppc__))

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tbl, tbu0, tbu1;

    do {
        asm volatile ("mftbu %0" : "=r" (tbu0));
        asm volatile ("mftb  %0" : "=r" (tbl));
        asm volatile ("mftbu %0" : "=r" (tbu1));
    } while (tbu0 != tbu1);

    return tbl;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __powerpc__ || __ppc__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc64__)

#if defined(__OpenBSD__)
#warning OpenBSD does not allow access to tick register using software version instead
#else
#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tick;
    asm volatile ("rdpr %%tick, %0;" : "=&r" (tick));
    return tick;
}
#endif /* __OpenBSD__ */
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc__) && !defined(__sparc64__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tick;
    asm volatile (".byte 0x83, 0x41, 0x00, 0x00");
    asm volatile ("mov   %%g1, %0" : "=r" (tick));
    return tick;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc__ && !__sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__alpha__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long cc;
    asm volatile ("rpcc %0" : "=r" (cc));
    return cc & 0xFFFFFFFF;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __alpha__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__ia64__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long itc;
    asm volatile ("mov %0 = ar.itc" : "=r" (itc));
    return itc;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __ia64__ */

#if !defined(HAVE_HARDCLOCK) && defined(_WIN32) && \
    !defined(EFIX64) && !defined(EFI32)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    LARGE_INTEGER offset;

    QueryPerformanceCounter(&offset);

    return (unsigned long) (offset.QuadPart);
}
#endif /* !HAVE_HARDCLOCK && _WIN32 && !EFIX64 && !EFI32 */

#if !defined(HAVE_HARDCLOCK)

#define HAVE_HARDCLOCK

static int hardclock_init = 0;
static mbedtls_ms_time_t ms_time_init;

static unsigned long mbedtls_timing_hardclock(void)
{
    if (hardclock_init == 0) {
        ms_time_init = mbedtls_ms_time();
        hardclock_init = 1;
    }

    mbedtls_ms_time_t now = mbedtls_ms_time();
    return now - ms_time_init;
}
#endif /* !HAVE_HARDCLOCK */

volatile int mbedtls_timing_alarmed = 0;

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

/* It's OK to use a global because alarm() is supposed to be global anyway */
static DWORD alarmMs;

static void TimerProc(void *TimerContext)
{
    (void) TimerContext;
    Sleep(alarmMs);
    mbedtls_timing_alarmed = 1;
    /* _endthread will be called implicitly on return
     * That ensures execution of thread function's epilogue */
}

static void mbedtls_set_alarm(int seconds)
{
    if (seconds == 0) {
        /* No need to create a thread for this simple case.
         * Also, this shorcut is more reliable at least on MinGW32 */
        mbedtls_timing_alarmed = 1;
        return;
    }

    mbedtls_timing_alarmed = 0;
    alarmMs = seconds * 1000;
    (void) _beginthread(TimerProc, 0, NULL);
}

#else /* _WIN32 && !EFIX64 && !EFI32 */

static void sighandler(int signum)
{
    mbedtls_timing_alarmed = 1;
    signal(signum, sighandler);
}

static void mbedtls_set_alarm(int seconds)
{
    mbedtls_timing_alarmed = 0;
    signal(SIGALRM, sighandler);
    alarm(seconds);
    if (seconds == 0) {
        /* alarm(0) cancelled any previous pending alarm, but the
           handler won't fire, so raise the flag straight away. */
        mbedtls_timing_alarmed = 1;
    }
}

#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !MBEDTLS_TIMING_ALT */

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    size_t use_len;
    int rnd;

    if (rng_state != NULL) {
        rng_state  = NULL;
    }

    while (len > 0) {
        use_len = len;
        if (use_len > sizeof(int)) {
            use_len = sizeof(int);
        }

        rnd = rand();
        memcpy(output, &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return 0;
}

#define CHECK_AND_CONTINUE(R)                                         \
    {                                                                   \
        int CHECK_AND_CONTINUE_ret = (R);                             \
        if (CHECK_AND_CONTINUE_ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED) { \
            mbedtls_printf("Feature not supported. Skipping.\n");     \
            continue;                                                   \
        }                                                               \
        else if (CHECK_AND_CONTINUE_ret != 0) {                        \
            mbedtls_exit(1);                                          \
        }                                                               \
    }

#if defined(MBEDTLS_ECP_C)
static int set_ecp_curve(const char *string, mbedtls_ecp_curve_info *curve)
{
    const mbedtls_ecp_curve_info *found =
        mbedtls_ecp_curve_info_from_name(string);
    if (found != NULL) {
        *curve = *found;
        return 1;
    } else {
        return 0;
    }
}
#endif

#if defined(PSA_WANT_ALG_ECDH) || defined(PSA_WANT_ALG_FFDH)
/**
 * Benchmark parameters for a PSA key agreement family.
 *
 * Each entry describes one concrete benchmark target, such as an ECDH curve
 * or an RFC7919 FFDH group.
 */
typedef struct {
    const char *name;
    psa_key_type_t key_type;
    size_t key_bits;
    psa_algorithm_t alg;
} psa_key_agreement_benchmark_info;

/**
 * Translate PSA status codes into the benchmark program's error convention.
 *
 * The benchmark macros expect an integer return code and already treat
 * MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED as a "skip" condition.
 */
static int psa_status_to_benchmark_ret(psa_status_t status)
{
    if (status == PSA_SUCCESS) {
        return 0;
    }

    if (status == PSA_ERROR_NOT_SUPPORTED) {
        return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
    }

    return (int) status;
}

/**
 * Destroy a key used by the PSA benchmark helpers.
 *
 * This accepts an uninitialized key id and always resets the caller's handle
 * after a successful or failed destroy attempt.
 */
static int psa_destroy_benchmark_key(mbedtls_svc_key_id_t *key)
{
    if (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(*key) == 0) {
        return 0;
    }

    int ret = psa_status_to_benchmark_ret(psa_destroy_key(*key));
    *key = MBEDTLS_SVC_KEY_ID_INIT;
    return ret;
}

/**
 * Generate a key pair for one benchmark entry.
 *
 * The generated key must support raw key agreement. The benchmark also exports
 * the corresponding public key for use as peer input, which PSA allows
 * without widening the key's usage policy.
 */
static int psa_generate_benchmark_key(const psa_key_agreement_benchmark_info *info,
                                      mbedtls_svc_key_id_t *key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, info->alg);
    psa_set_key_type(&attributes, info->key_type);
    psa_set_key_bits(&attributes, info->key_bits);

    return psa_status_to_benchmark_ret(psa_generate_key(&attributes, key));
}

/**
 * Execute one raw PSA key agreement operation for benchmarking.
 *
 * When \p generate_private_key is non-zero, this function includes private-key
 * generation in the measured path. Otherwise it reuses \p private_key so the
 * timed operation covers only the key agreement call itself.
 */
static int psa_raw_key_agreement_benchmark_once(
    const psa_key_agreement_benchmark_info *info,
    mbedtls_svc_key_id_t private_key,
    int generate_private_key,
    const unsigned char *peer_key,
    size_t peer_key_length,
    unsigned char *output,
    size_t output_size)
{
    mbedtls_svc_key_id_t local_private_key = MBEDTLS_SVC_KEY_ID_INIT;
    size_t output_length;
    int ret;

    if (generate_private_key) {
        ret = psa_generate_benchmark_key(info, &local_private_key);
        if (ret != 0) {
            return ret;
        }

        private_key = local_private_key;
    }

    ret = psa_status_to_benchmark_ret(
        psa_raw_key_agreement(info->alg, private_key,
                              peer_key, peer_key_length,
                              output, output_size, &output_length));

    if (generate_private_key) {
        int destroy_ret = psa_destroy_benchmark_key(&local_private_key);
        if (ret == 0) {
            ret = destroy_ret;
        }
    }

    return ret;
}

/**
 * Print a benchmark entry as skipped because the primitive is unsupported.
 */
static void print_feature_not_supported(const char *title)
{
    mbedtls_printf(HEADER_FORMAT, title);
    mbedtls_printf("Feature Not Supported. Skipping.\n");
}

/**
 * Look up a benchmark entry by its command-line name.
 */
static int set_psa_key_agreement_name(const char *string,
                                      const psa_key_agreement_benchmark_info *table,
                                      const char **name)
{
    const psa_key_agreement_benchmark_info *info;

    for (info = table; info->name != NULL; info++) {
        if (strcmp(string, info->name) == 0) {
            *name = info->name;
            return 1;
        }
    }

    return 0;
}

/**
 * Benchmark a family of PSA key agreement parameters.
 *
 * For each entry in \p table, this function:
 * - generates a server key and exports its public key,
 * - times an ephemeral client path, where client key generation is included,
 * - times a static client path, where a pre-generated key is reused,
 * - prints results using the supplied title prefixes.
 *
 * The optional \p name_filter is used by the ECDH command-line path to keep
 * compatibility with the existing single-curve selection behaviour.
 */
static void benchmark_psa_key_agreement(
    const psa_key_agreement_benchmark_info *table,
    const char *ephemeral_prefix,
    const char *static_prefix,
    const char *name_filter,
    unsigned char *peer_key,
    size_t peer_key_size,
    unsigned char *shared_secret,
    size_t shared_secret_size)
{
    const psa_key_agreement_benchmark_info *info;

    for (info = table; info->name != NULL; info++) {
        size_t peer_key_length;
        mbedtls_svc_key_id_t server_key = MBEDTLS_SVC_KEY_ID_INIT;
        mbedtls_svc_key_id_t client_key = MBEDTLS_SVC_KEY_ID_INIT;
        char title[TITLE_LEN];
        int setup_ret;

        if (name_filter != NULL && strcmp(name_filter, info->name) != 0) {
            continue;
        }

        /* Generate the peer key once and export its public part for both runs. */
        setup_ret = psa_generate_benchmark_key(info, &server_key);
        if (setup_ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED) {
            mbedtls_snprintf(title, sizeof(title), "%s%s",
                             ephemeral_prefix, info->name);
            print_feature_not_supported(title);
            mbedtls_snprintf(title, sizeof(title), "%s%s",
                             static_prefix, info->name);
            print_feature_not_supported(title);
            continue;
        } else if (setup_ret != 0) {
            mbedtls_exit(1);
        }

        setup_ret = psa_status_to_benchmark_ret(
            psa_export_public_key(server_key, peer_key, peer_key_size,
                                  &peer_key_length));
        if (setup_ret != 0) {
            (void) psa_destroy_benchmark_key(&server_key);
            mbedtls_exit(1);
        }

        mbedtls_snprintf(title, sizeof(title), "%s%s",
                         ephemeral_prefix, info->name);
        TIME_PUBLIC(title, "handshake",
                    ret = psa_raw_key_agreement_benchmark_once(
                        info, MBEDTLS_SVC_KEY_ID_INIT, 1,
                        peer_key, peer_key_length,
                        shared_secret, shared_secret_size));

        /* Reuse a fixed client key so this pass measures agreement only. */
        setup_ret = psa_generate_benchmark_key(info, &client_key);
        if (setup_ret != 0) {
            (void) psa_destroy_benchmark_key(&server_key);
            mbedtls_exit(1);
        }

        mbedtls_snprintf(title, sizeof(title), "%s%s",
                         static_prefix, info->name);
        TIME_PUBLIC(title, "handshake",
                    ret = psa_raw_key_agreement_benchmark_once(
                        info, client_key, 0,
                        peer_key, peer_key_length,
                        shared_secret, shared_secret_size));

        setup_ret = psa_destroy_benchmark_key(&client_key);
        if (setup_ret != 0) {
            (void) psa_destroy_benchmark_key(&server_key);
            mbedtls_exit(1);
        }

        setup_ret = psa_destroy_benchmark_key(&server_key);
        if (setup_ret != 0) {
            mbedtls_exit(1);
        }
    }
}

#endif /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */

#if defined(PSA_WANT_ALG_ECDH)
/** ECDH benchmark targets enabled in the current PSA configuration. */
static const psa_key_agreement_benchmark_info ecdh_benchmark_table[] = {
#if defined(PSA_WANT_ECC_SECP_K1_256)
    { "secp256k1", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1),
      256, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_256)
    { "secp256r1", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
      256, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
    { "secp384r1", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
      384, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_521)
    { "secp521r1", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
      521, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
    { "brainpoolP256r1",
      PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1),
      256, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
    { "brainpoolP384r1",
      PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1),
      384, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
    { "brainpoolP512r1",
      PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1),
      512, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_MONTGOMERY_255)
    { "curve25519", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY),
      255, PSA_ALG_ECDH },
#endif
#if defined(PSA_WANT_ECC_MONTGOMERY_448)
    { "curve448", PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY),
      448, PSA_ALG_ECDH },
#endif
    { NULL, 0, 0, 0 }
};

/**
 * Benchmark ECDH using ECC-sized scratch buffers.
 *
 * Using ECC-specific buffers keeps the ECDH stack usage independent from the
 * largest enabled FFDH group, which is useful on constrained targets.
 */
static void benchmark_psa_ecdh(const char *name_filter)
{
    unsigned char peer_key[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    unsigned char shared_secret[PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS)];

    benchmark_psa_key_agreement(ecdh_benchmark_table,
                                "ECDHE-", "ECDH-",
                                name_filter,
                                peer_key, sizeof(peer_key),
                                shared_secret, sizeof(shared_secret));
}
#endif

#if defined(PSA_WANT_ALG_FFDH)
/** FFDH benchmark targets enabled in the current PSA configuration. */
static const psa_key_agreement_benchmark_info ffdh_benchmark_table[] = {
#if defined(PSA_WANT_DH_RFC7919_2048)
    { "2048", PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919),
      2048, PSA_ALG_FFDH },
#endif
#if defined(PSA_WANT_DH_RFC7919_3072)
    { "3072", PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919),
      3072, PSA_ALG_FFDH },
#endif
#if defined(PSA_WANT_DH_RFC7919_4096)
    { "4096", PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919),
      4096, PSA_ALG_FFDH },
#endif
#if defined(PSA_WANT_DH_RFC7919_6144)
    { "6144", PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919),
      6144, PSA_ALG_FFDH },
#endif
#if defined(PSA_WANT_DH_RFC7919_8192)
    { "8192", PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919),
      8192, PSA_ALG_FFDH },
#endif
    { NULL, 0, 0, 0 }
};

/**
 * Benchmark FFDH using group-sized scratch buffers.
 */
static void benchmark_psa_ffdh(const char *name_filter)
{
    unsigned char peer_key[PSA_KEY_EXPORT_FFDH_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_FFDH_MAX_KEY_BITS)];
    unsigned char shared_secret[PSA_BITS_TO_BYTES(PSA_VENDOR_FFDH_MAX_KEY_BITS)];

    benchmark_psa_key_agreement(ffdh_benchmark_table,
                                "FFDHE-", "FFDH-",
                                name_filter,
                                peer_key, sizeof(peer_key),
                                shared_secret, sizeof(shared_secret));
}
#endif

unsigned char buf[BUFSIZE];

typedef struct {
    char md5, ripemd160, sha1, sha256, sha512,
         sha3_224, sha3_256, sha3_384, sha3_512,
         aes_cbc, aes_cfb128, aes_cfb8, aes_ctr, aes_gcm, aes_ccm, aes_xts, chachapoly,
         aes_cmac,
         aria, camellia, chacha20,
         poly1305,
         ctr_drbg, hmac_drbg,
         rsa, ecdsa, ecdh, ffdh;
} todo_list;


int main(int argc, char *argv[])
{
    int i;
    unsigned char tmp[200];
    char title[TITLE_LEN];
    todo_list todo;
#if defined(PSA_WANT_ALG_ECDH)
    const char *selected_ecdh_curve = NULL;
#endif
#if defined(PSA_WANT_ALG_FFDH)
    const char *selected_ffdh_group = NULL;
#endif
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[HEAP_SIZE] = { 0 };
#endif
#if defined(MBEDTLS_ECP_C)
    mbedtls_ecp_curve_info single_curve[2] = {
        { MBEDTLS_ECP_DP_NONE, 0, 0, NULL },
        { MBEDTLS_ECP_DP_NONE, 0, 0, NULL },
    };
    const mbedtls_ecp_curve_info *curve_list = mbedtls_ecp_curve_list();
#endif

#if defined(MBEDTLS_ECP_C)
    (void) curve_list; /* Unused in some configurations where no benchmark uses ECC */
#endif

    if (argc <= 1) {
        memset(&todo, 1, sizeof(todo));
    } else {
        memset(&todo, 0, sizeof(todo));

        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "md5") == 0) {
                todo.md5 = 1;
            } else if (strcmp(argv[i], "ripemd160") == 0) {
                todo.ripemd160 = 1;
            } else if (strcmp(argv[i], "sha1") == 0) {
                todo.sha1 = 1;
            } else if (strcmp(argv[i], "sha256") == 0) {
                todo.sha256 = 1;
            } else if (strcmp(argv[i], "sha512") == 0) {
                todo.sha512 = 1;
            } else if (strcmp(argv[i], "sha3_224") == 0) {
                todo.sha3_224 = 1;
            } else if (strcmp(argv[i], "sha3_256") == 0) {
                todo.sha3_256 = 1;
            } else if (strcmp(argv[i], "sha3_384") == 0) {
                todo.sha3_384 = 1;
            } else if (strcmp(argv[i], "sha3_512") == 0) {
                todo.sha3_512 = 1;
            } else if (strcmp(argv[i], "aes_cbc") == 0) {
                todo.aes_cbc = 1;
            } else if (strcmp(argv[i], "aes_cfb128") == 0) {
                todo.aes_cfb128 = 1;
            } else if (strcmp(argv[i], "aes_cfb8") == 0) {
                todo.aes_cfb8 = 1;
            } else if (strcmp(argv[i], "aes_ctr") == 0) {
                todo.aes_ctr = 1;
            } else if (strcmp(argv[i], "aes_xts") == 0) {
                todo.aes_xts = 1;
            } else if (strcmp(argv[i], "aes_gcm") == 0) {
                todo.aes_gcm = 1;
            } else if (strcmp(argv[i], "aes_ccm") == 0) {
                todo.aes_ccm = 1;
            } else if (strcmp(argv[i], "chachapoly") == 0) {
                todo.chachapoly = 1;
            } else if (strcmp(argv[i], "aes_cmac") == 0) {
                todo.aes_cmac = 1;
            } else if (strcmp(argv[i], "aria") == 0) {
                todo.aria = 1;
            } else if (strcmp(argv[i], "camellia") == 0) {
                todo.camellia = 1;
            } else if (strcmp(argv[i], "chacha20") == 0) {
                todo.chacha20 = 1;
            } else if (strcmp(argv[i], "poly1305") == 0) {
                todo.poly1305 = 1;
            } else if (strcmp(argv[i], "ctr_drbg") == 0) {
                todo.ctr_drbg = 1;
            } else if (strcmp(argv[i], "hmac_drbg") == 0) {
                todo.hmac_drbg = 1;
            } else if (strcmp(argv[i], "rsa") == 0) {
                todo.rsa = 1;
            } else if (strcmp(argv[i], "ecdsa") == 0) {
                todo.ecdsa = 1;
            } else if (strcmp(argv[i], "ecdh") == 0) {
                todo.ecdh = 1;
            } else if (strcmp(argv[i], "ffdh") == 0) {
                todo.ffdh = 1;
            } else {
                int handled = 0;

#if defined(MBEDTLS_ECP_C)
                if (set_ecp_curve(argv[i], single_curve)) {
                    curve_list = single_curve;
#if defined(PSA_WANT_ALG_ECDH)
                    selected_ecdh_curve = single_curve[0].name;
#endif
                    handled = 1;
                }
#endif

#if defined(PSA_WANT_ALG_ECDH)
                if (!handled &&
                    set_psa_key_agreement_name(argv[i], ecdh_benchmark_table,
                                               &selected_ecdh_curve)) {
                    handled = 1;
                }
#endif

#if defined(PSA_WANT_ALG_FFDH)
                if (!handled &&
                    set_psa_key_agreement_name(argv[i], ffdh_benchmark_table,
                                               &selected_ffdh_group)) {
                    handled = 1;
                }
#endif

                if (!handled) {
                    mbedtls_printf("Unrecognized option: %s\n", argv[i]);
                    mbedtls_printf("Available options: " OPTIONS);
                }
            }
        }
    }

    mbedtls_printf("\n");

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif
    memset(buf, 0xAA, sizeof(buf));
    memset(tmp, 0xBB, sizeof(tmp));

    if (psa_crypto_init() != PSA_SUCCESS) {
        mbedtls_exit(1);
    }

    /* Avoid "unused static function" warning in configurations without
     * symmetric crypto. */
    (void) mbedtls_timing_hardclock;

#if defined(MBEDTLS_MD5_C)
    if (todo.md5) {
        TIME_AND_TSC("MD5", mbedtls_md5(buf, BUFSIZE, tmp));
    }
#endif

#if defined(MBEDTLS_RIPEMD160_C)
    if (todo.ripemd160) {
        TIME_AND_TSC("RIPEMD160", mbedtls_ripemd160(buf, BUFSIZE, tmp));
    }
#endif

#if defined(MBEDTLS_SHA1_C)
    if (todo.sha1) {
        TIME_AND_TSC("SHA-1", mbedtls_sha1(buf, BUFSIZE, tmp));
    }
#endif

#if defined(MBEDTLS_SHA256_C)
    if (todo.sha256) {
        TIME_AND_TSC("SHA-256", mbedtls_sha256(buf, BUFSIZE, tmp, 0));
    }
#endif

#if defined(MBEDTLS_SHA512_C)
    if (todo.sha512) {
        TIME_AND_TSC("SHA-512", mbedtls_sha512(buf, BUFSIZE, tmp, 0));
    }
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA3_224)
    if (todo.sha3_224) {
        TIME_AND_TSC("SHA3-224", mbedtls_sha3(MBEDTLS_SHA3_224, buf, BUFSIZE, tmp, 28));
    }
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA3_256)
    if (todo.sha3_256) {
        TIME_AND_TSC("SHA3-256", mbedtls_sha3(MBEDTLS_SHA3_256, buf, BUFSIZE, tmp, 32));
    }
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA3_384)
    if (todo.sha3_384) {
        TIME_AND_TSC("SHA3-384", mbedtls_sha3(MBEDTLS_SHA3_384, buf, BUFSIZE, tmp, 48));
    }
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
    if (todo.sha3_512) {
        TIME_AND_TSC("SHA3-512", mbedtls_sha3(MBEDTLS_SHA3_512, buf, BUFSIZE, tmp, 64));
    }
#endif


#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if (todo.aes_cbc) {
        int keysize;
        mbedtls_aes_context aes;

        mbedtls_aes_init(&aes);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-CBC-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            CHECK_AND_CONTINUE(mbedtls_aes_setkey_enc(&aes, tmp, keysize));

            TIME_AND_TSC(title,
                         mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, BUFSIZE, tmp, buf, buf));
        }
        mbedtls_aes_free(&aes);
    }
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    if (todo.aes_cfb128) {
        int keysize;
        size_t iv_off = 0;
        mbedtls_aes_context aes;

        mbedtls_aes_init(&aes);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-CFB128-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            CHECK_AND_CONTINUE(mbedtls_aes_setkey_enc(&aes, tmp, keysize));

            TIME_AND_TSC(title,
                         mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, BUFSIZE,
                                                  &iv_off, tmp, buf, buf));
        }
        mbedtls_aes_free(&aes);
    }
    if (todo.aes_cfb8) {
        int keysize;
        mbedtls_aes_context aes;

        mbedtls_aes_init(&aes);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-CFB8-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            CHECK_AND_CONTINUE(mbedtls_aes_setkey_enc(&aes, tmp, keysize));

            TIME_AND_TSC(title,
                         mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_ENCRYPT, BUFSIZE, tmp, buf, buf));
        }
        mbedtls_aes_free(&aes);
    }
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    if (todo.aes_ctr) {
        int keysize;
        mbedtls_aes_context aes;

        uint8_t stream_block[16];
        size_t nc_off;

        mbedtls_aes_init(&aes);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-CTR-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            memset(stream_block, 0, sizeof(stream_block));
            nc_off = 0;

            CHECK_AND_CONTINUE(mbedtls_aes_setkey_enc(&aes, tmp, keysize));

            TIME_AND_TSC(title, mbedtls_aes_crypt_ctr(&aes, BUFSIZE, &nc_off, tmp, stream_block,
                                                      buf, buf));
        }
        mbedtls_aes_free(&aes);
    }
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    if (todo.aes_xts) {
        int keysize;
        mbedtls_aes_xts_context ctx;

        mbedtls_aes_xts_init(&ctx);
        for (keysize = 128; keysize <= 256; keysize += 128) {
            mbedtls_snprintf(title, sizeof(title), "AES-XTS-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            CHECK_AND_CONTINUE(mbedtls_aes_xts_setkey_enc(&ctx, tmp, keysize * 2));

            TIME_AND_TSC(title,
                         mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_ENCRYPT, BUFSIZE,
                                               tmp, buf, buf));

            mbedtls_aes_xts_free(&ctx);
        }
    }
#endif
#if defined(MBEDTLS_GCM_C)
    if (todo.aes_gcm) {
        int keysize;
        mbedtls_gcm_context gcm;

        mbedtls_gcm_init(&gcm);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-GCM-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, tmp, keysize);

            TIME_AND_TSC(title,
                         mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, BUFSIZE, tmp,
                                                   12, NULL, 0, buf, buf, 16, tmp));

            mbedtls_gcm_free(&gcm);
        }
    }
#endif
#if defined(MBEDTLS_CCM_C)
    if (todo.aes_ccm) {
        int keysize;
        mbedtls_ccm_context ccm;

        mbedtls_ccm_init(&ccm);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-CCM-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, tmp, keysize);

            TIME_AND_TSC(title,
                         mbedtls_ccm_encrypt_and_tag(&ccm, BUFSIZE, tmp,
                                                     12, NULL, 0, buf, buf, tmp, 16));

            mbedtls_ccm_free(&ccm);
        }
    }
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    if (todo.chachapoly) {
        mbedtls_chachapoly_context chachapoly;

        mbedtls_chachapoly_init(&chachapoly);
        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        mbedtls_snprintf(title, sizeof(title), "ChaCha20-Poly1305");

        mbedtls_chachapoly_setkey(&chachapoly, tmp);

        TIME_AND_TSC(title,
                     mbedtls_chachapoly_encrypt_and_tag(&chachapoly,
                                                        BUFSIZE, tmp, NULL, 0, buf, buf, tmp));

        mbedtls_chachapoly_free(&chachapoly);
    }
#endif
#if defined(MBEDTLS_CMAC_C)
    if (todo.aes_cmac) {
        unsigned char output[16];
        const mbedtls_cipher_info_t *cipher_info;
        mbedtls_cipher_type_t cipher_type;
        int keysize;

        for (keysize = 128, cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
             keysize <= 256;
             keysize += 64, cipher_type++) {
            mbedtls_snprintf(title, sizeof(title), "AES-CMAC-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));

            cipher_info = mbedtls_cipher_info_from_type(cipher_type);

            TIME_AND_TSC(title,
                         mbedtls_cipher_cmac(cipher_info, tmp, keysize,
                                             buf, BUFSIZE, output));
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));
        TIME_AND_TSC("AES-CMAC-PRF-128",
                     mbedtls_aes_cmac_prf_128(tmp, 16, buf, BUFSIZE,
                                              output));
    }
#endif /* MBEDTLS_CMAC_C */
#endif /* MBEDTLS_AES_C */

#if defined(MBEDTLS_ARIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (todo.aria) {
        int keysize;
        mbedtls_aria_context aria;

        mbedtls_aria_init(&aria);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "ARIA-CBC-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            mbedtls_aria_setkey_enc(&aria, tmp, keysize);

            TIME_AND_TSC(title,
                         mbedtls_aria_crypt_cbc(&aria, MBEDTLS_ARIA_ENCRYPT,
                                                BUFSIZE, tmp, buf, buf));
        }
        mbedtls_aria_free(&aria);
    }
#endif

#if defined(MBEDTLS_CAMELLIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (todo.camellia) {
        int keysize;
        mbedtls_camellia_context camellia;

        mbedtls_camellia_init(&camellia);
        for (keysize = 128; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "CAMELLIA-CBC-%d", keysize);

            memset(buf, 0, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            mbedtls_camellia_setkey_enc(&camellia, tmp, keysize);

            TIME_AND_TSC(title,
                         mbedtls_camellia_crypt_cbc(&camellia, MBEDTLS_CAMELLIA_ENCRYPT,
                                                    BUFSIZE, tmp, buf, buf));
        }
        mbedtls_camellia_free(&camellia);
    }
#endif

#if defined(MBEDTLS_CHACHA20_C)
    if (todo.chacha20) {
        TIME_AND_TSC("ChaCha20", mbedtls_chacha20_crypt(buf, buf, 0U, BUFSIZE, buf, buf));
    }
#endif

#if defined(MBEDTLS_POLY1305_C)
    if (todo.poly1305) {
        TIME_AND_TSC("Poly1305", mbedtls_poly1305_mac(buf, buf, BUFSIZE, buf));
    }
#endif

#if defined(MBEDTLS_CTR_DRBG_C)
    if (todo.ctr_drbg) {
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_ctr_drbg_init(&ctr_drbg);
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        TIME_AND_TSC("CTR_DRBG (NOPR)",
                     mbedtls_ctr_drbg_random(&ctr_drbg, buf, BUFSIZE));
        mbedtls_ctr_drbg_free(&ctr_drbg);

        mbedtls_ctr_drbg_init(&ctr_drbg);
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);
        TIME_AND_TSC("CTR_DRBG (PR)",
                     mbedtls_ctr_drbg_random(&ctr_drbg, buf, BUFSIZE));
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
#endif

#if defined(MBEDTLS_HMAC_DRBG_C) && \
    (defined(MBEDTLS_SHA1_C) || defined(MBEDTLS_SHA256_C))
    if (todo.hmac_drbg) {
        mbedtls_hmac_drbg_context hmac_drbg;
        const mbedtls_md_info_t *md_info;

        mbedtls_hmac_drbg_init(&hmac_drbg);

#if defined(MBEDTLS_SHA1_C)
        if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)) == NULL) {
            mbedtls_exit(1);
        }

        if (mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        TIME_AND_TSC("HMAC_DRBG SHA-1 (NOPR)",
                     mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));

        if (mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        mbedtls_hmac_drbg_set_prediction_resistance(&hmac_drbg,
                                                    MBEDTLS_HMAC_DRBG_PR_ON);
        TIME_AND_TSC("HMAC_DRBG SHA-1 (PR)",
                     mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));
#endif

#if defined(MBEDTLS_SHA256_C)
        if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL) {
            mbedtls_exit(1);
        }

        if (mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        TIME_AND_TSC("HMAC_DRBG SHA-256 (NOPR)",
                     mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));

        if (mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        mbedtls_hmac_drbg_set_prediction_resistance(&hmac_drbg,
                                                    MBEDTLS_HMAC_DRBG_PR_ON);
        TIME_AND_TSC("HMAC_DRBG SHA-256 (PR)",
                     mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));
#endif
        mbedtls_hmac_drbg_free(&hmac_drbg);
    }
#endif /* MBEDTLS_HMAC_DRBG_C && ( MBEDTLS_SHA1_C || MBEDTLS_SHA256_C ) */

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if (todo.rsa) {
        int keysize;
        mbedtls_rsa_context rsa;

        for (keysize = 2048; keysize <= 4096; keysize += 1024) {
            mbedtls_snprintf(title, sizeof(title), "RSA-%d", keysize);

            mbedtls_rsa_init(&rsa);
            mbedtls_rsa_gen_key(&rsa, myrand, NULL, keysize, 65537);

            TIME_PUBLIC(title, " public",
                        buf[0] = 0;
                        ret = mbedtls_rsa_public(&rsa, buf, buf));

            TIME_PUBLIC(title, "private",
                        buf[0] = 0;
                        ret = mbedtls_rsa_private(&rsa, myrand, NULL, buf, buf));

            mbedtls_rsa_free(&rsa);
        }
    }
#endif

#if defined(PSA_WANT_ALG_FFDH)
    if (todo.ffdh) {
        benchmark_psa_ffdh(selected_ffdh_group);
    }
#endif

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_SHA256_C)
    if (todo.ecdsa) {
        mbedtls_ecdsa_context ecdsa;
        const mbedtls_ecp_curve_info *curve_info;
        size_t sig_len;

        memset(buf, 0x2A, sizeof(buf));

        for (curve_info = curve_list;
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++) {
            if (!mbedtls_ecdsa_can_do(curve_info->grp_id)) {
                continue;
            }

            mbedtls_ecdsa_init(&ecdsa);

            if (mbedtls_ecdsa_genkey(&ecdsa, curve_info->grp_id, myrand, NULL) != 0) {
                mbedtls_exit(1);
            }

            mbedtls_snprintf(title, sizeof(title), "ECDSA-%s",
                             curve_info->name);
            TIME_PUBLIC(title,
                        "sign",
                        ret =
                            mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, buf,
                                                          curve_info->bit_size,
                                                          tmp, sizeof(tmp), &sig_len, myrand,
                                                          NULL));

            mbedtls_ecdsa_free(&ecdsa);
        }

        for (curve_info = curve_list;
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++) {
            if (!mbedtls_ecdsa_can_do(curve_info->grp_id)) {
                continue;
            }

            mbedtls_ecdsa_init(&ecdsa);

            if (mbedtls_ecdsa_genkey(&ecdsa, curve_info->grp_id, myrand, NULL) != 0 ||
                mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, buf, curve_info->bit_size,
                                              tmp, sizeof(tmp), &sig_len, myrand, NULL) != 0) {
                mbedtls_exit(1);
            }

            mbedtls_snprintf(title, sizeof(title), "ECDSA-%s",
                             curve_info->name);
            TIME_PUBLIC(title, "verify",
                        ret = mbedtls_ecdsa_read_signature(&ecdsa, buf, curve_info->bit_size,
                                                           tmp, sig_len));

            mbedtls_ecdsa_free(&ecdsa);
        }
    }
#endif

#if defined(PSA_WANT_ALG_ECDH)
    if (todo.ecdh) {
        benchmark_psa_ecdh(selected_ecdh_curve);
    }
#endif

    mbedtls_printf("\n");

    mbedtls_psa_crypto_free();
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif

    mbedtls_exit(0);
}

#endif /* MBEDTLS_HAVE_TIME */

/*
 *  Platform abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_PLATFORM_C)

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error_common.h"

/* The compile time configuration of memory allocation via the macros
 * MBEDTLS_PLATFORM_{FREE/CALLOC}_MACRO takes precedence over the runtime
 * configuration via mbedtls_platform_set_calloc_free(). So, omit everything
 * related to the latter if MBEDTLS_PLATFORM_{FREE/CALLOC}_MACRO are defined. */
#if defined(MBEDTLS_PLATFORM_MEMORY) &&                 \
    !(defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&        \
    defined(MBEDTLS_PLATFORM_FREE_MACRO))

#if !defined(MBEDTLS_PLATFORM_STD_CALLOC)
static void *platform_calloc_uninit(size_t n, size_t size)
{
    ((void) n);
    ((void) size);
    return NULL;
}

#define MBEDTLS_PLATFORM_STD_CALLOC   platform_calloc_uninit
#endif /* !MBEDTLS_PLATFORM_STD_CALLOC */

#if !defined(MBEDTLS_PLATFORM_STD_FREE)
static void platform_free_uninit(void *ptr)
{
    ((void) ptr);
}

#define MBEDTLS_PLATFORM_STD_FREE     platform_free_uninit
#endif /* !MBEDTLS_PLATFORM_STD_FREE */

static void * (*mbedtls_calloc_func)(size_t, size_t) = MBEDTLS_PLATFORM_STD_CALLOC;
static void (*mbedtls_free_func)(void *) = MBEDTLS_PLATFORM_STD_FREE;

void *mbedtls_calloc(size_t nmemb, size_t size)
{
    return (*mbedtls_calloc_func)(nmemb, size);
}

void mbedtls_free(void *ptr)
{
    (*mbedtls_free_func)(ptr);
}

int mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
                                     void (*free_func)(void *))
{
    mbedtls_calloc_func = calloc_func;
    mbedtls_free_func = free_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_MEMORY &&
          !( defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&
             defined(MBEDTLS_PLATFORM_FREE_MACRO) ) */

#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
#include <stdarg.h>
int mbedtls_platform_win32_snprintf(char *s, size_t n, const char *fmt, ...)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    va_list argp;

    va_start(argp, fmt);
    ret = mbedtls_vsnprintf(s, n, fmt, argp);
    va_end(argp);

    return ret;
}
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_SNPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_snprintf_uninit(char *s, size_t n,
                                    const char *format, ...)
{
    ((void) s);
    ((void) n);
    ((void) format);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_SNPRINTF    platform_snprintf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_SNPRINTF */

int (*mbedtls_snprintf)(char *s, size_t n,
                        const char *format,
                        ...) = MBEDTLS_PLATFORM_STD_SNPRINTF;

int mbedtls_platform_set_snprintf(int (*snprintf_func)(char *s, size_t n,
                                                       const char *format,
                                                       ...))
{
    mbedtls_snprintf = snprintf_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_SNPRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#include <stdarg.h>
int mbedtls_platform_win32_vsnprintf(char *s, size_t n, const char *fmt, va_list arg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Avoid calling the invalid parameter handler by checking ourselves */
    if (s == NULL || n == 0 || fmt == NULL) {
        return -1;
    }

#if defined(_TRUNCATE)
    ret = vsnprintf_s(s, n, _TRUNCATE, fmt, arg);
#else
    ret = vsnprintf(s, n, fmt, arg);
    if (ret < 0 || (size_t) ret == n) {
        s[n-1] = '\0';
        ret = -1;
    }
#endif

    return ret;
}
#endif

#if defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_VSNPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_vsnprintf_uninit(char *s, size_t n,
                                     const char *format, va_list arg)
{
    ((void) s);
    ((void) n);
    ((void) format);
    ((void) arg);
    return -1;
}

#define MBEDTLS_PLATFORM_STD_VSNPRINTF    platform_vsnprintf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_VSNPRINTF */

int (*mbedtls_vsnprintf)(char *s, size_t n,
                         const char *format,
                         va_list arg) = MBEDTLS_PLATFORM_STD_VSNPRINTF;

int mbedtls_platform_set_vsnprintf(int (*vsnprintf_func)(char *s, size_t n,
                                                         const char *format,
                                                         va_list arg))
{
    mbedtls_vsnprintf = vsnprintf_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_VSNPRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_PRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_PRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_printf_uninit(const char *format, ...)
{
    ((void) format);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_PRINTF    platform_printf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_PRINTF */

int (*mbedtls_printf)(const char *, ...) = MBEDTLS_PLATFORM_STD_PRINTF;

int mbedtls_platform_set_printf(int (*printf_func)(const char *, ...))
{
    mbedtls_printf = printf_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_PRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_FPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_fprintf_uninit(FILE *stream, const char *format, ...)
{
    ((void) stream);
    ((void) format);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_FPRINTF   platform_fprintf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_FPRINTF */

int (*mbedtls_fprintf)(FILE *, const char *, ...) =
    MBEDTLS_PLATFORM_STD_FPRINTF;

int mbedtls_platform_set_fprintf(int (*fprintf_func)(FILE *, const char *, ...))
{
    mbedtls_fprintf = fprintf_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_FPRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_SETBUF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_SETBUF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static void platform_setbuf_uninit(FILE *stream, char *buf)
{
    ((void) stream);
    ((void) buf);
}

#define MBEDTLS_PLATFORM_STD_SETBUF   platform_setbuf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_SETBUF */
void (*mbedtls_setbuf)(FILE *stream, char *buf) = MBEDTLS_PLATFORM_STD_SETBUF;

int mbedtls_platform_set_setbuf(void (*setbuf_func)(FILE *stream, char *buf))
{
    mbedtls_setbuf = setbuf_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_SETBUF_ALT */

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_EXIT)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static void platform_exit_uninit(int status)
{
    ((void) status);
}

#define MBEDTLS_PLATFORM_STD_EXIT   platform_exit_uninit
#endif /* !MBEDTLS_PLATFORM_STD_EXIT */

void (*mbedtls_exit)(int status) = MBEDTLS_PLATFORM_STD_EXIT;

int mbedtls_platform_set_exit(void (*exit_func)(int status))
{
    mbedtls_exit = exit_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_EXIT_ALT */

#if defined(MBEDTLS_HAVE_TIME)

#if defined(MBEDTLS_PLATFORM_TIME_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_TIME)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static mbedtls_time_t platform_time_uninit(mbedtls_time_t *timer)
{
    ((void) timer);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_TIME   platform_time_uninit
#endif /* !MBEDTLS_PLATFORM_STD_TIME */

mbedtls_time_t (*mbedtls_time)(mbedtls_time_t *timer) = MBEDTLS_PLATFORM_STD_TIME;

int mbedtls_platform_set_time(mbedtls_time_t (*time_func)(mbedtls_time_t *timer))
{
    mbedtls_time = time_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#endif /* MBEDTLS_HAVE_TIME */

#if defined(MBEDTLS_ENTROPY_NV_SEED)
#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS) && defined(MBEDTLS_FS_IO)
/* Default implementations for the platform independent seed functions use
 * standard libc file functions to read from and write to a pre-defined filename
 */
int mbedtls_platform_std_nv_seed_read(unsigned char *buf, size_t buf_len)
{
    FILE *file;
    size_t n;

    if ((file = fopen(MBEDTLS_PLATFORM_STD_NV_SEED_FILE, "rb")) == NULL) {
        return -1;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    mbedtls_setbuf(file, NULL);

    if ((n = fread(buf, 1, buf_len, file)) != buf_len) {
        fclose(file);
        mbedtls_platform_zeroize(buf, buf_len);
        return -1;
    }

    fclose(file);
    return (int) n;
}

int mbedtls_platform_std_nv_seed_write(unsigned char *buf, size_t buf_len)
{
    FILE *file;
    size_t n;

    if ((file = fopen(MBEDTLS_PLATFORM_STD_NV_SEED_FILE, "w")) == NULL) {
        return -1;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    mbedtls_setbuf(file, NULL);

    if ((n = fwrite(buf, 1, buf_len, file)) != buf_len) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return (int) n;
}
#endif /* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_nv_seed_read_uninit(unsigned char *buf, size_t buf_len)
{
    ((void) buf);
    ((void) buf_len);
    return -1;
}

#define MBEDTLS_PLATFORM_STD_NV_SEED_READ   platform_nv_seed_read_uninit
#endif /* !MBEDTLS_PLATFORM_STD_NV_SEED_READ */

#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_nv_seed_write_uninit(unsigned char *buf, size_t buf_len)
{
    ((void) buf);
    ((void) buf_len);
    return -1;
}

#define MBEDTLS_PLATFORM_STD_NV_SEED_WRITE   platform_nv_seed_write_uninit
#endif /* !MBEDTLS_PLATFORM_STD_NV_SEED_WRITE */

int (*mbedtls_nv_seed_read)(unsigned char *buf, size_t buf_len) =
    MBEDTLS_PLATFORM_STD_NV_SEED_READ;
int (*mbedtls_nv_seed_write)(unsigned char *buf, size_t buf_len) =
    MBEDTLS_PLATFORM_STD_NV_SEED_WRITE;

int mbedtls_platform_set_nv_seed(
    int (*nv_seed_read_func)(unsigned char *buf, size_t buf_len),
    int (*nv_seed_write_func)(unsigned char *buf, size_t buf_len))
{
    mbedtls_nv_seed_read = nv_seed_read_func;
    mbedtls_nv_seed_write = nv_seed_write_func;
    return 0;
}
#endif /* MBEDTLS_PLATFORM_NV_SEED_ALT */
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#if !defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)
/*
 * Placeholder platform setup that does nothing by default
 */
int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
    (void) ctx;

    return 0;
}

/*
 * Placeholder platform teardown that does nothing by default
 */
void mbedtls_platform_teardown(mbedtls_platform_context *ctx)
{
    (void) ctx;
}
#endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT */

#if !defined(MBEDTLS_PLATFORM_GET_ENTROPY_ALT)

#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__QNXNTO__) && \
    !defined(__HAIKU__) && !defined(__midipix__) && !defined(__MVS__)
#error \
    "The default platform entropy sources only work on Unix and Windows. " \
    "Please enable MBEDTLS_PLATFORM_GET_ENTROPY_ALT and implement " \
    "mbedtls_platform_get_entropy()."
#endif

#include "mbedtls/entropy.h"

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#include <windows.h>
#include <bcrypt.h>
#include <intsafe.h>

int mbedtls_platform_get_entropy(unsigned char *output, size_t output_size,
                                 size_t *output_len, size_t *entropy_content)
{
    *output_len = 0;

    /*
     * BCryptGenRandom takes ULONG for size, which is smaller than size_t on
     * 64-bit Windows platforms.
     */
    if (output_size > ULONG_MAX) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, output, (unsigned long) output_size,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    *output_len = output_size;
    *entropy_content = 8 * *output_len;

    return 0;
}
#else /* _WIN32 && !EFIX64 && !EFI32 */

#if defined(__linux__) || defined(__midipix__)
/* Ensure that syscall() is available even when compiling with -std=c99 */
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if !defined(__USE_MISC)
#define __USE_MISC
#endif
#endif

/*
 * Test for Linux getrandom() support.
 * Since there is no wrapper in the libc yet, use the generic syscall wrapper
 * available in GNU libc and compatible libc's (eg uClibc).
 */
#if ((defined(__linux__) && defined(__GLIBC__)) || defined(__midipix__))
#include <unistd.h>
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define HAVE_GETRANDOM
#include <errno.h>

static int getrandom_wrapper(void *buf, size_t buflen, unsigned int flags)
{
    /* MemSan cannot understand that the syscall writes to the buffer */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset(buf, 0, buflen);
#endif
#endif
    return (int) syscall(SYS_getrandom, buf, buflen, flags);
}
#endif /* SYS_getrandom */
#endif /* __linux__ || __midipix__ */

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/param.h>
#if (defined(__FreeBSD__) && __FreeBSD_version >= 1200000) || \
    (defined(__DragonFly__) && __DragonFly_version >= 500700)
#include <errno.h>
#include <sys/random.h>
#define HAVE_GETRANDOM
static int getrandom_wrapper(void *buf, size_t buflen, unsigned int flags)
{
    return (int) getrandom(buf, buflen, flags);
}
#endif /* (__FreeBSD__ && __FreeBSD_version >= 1200000) ||
          (__DragonFly__ && __DragonFly_version >= 500700) */
#endif /* __FreeBSD__ || __DragonFly__ */

/*
 * Some BSD systems provide KERN_ARND.
 * This is equivalent to reading from /dev/urandom, only it doesn't require an
 * open file descriptor, and provides up to 256 bytes per call (basically the
 * same as getentropy(), but with a longer history).
 *
 * Documentation: https://netbsd.gw.com/cgi-bin/man-cgi?sysctl+7
 */
#if (defined(__FreeBSD__) || defined(__NetBSD__)) && !defined(HAVE_GETRANDOM)
#include <sys/param.h>
#include <sys/sysctl.h>
#if defined(KERN_ARND)
#define HAVE_SYSCTL_ARND

static int sysctl_arnd_wrapper(unsigned char *buf, size_t buflen)
{
    int name[2];
    size_t len;

    name[0] = CTL_KERN;
    name[1] = KERN_ARND;

    while (buflen > 0) {
        len = buflen > 256 ? 256 : buflen;
        if (sysctl(name, 2, buf, &len, NULL, 0) == -1) {
            return -1;
        }
        buflen -= len;
        buf += len;
    }
    return 0;
}
#endif /* KERN_ARND */
#endif /* __FreeBSD__ || __NetBSD__ */

#include <stdio.h>

int mbedtls_platform_get_entropy(unsigned char *output, size_t output_size,
                                 size_t *output_len, size_t *entropy_content)
{
    FILE *file;
    size_t read_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(HAVE_GETRANDOM)
    ret = getrandom_wrapper(output, output_size, 0);
    if (ret >= 0) {
        *output_len = (size_t) ret;
        *entropy_content = 8 * *output_len;
        return 0;
    } else if (errno != ENOSYS) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    /* Fall through if the system call isn't known. */
#else
    ((void) ret);
#endif /* HAVE_GETRANDOM */

#if defined(HAVE_SYSCTL_ARND)
    ((void) file);
    ((void) read_len);
    if (sysctl_arnd_wrapper(output, output_size) == -1) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *output_len = output_size;
    *entropy_content = 8 * *output_len;
    return 0;
#else

    *output_len = 0;

    file = fopen("/dev/urandom", "rb");
    if (file == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    mbedtls_setbuf(file, NULL);

    read_len = fread(output, 1, output_size, file);
    if (read_len != output_size) {
        fclose(file);
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    fclose(file);
    *output_len = output_size;
    *entropy_content = 8 * *output_len;

    return 0;
#endif /* HAVE_SYSCTL_ARND */
}
#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !MBEDTLS_PLATFORM_GET_ENTROPY_ALT */

#endif /* MBEDTLS_PLATFORM_C */

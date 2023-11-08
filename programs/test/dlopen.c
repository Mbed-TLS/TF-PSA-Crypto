/*
 *  Test dynamic loading of libtfpsacrypto
 *
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

#include "psa/build_info.h"
#include "psa/crypto.h"
#include "tf_psa_crypto/platform.h"

#if defined(__APPLE__)
#define SO_SUFFIX ".dylib"
#else
#define SO_SUFFIX ".so"
#endif

#define CRYPTO_SO_FILENAME "libtfpsacrypto" SO_SUFFIX
#define CRYPTO_SO_PATH "core/" CRYPTO_SO_FILENAME
#include <stdlib.h>
#include <dlfcn.h>

#define CHECK_DLERROR(function, argument)                              \
    do                                                                 \
    {                                                                  \
        char *CHECK_DLERROR_error = dlerror();                         \
        if (CHECK_DLERROR_error != NULL)                               \
        {                                                              \
            fprintf(stderr, "Dynamic loading error for %s(%s): %s\n",  \
                    function, argument, CHECK_DLERROR_error);          \
            tf_psa_crypto_exit(TF_PSA_CRYPTO_EXIT_FAILURE);            \
        }                                                              \
    }                                                                  \
    while (0)

int main(void)
{
    void *crypto_so = dlopen(CRYPTO_SO_PATH, RTLD_NOW);
    CHECK_DLERROR("dlopen", CRYPTO_SO_PATH);

    psa_status_t (*psa_crypto_init_ptr)(void) = dlsym(crypto_so, "psa_crypto_init");
    CHECK_DLERROR("dlsym", "psa_crypto_init");

    psa_status_t res = psa_crypto_init_ptr();
    if (res == PSA_SUCCESS)
    {
        tf_psa_crypto_printf("dlopen(%s): Call to psa_crypto_init was successful.\n",
                             CRYPTO_SO_FILENAME);
    }
    else
    {
        tf_psa_crypto_printf("dlopen(%s): Call to psa_crypto_init failed.\n",
                             CRYPTO_SO_FILENAME);
    }

    dlclose(crypto_so);
    CHECK_DLERROR("dlclose", CRYPTO_SO_PATH);
    return 0;
}
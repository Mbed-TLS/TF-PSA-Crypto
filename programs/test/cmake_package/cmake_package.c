/*
 *  Simple program to test that TF-PSA-Crypto builds correctly as a CMake
 *  package.
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

#include <psa/crypto.h>
#include <tf_psa_crypto/lms.h>

/* The main reason to build this is for testing the CMake build, so the program
 * doesn't need to do very much. It calls a PSA cryptography API and one that
 * is not part of it, to ensure linkage works, but that is all. */
int main()
{
    mbedtls_lms_public_t ctx;

    psa_crypto_init();
    mbedtls_lms_public_init(&ctx);

    return 0;
}

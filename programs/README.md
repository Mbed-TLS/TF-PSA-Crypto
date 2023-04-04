PSA cryptography example programs
=================================

This subdirectory mostly contains sample programs that illustrate specific features of the library, as well as a few test and support programs.

## PSA cryptography examples

* [`psa/aead_demo.c`](psa/aead_demo.c): PSA multi-part AEAD demonstration. This program AEAD-encrypts a message, using the algorithm and key size specified on the command line, using the PSA AEAD multi-part API.

* [`psa/crypto_examples.c`](psa/crypto_examples.c): PSA single and multi part unauthenticated cipher encryption and decryption demonstration.

* [`psa/hmac_demo.c`](psa/hmac_demo.c): PSA API multi-part HMAC demonstration. This programs computes the HMAC of two messages using the multi-part API.

* [`psa/key_ladder_demo.c`](psa/key_ladder_demo.c): PSA API key derivation demonstration. This program calculates a key ladder: a chain of secret material, each derived from the previous one in a deterministic way based on a label. Two keys are identical if and only if they are derived from the same key using the same label.

* [`psa/psa_constant_names.c`](psa/psa_constant_names.c): This programs prints the PSA symbolic name of a numerical value given its type.

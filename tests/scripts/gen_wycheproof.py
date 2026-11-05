#!/usr/bin/env python3
"""Convert Project Wycheproof JSON test vectors into Mbed TLS .data files.

The Wycheproof vectors are not vendored in this repository. To generate the .data files,
clone Project Wycheproof and check out the pinned revision:

    git clone https://github.com/C2SP/wycheproof
    git -C wycheproof checkout 6d7cccd0fcb1917368579adeeac10fe802f1b521

Then point this script at the testvectors_v1 directory:

    tf-psa-crypto/tests/scripts/gen_wycheproof.py path/to/wycheproof/testvectors_v1

By default the .data files are written next to their corresponding test harnesses in
tf-psa-crypto/tests/suites. Use --output-dir to change this behaviour.
"""

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from cryptography.exceptions import UnsupportedAlgorithm

WYCHEPROOF_COMMIT = "6d7cccd0fcb1917368579adeeac10fe802f1b521"

# Parsed from command-line arguments.
WYCHEPROOF_BASE_DIR = Path()
DATA_BASE_DIR = Path()

# Defaults to the suites/ directory next to the current scripts/
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "suites"


def format_inputs(*inputs) -> str:
    return ":".join(f'"{i}"' for i in inputs)


def write_output(out: str, filename: str) -> None:
    file = DATA_BASE_DIR / filename
    with file.open("w") as fp:
        fp.write(out.rstrip("\n"))
    print(f"[+] Wrote {filename}", file=sys.stderr)


def header(filename: str, name: str) -> str:
    return f"""# Tests for {name}, from Project Wycheproof.
# See: https://github.com/C2SP/wycheproof/blob/{WYCHEPROOF_COMMIT}/testvectors_v1/{filename}"""


def intro(filename: str, name: str):
    file = WYCHEPROOF_BASE_DIR / filename
    with file.open("r") as fp:
        data = json.load(fp)
    return header(filename, name), data


def normalize_private_scalar(private_hex: str, bits: int) -> str:
    """Normalize a Weierstrass private scalar.

    PSA import requires exactly PSA_BITS_TO_BYTES(curve_size) bytes.
    """
    size = (bits + 7) // 8
    raw = bytes.fromhex(private_hex).lstrip(b"\x00")
    return raw.rjust(size, b"\x00").hex()


def find_curve(filename: str, curves) -> str | None:
    """Return the curve name from the JSON filename."""
    for curve in curves:
        if f"_{curve.lower()}_" in filename.lower():
            return curve
    return None


def gen_aes_cbc():
    """Generate .data files for AES-CBC with PKCS#7 padding.

    Valid tests are tested with mbedtls_aes_cbc_enc_dec() which encrypt/decrypts
    correctly.

    Invalid tests are tested with mbedtls_aes_cbc_dec_invalid_padding() to ensure that
    the invalid padding is caught.
    """
    out, data = intro("aes_cbc_pkcs5_test.json", "AES-CBC with PKCS#7 padding")
    for group in data["testGroups"]:
        key_size = group["keySize"]
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof AES-{key_size}-CBC #{test['tcId']}\n"
            out += (
                "mbedtls_aes_cbc_enc_dec"
                if test["result"] == "valid"
                else "mbedtls_aes_cbc_dec_invalid_padding"
            )
            out += ":" + format_inputs(test["key"], test["iv"], test["msg"], test["ct"])
    write_output(out, "test_suite_cbc_wycheproof.data")


def gen_aes_ccm():
    """Generate .data files for AES-CCM.

    Tests are executed by different functions:

        - Valid -> mbedtls_ccm_encrypt_and_tag(), to correctly encrypt/decrypt.
        - ModifiedTag -> mbedtls_ccm_decrypt_modified_tag(), to catch invalid MACs.
        - InvalidNonceSize -> mbedtls_ccm_encrypt_decrypt_invalid_nonce(), to ensure
          that invalid nonces are rejected.
        - InvalidTagSize/InsecureTagSize -> mbedtls_ccm_decrypt_invalid_insecure_tag(),
          to explicitly catch errors with the MAC tag.
    """
    out, data = intro("aes_ccm_test.json", "AES-CCM")
    for group in data["testGroups"]:
        key_size = group["keySize"]
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof AES-{key_size}-CCM #{test['tcId']}\n"
            flags = test.get("flags", [])
            if test["result"] == "valid":
                out += "mbedtls_ccm_encrypt_and_tag"
            elif "ModifiedTag" in flags:
                out += "mbedtls_ccm_decrypt_modified_tag"
            elif "InvalidNonceSize" in flags:
                out += "mbedtls_ccm_encrypt_decrypt_invalid_nonce"
            elif "InvalidTagSize" in flags or "InsecureTagSize" in flags:
                out += "mbedtls_ccm_decrypt_invalid_insecure_tag"
            else:
                raise ValueError(f"Unhandled test {test['tcId']}, {flags}")
            out += ":" + format_inputs(
                test["key"],
                test["msg"],
                test["iv"],
                test["aad"],
                test["ct"],
                test["tag"],
            )
    write_output(out, "test_suite_ccm_wycheproof.data")


def gen_aes_gcm():
    """Generate .data files for AES-GCM.

    Tests are executed by different functions:

        - Valid -> mbedtls_gcm_enc_dec(), to correctly encrypt/decrypt.
        - ZeroLengthIv -> mbedtls_gcm_enc_dec_zero_length_iv(), to ensure that a
          zero-length IV is rejected.
        - ModifiedTag -> mbedtls_gcm_dec_modified_tag(), to catch invalid MACs.
    """
    out, data = intro("aes_gcm_test.json", "AES-GCM")
    for group in data["testGroups"]:
        key_size = group["keySize"]
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof AES-{key_size}-GCM #{test['tcId']}\n"
            flags = test.get("flags", [])
            if test["result"] == "valid":
                out += "mbedtls_gcm_enc_dec"
            elif "ZeroLengthIv" in flags:
                out += "mbedtls_gcm_enc_dec_zero_length_iv"
            elif "ModifiedTag" in flags:
                out += "mbedtls_gcm_dec_modified_tag"
            else:
                raise ValueError(f"Unhandled test {test['tcId']}, {flags}")
            out += ":" + format_inputs(
                test["key"],
                test["iv"],
                test["aad"],
                test["msg"],
                test["ct"],
                test["tag"],
            )
    write_output(out, "test_suite_gcm_wycheproof.data")


def gen_aria_cbc():
    """Generate .data files for ARIA-CBC.

    Valid tests are tested with mbedtls_aria_cbc_enc_dec() which encrypt/decrypts
    correctly.

    Invalid tests are tested with mbedtls_aria_cbc_dec_invalid_padding() to ensure that
    the invalid padding is caught.
    """
    out, data = intro("aria_cbc_pkcs5_test.json", "ARIA-CBC with PKCS#7 padding")
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof ARIA-CBC #{test['tcId']}\n"
            out += (
                "mbedtls_aria_cbc_enc_dec"
                if test["result"] == "valid"
                else "mbedtls_aria_cbc_dec_invalid_padding"
            )
            out += ":" + format_inputs(test["key"], test["iv"], test["msg"], test["ct"])
    write_output(out, "test_suite_aria_cbc_wycheproof.data")


def gen_aria_ccm():
    """Generate .data files for ARIA-CCM.

    Valid tests are tested with mbedtls_aria_ccm_enc_dec() which correctly
    encrypts/decrypts with a MAC tag.

    Invalid tests are tested with mbedtls_aria_ccm_dec_invalid() to ensure that the
    invalid MAC is detected.
    """
    out, data = intro("aria_ccm_test.json", "ARIA-CCM")
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof ARIA-CCM #{test['tcId']}\n"
            out += (
                "mbedtls_aria_ccm_enc_dec"
                if test["result"] == "valid"
                else "mbedtls_aria_ccm_dec_invalid"
            )
            out += ":" + format_inputs(
                test["key"],
                test["iv"],
                test["aad"],
                test["msg"],
                test["ct"],
                test["tag"],
            )
    write_output(out, "test_suite_aria_ccm_wycheproof.data")


def gen_aria_gcm():
    """Generate .data files for ARIA-GCM.

    Valid tests are tested with aria_gcm_enc_dec() which correctly encrypts/decrypts
    with a MAC tag.

    Invalid tests are tested with mbedtls_aria_gcm_dec_invalid() to ensure that the
    invalid MAC is detected.
    """
    out, data = intro("aria_gcm_test.json", "ARIA-GCM")
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof ARIA-GCM #{test['tcId']}\n"
            out += (
                "mbedtls_aria_gcm_enc_dec"
                if test["result"] == "valid"
                else "mbedtls_aria_gcm_dec_invalid"
            )
            out += ":" + format_inputs(
                test["key"],
                test["iv"],
                test["aad"],
                test["msg"],
                test["ct"],
                test["tag"],
            )
    write_output(out, "test_suite_aria_gcm_wycheproof.data")


def gen_camellia_cbc():
    """Generate .data files for Camellia-CBC.

    Valid tests are tested with mbedtls_camellia_cbc_enc_dec() which encrypt/decrypts
    correctly.

    Invalid tests are tested with mbedtls_camellia_cbc_dec_invalid_padding() to ensure that
    the invalid padding is caught.
    """
    out, data = intro(
        "camellia_cbc_pkcs5_test.json", "Camellia-CBC with PKCS#7 padding"
    )
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof Camellia-CBC #{test['tcId']}\n"
            out += (
                "mbedtls_camellia_cbc_enc_dec"
                if test["result"] == "valid"
                else "mbedtls_camellia_cbc_dec_invalid_padding"
            )
            out += ":" + format_inputs(test["key"], test["iv"], test["msg"], test["ct"])
    write_output(out, "test_suite_camellia_cbc_wycheproof.data")


def gen_camellia_ccm():
    """Generate .data files for Camellia-CCM.

    Valid tests are tested with mbedtls_camellia_ccm_enc_dec() which correctly
    encrypts/decrypts with a MAC tag.

    Invalid tests are tested with mbedtls_camellia_ccm_dec_invalid() to ensure that the
    invalid MAC is detected.
    """
    out, data = intro("camellia_ccm_test.json", "Camellia-CCM")
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof Camellia-CCM #{test['tcId']}\n"
            out += (
                "mbedtls_camellia_ccm_enc_dec"
                if test["result"] == "valid"
                else "mbedtls_camellia_ccm_dec_invalid"
            )
            out += ":" + format_inputs(
                test["key"],
                test["iv"],
                test["aad"],
                test["msg"],
                test["ct"],
                test["tag"],
            )
    write_output(out, "test_suite_camellia_ccm_wycheproof.data")


def gen_chachapoly():
    """Generate .data files for ChaCha20-Poly1305.

    Tests are executed by different functions:

        - Valid -> mbedtls_chachapoly_enc_dec(), to correctly encrypt/decrypt.
        - ModifiedTag -> mbedtls_chachapoly_dec_modified_tag(), to catch invalid MACs.
        - InvalidNonceSize -> mbedtls_chachapoly_invalid_nonce(), to ensure that an
          invalid nonce size is rejected.
    """
    out, data = intro("chacha20_poly1305_test.json", "ChaCha20-Poly1305")
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof ChaCha20-Poly1305 #{test['tcId']}\n"
            flags = test.get("flags", [])
            if test["result"] == "valid":
                out += "mbedtls_chachapoly_enc_dec"
            elif "ModifiedTag" in flags:
                out += "mbedtls_chachapoly_dec_modified_tag"
            elif "InvalidNonceSize" in flags:
                out += "mbedtls_chachapoly_invalid_nonce"
            else:
                raise ValueError(f"Unhandled test {test['tcId']}, {flags}")
            out += ":" + format_inputs(
                test["key"],
                test["iv"],
                test["aad"],
                test["msg"],
                test["ct"],
                test["tag"],
            )
    write_output(out, "test_suite_chachapoly_wycheproof.data")


def gen_cmac():
    """Generate .data files for AES-CMAC.

    Tests are executed by different functions:

        - Valid -> mbedtls_cmac_generate_verify(), to generate and verify the MAC.
        - InvalidKeySize -> mbedtls_cmac_genver_invalid_key_size(), to ensure that an
          invalid key size is rejected.
        - ModifiedTag -> mbedtls_cmac_verify_modified_tag(), to catch invalid MACs.
    """
    out, data = intro("aes_cmac_test.json", "AES-CMAC")
    for group in data["testGroups"]:
        for test in group["tests"]:
            out += "\n\n"
            out += f"Wycheproof AES-CMAC #{test['tcId']}\n"
            flags = test.get("flags", [])
            if test["result"] == "valid":
                out += "mbedtls_cmac_generate_verify"
            elif "InvalidKeySize" in flags:
                out += "mbedtls_cmac_genver_invalid_key_size"
            elif "ModifiedTag" in flags:
                out += "mbedtls_cmac_verify_modified_tag"
            else:
                raise ValueError(f"Unhandled test {test['tcId']}, {flags}")
            out += ":" + format_inputs(test["key"], test["msg"], test["tag"])
    write_output(out, "test_suite_cmac_wycheproof.data")


def gen_hkdf():
    """Generate .data files for HKDF, one file per hash.

    The first column is an unquoted PSA hash algorithm macro.

        - Valid -> mbedtls_hkdf_derive(), to derive and compare the OKM.
        - SizeTooLarge -> mbedtls_hkdf_size_too_large(), to ensure that an output
          size larger than 255*hashlen is rejected. The expected size is passed as
          an unquoted integer instead of the OKM.
    """
    hashes = [
        ("sha1", "PSA_ALG_SHA_1"),
        ("sha256", "PSA_ALG_SHA_256"),
        ("sha384", "PSA_ALG_SHA_384"),
        ("sha512", "PSA_ALG_SHA_512"),
    ]
    for suffix, macro in hashes:
        name = f"HKDF-{suffix.replace('sha', 'SHA-')}"
        out, data = intro(f"hkdf_{suffix}_test.json", name)
        for group in data["testGroups"]:
            for test in group["tests"]:
                out += "\n\n"
                out += f"Wycheproof {name} #{test['tcId']}\n"
                flags = test.get("flags", [])
                if test["result"] == "valid":
                    out += "mbedtls_hkdf_derive"
                    out += f":{macro}:" + format_inputs(
                        test["ikm"], test["salt"], test["info"], test["okm"]
                    )
                elif "SizeTooLarge" in flags:
                    out += "mbedtls_hkdf_size_too_large"
                    out += f":{macro}:" + format_inputs(
                        test["ikm"], test["salt"], test["info"]
                    )
                    out += f":{test['size']}"
                else:
                    raise ValueError(f"Unhandled test {test['tcId']}, {flags}")
        write_output(out, f"test_suite_hkdf_wycheproof.{suffix}.data")


def gen_hmac():
    """Generate .data files for HMAC, one file per hash.

    The first column is an unquoted PSA hash algorithm macro.

        - Valid -> mbedtls_hmac_gen_ver(), to generate and verify the MAC.
        - ModifiedTag -> mbedtls_hmac_ver_modified_tag(), to catch invalid MACs.
    """
    hashes = [
        ("sha1", "PSA_ALG_SHA_1"),
        ("sha256", "PSA_ALG_SHA_256"),
        ("sha384", "PSA_ALG_SHA_384"),
        ("sha512", "PSA_ALG_SHA_512"),
        ("sha3_224", "PSA_ALG_SHA3_224"),
        ("sha3_256", "PSA_ALG_SHA3_256"),
        ("sha3_384", "PSA_ALG_SHA3_384"),
        ("sha3_512", "PSA_ALG_SHA3_512"),
    ]
    for suffix, macro in hashes:
        name = f"HMAC-{suffix.replace('sha', 'SHA-')}"
        out, data = intro(f"hmac_{suffix}_test.json", name)
        for group in data["testGroups"]:
            for test in group["tests"]:
                out += "\n\n"
                out += f"Wycheproof {name} #{test['tcId']}\n"
                flags = test.get("flags", [])
                if test["result"] == "valid":
                    out += "mbedtls_hmac_gen_ver"
                elif "ModifiedTag" in flags:
                    out += "mbedtls_hmac_ver_modified_tag"
                else:
                    raise ValueError(f"Unhandled test {test['tcId']}, {flags}")
                out += f":{macro}:" + format_inputs(
                    test["key"], test["msg"], test["tag"]
                )
        write_output(out, f"test_suite_hmac_wycheproof.{suffix}.data")


def gen_pbkdf2():
    """Generate .data files for PBKDF2-HMAC, one file per hash.

    The first column is an unquoted PSA hash algorithm macro and the iteration
    count is an unquoted integer. All Wycheproof PBKDF2 vectors are valid.
    """
    hashes = [
        ("sha1", "PSA_ALG_SHA_1"),
        ("sha224", "PSA_ALG_SHA_224"),
        ("sha256", "PSA_ALG_SHA_256"),
        ("sha384", "PSA_ALG_SHA_384"),
        ("sha512", "PSA_ALG_SHA_512"),
    ]
    for suffix, macro in hashes:
        name = f"PBKDF2-HMAC-{suffix.replace('sha', 'SHA-')}"
        out, data = intro(f"pbkdf2_hmac{suffix}_test.json", name)
        for group in data["testGroups"]:
            for test in group["tests"]:
                if test["result"] != "valid":
                    raise ValueError(f"Unexpected invalid test {test['tcId']}")
                out += "\n\n"
                out += f"Wycheproof {name} #{test['tcId']}\n"
                out += "mbedtls_pbkdf2_derive"
                out += f":{macro}:" + format_inputs(test["password"], test["salt"])
                out += f":{test['iterationCount']}:" + format_inputs(test["dk"])
        write_output(out, f"test_suite_pbkdf2_wycheproof.{suffix}.data")


def gen_ecdh():  # pylint: disable=too-many-locals
    """Generate .data files for ECDH, one file per curve.

    Line format: mbedtls_ecdh_compute:<family>:<bits>:priv:peer:shared:<result>

        - Montgomery (x25519/x448): the peer is the raw u-coordinate, passed through.
        - Weierstrass (secp/brainpool): the peer DER public key is decoded into a raw
          uncompressed point (0x04||X||Y) with the `cryptography` library.

    The result code is 2 for "valid" (must succeed and match), 1 for "acceptable"
    (succeed and match OR fail) and 0 for "invalid".

    Wycheproof includes Weierstrass peer keys with invalid DER enconding, which means we
    cannot decode the raw uncompressed point. They are skipped here and tested with
    gen_ecdh_der().
    """
    result_codes = {"valid": 2, "acceptable": 1, "invalid": 0}
    # (suffix, json, PSA family macro, bits, montgomery?)
    curves = [
        ("x25519", "x25519_test.json", "PSA_ECC_FAMILY_MONTGOMERY", 255, True),
        ("x448", "x448_test.json", "PSA_ECC_FAMILY_MONTGOMERY", 448, True),
        ("secp256r1", "ecdh_secp256r1_test.json", "PSA_ECC_FAMILY_SECP_R1", 256, False),
        ("secp384r1", "ecdh_secp384r1_test.json", "PSA_ECC_FAMILY_SECP_R1", 384, False),
        ("secp521r1", "ecdh_secp521r1_test.json", "PSA_ECC_FAMILY_SECP_R1", 521, False),
        ("secp256k1", "ecdh_secp256k1_test.json", "PSA_ECC_FAMILY_SECP_K1", 256, False),
        (
            "brainpoolP256r1",
            "ecdh_brainpoolP256r1_test.json",
            "PSA_ECC_FAMILY_BRAINPOOL_P_R1",
            256,
            False,
        ),
        (
            "brainpoolP384r1",
            "ecdh_brainpoolP384r1_test.json",
            "PSA_ECC_FAMILY_BRAINPOOL_P_R1",
            384,
            False,
        ),
        (
            "brainpoolP512r1",
            "ecdh_brainpoolP512r1_test.json",
            "PSA_ECC_FAMILY_BRAINPOOL_P_R1",
            512,
            False,
        ),
    ]

    def peer_point(public_hex, montgomery):
        if montgomery:
            return public_hex  # raw u-coordinate already
        key = load_der_public_key(bytes.fromhex(public_hex))
        return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()

    total_skipped = 0
    for suffix, filename, family, bits, montgomery in curves:
        out, data = intro(filename, f"ECDH {suffix}")
        skipped = 0
        for group in data["testGroups"]:
            for test in group["tests"]:
                try:
                    point = peer_point(test["public"], montgomery)
                except (ValueError, UnsupportedAlgorithm):
                    skipped += 1
                    continue
                private = (
                    test["private"]
                    if montgomery
                    else normalize_private_scalar(test["private"], bits)
                )
                out += "\n\n"
                out += f"Wycheproof ECDH-{suffix} #{test['tcId']}\n"
                out += "mbedtls_ecdh_compute"
                out += f":{family}:{bits}:" + format_inputs(
                    private, point, test["shared"]
                )
                out += f":{result_codes[test['result']]}"
        write_output(out, f"test_suite_ecdh_wycheproof.{suffix}.data")
        total_skipped += skipped
        print(
            f"    ECDH-{suffix}: skipped {skipped} undecodable peer keys",
            file=sys.stderr,
        )
    print(f"    ECDH total skipped: {total_skipped}", file=sys.stderr)


def gen_ecdh_der():
    """Generate .data files for ECDH with raw DER peer keys, one per Weierstrass curve.

    Complements gen_ecdh(): the raw invalid DER keys are kept to test them with MbedTLS
    DER parser.

    Line format: mbedtls_ecdh_compute_der:<family>:<bits>:priv:peerDer:shared:result

    Possible results are 2 for valid tests (succeeds and matches), 1 for acceptable
    tests (succeeds and matches OR rejects), and 0 for invalid tests (must reject).
    """
    result_codes = {"valid": 2, "acceptable": 1, "invalid": 0}
    # (suffix, json, PSA family macro, bits)
    curves = [
        ("secp256r1", "ecdh_secp256r1_test.json", "PSA_ECC_FAMILY_SECP_R1", 256),
        ("secp384r1", "ecdh_secp384r1_test.json", "PSA_ECC_FAMILY_SECP_R1", 384),
        ("secp521r1", "ecdh_secp521r1_test.json", "PSA_ECC_FAMILY_SECP_R1", 521),
        ("secp256k1", "ecdh_secp256k1_test.json", "PSA_ECC_FAMILY_SECP_K1", 256),
        (
            "brainpoolP256r1",
            "ecdh_brainpoolP256r1_test.json",
            "PSA_ECC_FAMILY_BRAINPOOL_P_R1",
            256,
        ),
        (
            "brainpoolP384r1",
            "ecdh_brainpoolP384r1_test.json",
            "PSA_ECC_FAMILY_BRAINPOOL_P_R1",
            384,
        ),
        (
            "brainpoolP512r1",
            "ecdh_brainpoolP512r1_test.json",
            "PSA_ECC_FAMILY_BRAINPOOL_P_R1",
            512,
        ),
    ]
    for suffix, filename, family, bits in curves:
        out, data = intro(filename, f"ECDH {suffix} with DER peer keys")
        for group in data["testGroups"]:
            for test in group["tests"]:
                out += "\n\n"
                out += f"Wycheproof ECDH-{suffix}-DER #{test['tcId']}\n"
                out += "mbedtls_ecdh_compute_der"
                out += f":{family}:{bits}:" + format_inputs(
                    normalize_private_scalar(test["private"], bits),
                    test["public"],
                    test["shared"],
                )
                out += f":{result_codes[test['result']]}"
        write_output(out, f"test_suite_ecdh_wycheproof.{suffix}_der.data")


def gen_ecdsa():
    """Generate .data files for ECDSA with DER signatures, one file per curve+hash.

    Scope: MbedTLS curves (secp{256,384,521}r1, secp256k1, brainpoolP{256,384,512}r1)
    with SHA-2 and SHA-3. We exclude files with SHAKE and Bitcoin test files.

    Line format: mbedtls_ecdsa_verify_der:<MD>:pubkeyDer:msg:sig:<expected_valid>

    Enforces strict results: valid tests are expected to be successful, all other,
    including acceptable tests, are expected to be rejected.
    """
    supported = [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "secp256k1",
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1",
    ]
    md = {
        "SHA-256": "MBEDTLS_MD_SHA256",
        "SHA-384": "MBEDTLS_MD_SHA384",
        "SHA-512": "MBEDTLS_MD_SHA512",
        "SHA3-256": "MBEDTLS_MD_SHA3_256",
        "SHA3-384": "MBEDTLS_MD_SHA3_384",
        "SHA3-512": "MBEDTLS_MD_SHA3_512",
    }
    skip_keywords = ["p1363", "webcrypto", "ecpoint", "_pem", "bitcoin", "shake"]
    files = 0
    for path in sorted(WYCHEPROOF_BASE_DIR.glob("ecdsa_*_test.json")):
        filename = path.name
        if any(kw in filename for kw in skip_keywords):
            continue
        if find_curve(filename, supported) is None:
            continue
        with path.open("r") as fp:
            data = json.load(fp)
        sha = data["testGroups"][0].get("sha")
        if sha not in md:
            continue
        tag = filename.replace("ecdsa_", "").replace("_test.json", "")
        out = header(filename, f"ECDSA {tag}")
        for group in data["testGroups"]:
            pubkey = group["publicKeyDer"]
            for test in group["tests"]:
                expected_valid = 1 if test["result"] == "valid" else 0
                out += "\n\n"
                out += f"Wycheproof ECDSA-{tag} #{test['tcId']}\n"
                out += "mbedtls_ecdsa_verify_der"
                out += f":{md[sha]}:" + format_inputs(pubkey, test["msg"], test["sig"])
                out += f":{expected_valid}"
        write_output(out, f"test_suite_ecdsa_wycheproof.{tag}.data")
        files += 1
    print(f"    ECDSA: {files} .data files", file=sys.stderr)


def gen_ecdsa_p1363():  # pylint: disable=too-many-locals
    """Generate .data files for ECDSA with P1363 (raw r||s) signatures.

    Uses the uncompressed public key (0x04 || X || Y).

    Line format:

    mbedtls_ecdsa_verify_p1363:<PSA_HASH>:<family>:<bits>:point:msg:sig:<expected_valid>

    Results: same as DER ECDSA, valid tests should all succeed, invalid and acceptable
    tests should be rejected.
    """
    # curve -> (PSA family macro, bits)
    curves = {
        "secp256r1": ("PSA_ECC_FAMILY_SECP_R1", 256),
        "secp384r1": ("PSA_ECC_FAMILY_SECP_R1", 384),
        "secp521r1": ("PSA_ECC_FAMILY_SECP_R1", 521),
        "secp256k1": ("PSA_ECC_FAMILY_SECP_K1", 256),
        "brainpoolP256r1": ("PSA_ECC_FAMILY_BRAINPOOL_P_R1", 256),
        "brainpoolP384r1": ("PSA_ECC_FAMILY_BRAINPOOL_P_R1", 384),
        "brainpoolP512r1": ("PSA_ECC_FAMILY_BRAINPOOL_P_R1", 512),
    }
    hashes = {
        "SHA-256": "PSA_ALG_SHA_256",
        "SHA-384": "PSA_ALG_SHA_384",
        "SHA-512": "PSA_ALG_SHA_512",
    }
    files = 0
    for path in sorted(WYCHEPROOF_BASE_DIR.glob("ecdsa_*_p1363_test.json")):
        filename = path.name
        if "shake" in filename:
            continue
        curve = find_curve(filename, curves)
        if curve is None:
            continue
        with path.open("r") as fp:
            data = json.load(fp)
        sha = data["testGroups"][0].get("sha")
        if sha not in hashes:
            continue
        family, bits = curves[curve]
        tag = filename.replace("ecdsa_", "").replace("_test.json", "")
        out = header(filename, f"ECDSA {tag} (raw r||s)")
        for group in data["testGroups"]:
            point = group["publicKey"]["uncompressed"]
            for test in group["tests"]:
                expected_valid = 1 if test["result"] == "valid" else 0
                out += "\n\n"
                out += f"Wycheproof ECDSA-{tag} #{test['tcId']}\n"
                out += "mbedtls_ecdsa_verify_p1363"
                out += f":{hashes[sha]}:{family}:{bits}:" + format_inputs(
                    point, test["msg"], test["sig"]
                )
                out += f":{expected_valid}"
        write_output(out, f"test_suite_ecdsa_p1363_wycheproof.{tag}.data")
        files += 1
    print(f"    ECDSA-p1363: {files} .data files", file=sys.stderr)


def gen_nist_kw():
    """Generate .data files for AES Key Wrap, one file per (mode, key size).

        - aes_wrap_test.json -> MBEDTLS_KW_MODE_KW  (RFC 3394)
        - aes_kwp_test.json  -> MBEDTLS_KW_MODE_KWP (RFC 5649)

    The mode is an unquoted MBEDTLS_KW_MODE_* macro.

        - Valid -> wycheproof_nist_kw_valid(), wrap must match ct AND unwrap must
          recover msg.
        - Invalid -> wycheproof_nist_kw_unwrap_invalid(), unwrap must NOT recover msg.
        - Acceptable -> wycheproof_nist_kw_acceptable(), must succeed and match OR fail.
    """
    sources = [
        ("aes_wrap_test.json", "MBEDTLS_KW_MODE_KW", "AES-KW", "kw"),
        ("aes_kwp_test.json", "MBEDTLS_KW_MODE_KWP", "AES-KWP", "kwp"),
    ]
    for filename, mode, label, sub in sources:
        out, data = intro(filename, label)
        buckets = {}  # key size -> list of (test, function)
        for group in data["testGroups"]:
            key_size = group["keySize"]
            for test in group["tests"]:
                result = test["result"]
                if result == "valid":
                    function = "wycheproof_nist_kw_valid"
                elif result == "invalid":
                    function = "wycheproof_nist_kw_unwrap_invalid"
                elif result == "acceptable":
                    function = "wycheproof_nist_kw_acceptable"
                else:
                    raise ValueError(f"Unhandled result {result} at {test['tcId']}")
                buckets.setdefault(key_size, []).append((test, function))

        for key_size, cases in sorted(buckets.items()):
            out = header(filename, f"{label}-{key_size}")
            for test, function in cases:
                out += "\n\n"
                out += f"Wycheproof {label}-{key_size} #{test['tcId']}\n"
                if key_size != 128:
                    out += "depends_on:!MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH\n"
                out += function
                out += f":{mode}:" + format_inputs(test["key"], test["msg"], test["ct"])
            write_output(out, f"test_suite_nist_kw_wycheproof.{sub}_{key_size}.data")


def gen_rsa_decrypt():
    """Generate .data files for RSA decryption.

    OAEP (rsa_oaep_*, only where mgfSha == sha):
        mbedtls_rsa_oaep_decrypt:<MD>:pkcs8:ct:label:msg:<expected_valid>
    PKCS#1 v1.5 (rsa_pkcs1_*):
        mbedtls_rsa_pkcs1v15_decrypt:pkcs8:ct:msg:<expected_valid>

    Scope: key sizes 2048, 3072, 4096, with SHA-2 for OAEP.

    Results: valid tests must succeed, all others must fail.
    """
    md = {
        "SHA-1": "PSA_ALG_SHA_1",
        "SHA-224": "PSA_ALG_SHA_224",
        "SHA-256": "PSA_ALG_SHA_256",
        "SHA-384": "PSA_ALG_SHA_384",
        "SHA-512": "PSA_ALG_SHA_512",
    }
    oaep_files = 0
    for path in sorted(WYCHEPROOF_BASE_DIR.glob("rsa_oaep_*_test.json")):
        filename = path.name
        with path.open("r") as fp:
            data = json.load(fp)
        group0 = data["testGroups"][0]
        sha = group0.get("sha")
        # Separate into several conditions to appease pylint.
        if sha not in md:
            continue
        if group0.get("mgfSha") != sha:  # Only keep tests with hash == mgfHash
            continue
        if any(kw in filename for kw in {"_8192_", "misc", "three_primes"}):
            continue
        tag = filename.replace("_test.json", "")
        out = header(filename, tag)
        for group in data["testGroups"]:
            pkcs8 = group["privateKeyPkcs8"]
            for test in group["tests"]:
                expected_valid = 1 if test["result"] == "valid" else 0
                out += "\n\n"
                out += f"Wycheproof {tag} #{test['tcId']}\n"
                out += "mbedtls_rsa_oaep_decrypt"
                out += f":{md[sha]}:" + format_inputs(
                    pkcs8, test["ct"], test["label"], test["msg"]
                )
                out += f":{expected_valid}"
        write_output(out, f"test_suite_rsa_oaep_wycheproof.{tag}.data")
        oaep_files += 1

    pkcs1_files = 0
    for path in sorted(WYCHEPROOF_BASE_DIR.glob("rsa_pkcs1_*_test.json")):
        filename = path.name
        if any(kw in filename for kw in {"sig_gen", "_8192_", "1024", "1536"}):
            continue
        with path.open("r") as fp:
            data = json.load(fp)
        tag = filename.replace("_test.json", "")
        out = header(filename, tag)
        for group in data["testGroups"]:
            pkcs8 = group["privateKeyPkcs8"]
            for test in group["tests"]:
                expected_valid = 1 if test["result"] == "valid" else 0
                out += "\n\n"
                out += f"Wycheproof {tag} #{test['tcId']}\n"
                out += "mbedtls_rsa_pkcs1v15_decrypt"
                out += ":" + format_inputs(pkcs8, test["ct"], test["msg"])
                out += f":{expected_valid}"
        write_output(out, f"test_suite_rsa_pkcs1v15dec_wycheproof.{tag}.data")
        pkcs1_files += 1
    print(
        f"    RSA-decrypt: {oaep_files} OAEP + {pkcs1_files} PKCS1v15 .data files",
        file=sys.stderr,
    )


def gen_rsa_verify():
    """Generate .data files for RSA signature verification, one file per source.

    PKCS#1 v1.5 (rsa_signature_*) and PSS (rsa_pss_*, only where mgfSha == sha, since
    mbedtls_pk_verify_ext uses MGF1 with the signature hash and any salt length).

    Scope: key sizes 2048, 3072, and 4096, with SHA-2 hashes and SHA-3 for PKCS#1 v1.5.

        PKCS1v15: mbedtls_rsa_pkcs1v15_verify:<MD>:pubDer:msg:sig:<result>
        PSS     : mbedtls_rsa_pss_verify     :<MD>:pubDer:msg:sig:<result>

    Results: valid tests must succeed, all other tests must fail.
    """
    md = {
        "SHA-224": "MBEDTLS_MD_SHA224",
        "SHA-256": "MBEDTLS_MD_SHA256",
        "SHA-384": "MBEDTLS_MD_SHA384",
        "SHA-512": "MBEDTLS_MD_SHA512",
        "SHA3-224": "MBEDTLS_MD_SHA3_224",
        "SHA3-256": "MBEDTLS_MD_SHA3_256",
        "SHA3-384": "MBEDTLS_MD_SHA3_384",
        "SHA3-512": "MBEDTLS_MD_SHA3_512",
    }

    def gen_rsa(pattern, function, tag_prefix, pss=False):  # pylint: disable=too-many-locals
        files = 0
        for path in sorted(WYCHEPROOF_BASE_DIR.glob(pattern)):
            filename = path.name
            with path.open("r") as fp:
                data = json.load(fp)
            group0 = data["testGroups"][0]
            sha = group0.get("sha")
            if sha not in md:
                continue
            if "_8192_" in filename:  # skip slow 8192
                continue
            if pss and group0.get("mgfSha") != sha:  # keep only mgf hash == sig hash
                continue
            if pss and "_params" in filename:
                continue
            tag = filename.replace("_test.json", "")
            out = header(filename, tag)
            for group in data["testGroups"]:
                pubkey = group["publicKeyDer"]
                for test in group["tests"]:
                    expected_valid = 1 if test["result"] == "valid" else 0
                    out += "\n\n"
                    out += f"Wycheproof {tag} #{test['tcId']}\n"
                    out += function
                    out += f":{md[sha]}:" + format_inputs(
                        pubkey, test["msg"], test["sig"]
                    )
                    out += f":{expected_valid}"
            write_output(out, f"test_suite_{tag_prefix}_wycheproof.{tag}.data")
            files += 1
        return files

    pkcs1v15_files = gen_rsa(
        "rsa_signature_*_test.json", "mbedtls_rsa_pkcs1v15_verify", "rsa_pkcs1v15"
    )
    pss_files = gen_rsa(
        "rsa_pss_*_test.json", "mbedtls_rsa_pss_verify", "rsa_pss", pss=True
    )
    print(
        f"    RSA-verify: {pkcs1v15_files} PKCS1v15 + {pss_files} PSS .data files",
        file=sys.stderr,
    )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "wycheproof_dir",
        type=Path,
        help="path to a Project Wycheproof testvectors_v1 directory"
        f" (pinned revision: {WYCHEPROOF_COMMIT})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"directory to write the .data files to (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()

    if not args.wycheproof_dir.is_dir():
        parser.error(f"no such directory: {args.wycheproof_dir}")

    global WYCHEPROOF_BASE_DIR, DATA_BASE_DIR  # pylint: disable=global-statement
    WYCHEPROOF_BASE_DIR = args.wycheproof_dir
    DATA_BASE_DIR = args.output_dir

    gen_aes_cbc()
    gen_aes_ccm()
    gen_aes_gcm()

    gen_aria_cbc()
    gen_aria_ccm()
    gen_aria_gcm()

    gen_camellia_cbc()
    gen_camellia_ccm()

    gen_chachapoly()

    gen_cmac()
    gen_hmac()

    gen_hkdf()
    gen_pbkdf2()

    gen_nist_kw()

    gen_ecdh()
    gen_ecdh_der()
    gen_ecdsa()
    gen_ecdsa_p1363()

    gen_rsa_decrypt()
    gen_rsa_verify()


if __name__ == "__main__":
    main()

"""
Cryptographic constants database.

This module contains known cryptographic constants used for identifying
crypto implementations in binaries. These patterns are used by the
quantum search algorithms to locate cryptographic code.

NOTE: All patterns must be at least 4 bytes to avoid false positives.
For multi-byte integer constants, we include both big-endian and 
little-endian variants since the byte order depends on architecture.
"""

import struct

# ─── AES ────────────────────────────────────────────────────────────────────

# AES S-box (first 16 bytes — highly unique, zero false positive risk)
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

# AES Inverse S-box (first 16 bytes)
AES_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
])

# AES Round constants (all 10 — unique enough together)
AES_RCON = bytes([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36,
])

# ─── SHA-256 ────────────────────────────────────────────────────────────────

# SHA-256 initial hash values H0-H3 (big-endian, as defined in FIPS 180-4)
SHA256_H_BE = bytes([
    0x6a, 0x09, 0xe6, 0x67,  # H0
    0xbb, 0x67, 0xae, 0x85,  # H1
    0x3c, 0x6e, 0xf3, 0x72,  # H2
    0xa5, 0x4f, 0xf5, 0x3a,  # H3
])

# SHA-256 initial hash values H0-H3 (little-endian, as stored on x86)
SHA256_H_LE = b''.join(
    struct.pack('<I', v) for v in [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a]
)

# SHA-256 round constants K[0..3] (big-endian)
SHA256_K_BE = bytes([
    0x42, 0x8a, 0x2f, 0x98,
    0x71, 0x37, 0x44, 0x91,
    0xb5, 0xc0, 0xfb, 0xcf,
    0xe9, 0xb5, 0xdb, 0xa5,
])

# SHA-256 round constants K[0..3] (little-endian)
SHA256_K_LE = b''.join(
    struct.pack('<I', v) for v in [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]
)

# ─── SHA-512 ────────────────────────────────────────────────────────────────

# SHA-512 initial hash values (first 16 bytes of H0-H1, big-endian)
SHA512_H_BE = bytes([
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
    0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
])

# SHA-512 H0-H1 (little-endian)
SHA512_H_LE = b''.join(
    struct.pack('<Q', v) for v in [0x6a09e667f3bcc908, 0xbb67ae8584caa73b]
)

# ─── MD5 ────────────────────────────────────────────────────────────────────

# MD5 initial values (little-endian as defined)
MD5_INIT = bytes([
    0x01, 0x23, 0x45, 0x67,  # A
    0x89, 0xab, 0xcd, 0xef,  # B
    0xfe, 0xdc, 0xba, 0x98,  # C
    0x76, 0x54, 0x32, 0x10,  # D
])

# ─── ChaCha20 / Salsa20 ────────────────────────────────────────────────────

# ChaCha20/Salsa20 constants "expand 32-byte k"
CHACHA20_CONSTANTS = b"expand 32-byte k"

# Salsa20 uses the same constant string
SALSA20_CONSTANTS = b"expand 32-byte k"

# ─── DES ────────────────────────────────────────────────────────────────────

# DES S-box 1 (first row, 16 bytes — unique enough for 4-bit substitution)
DES_SBOX1 = bytes([
    14, 4, 13, 1, 2, 15, 11, 8,
    3, 10, 6, 12, 5, 9, 0, 7,
])

# ─── Blowfish ───────────────────────────────────────────────────────────────

# Blowfish P-array (first 8 bytes)
BLOWFISH_P = bytes([
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
])

# ─── RSA ────────────────────────────────────────────────────────────────────

# RSA public exponent e=65537 (3 bytes, big-endian)
# NOTE: Only 3 bytes, but 0x010001 is distinctive enough
RSA_E_65537_BE = bytes([0x01, 0x00, 0x01])

# RSA e=65537 as 4-byte little-endian (as stored in x86 binaries)
RSA_E_65537_LE = struct.pack('<I', 65537)

# NOTE: RSA_E_3 removed — single byte 0x03 causes massive false positives

# ─── Elliptic Curves ────────────────────────────────────────────────────────

# NIST P-256 curve prime (first 16 bytes — very distinctive)
P256_P = bytes([
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# secp256k1 order n (first 16 bytes)
SECP256K1_N = bytes([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
])

# ─── Post-Quantum Crypto ───────────────────────────────────────────────────

# Kyber (ML-KEM) — q=3329 as little-endian 16-bit (common in NTT code)
KYBER_Q_LE = struct.pack('<H', 3329)  # 0x01, 0x0D
# Kyber q=3329 as 32-bit LE for when it's stored as int
KYBER_Q_32_LE = struct.pack('<I', 3329)

# Dilithium (ML-DSA) — q=8380417 as little-endian 32-bit
DILITHIUM_Q_LE = struct.pack('<I', 8380417)

# Dilithium q as big-endian
DILITHIUM_Q_BE = struct.pack('>I', 8380417)

# ─── Organized constant database ───────────────────────────────────────────

CRYPTO_CONSTANTS = {
    "aes_sbox": {
        "sbox": AES_SBOX,
        "inv_sbox": AES_INV_SBOX,
    },
    "aes_rcon": {
        "rcon": AES_RCON,
    },
    "sha256": {
        "initial_hash_be": SHA256_H_BE,
        "initial_hash_le": SHA256_H_LE,
        "round_constants_be": SHA256_K_BE,
        "round_constants_le": SHA256_K_LE,
    },
    "sha512": {
        "initial_hash_be": SHA512_H_BE,
        "initial_hash_le": SHA512_H_LE,
    },
    "md5": {
        "init_values": MD5_INIT,
    },
    "chacha": {
        "sigma_constant": CHACHA20_CONSTANTS,
    },
    "salsa20": {
        "sigma_constant": SALSA20_CONSTANTS,
    },
    "des": {
        "sbox1": DES_SBOX1,
    },
    "blowfish": {
        "p_array": BLOWFISH_P,
    },
    "rsa": {
        "e_65537_be": RSA_E_65537_BE,
        "e_65537_le": RSA_E_65537_LE,
    },
    "ecc": {
        "p256_prime": P256_P,
        "secp256k1_order": SECP256K1_N,
    },
    "pqc_kyber": {
        "q_3329_le16": KYBER_Q_LE,
        "q_3329_le32": KYBER_Q_32_LE,
    },
    "pqc_dilithium": {
        "q_8380417_le": DILITHIUM_Q_LE,
        "q_8380417_be": DILITHIUM_Q_BE,
    },
}

# Minimum confidence thresholds based on pattern size
# Longer patterns = higher confidence
PATTERN_CONFIDENCE = {
    1: 0.1,   # Single byte — almost always false positive
    2: 0.2,   # Two bytes — very low confidence
    3: 0.4,   # Three bytes — low confidence 
    4: 0.6,   # Four bytes — moderate confidence
    8: 0.8,   # Eight bytes — high confidence
    16: 0.95, # Sixteen bytes — very high confidence
}


def get_confidence(pattern_size: int) -> float:
    """Get confidence score based on pattern length."""
    for size in sorted(PATTERN_CONFIDENCE.keys(), reverse=True):
        if pattern_size >= size:
            return PATTERN_CONFIDENCE[size]
    return 0.1

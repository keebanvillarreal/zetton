"""
Cryptographic constants database.

This module contains known cryptographic constants used for identifying
crypto implementations in binaries. These patterns are used by the
quantum search algorithms to locate cryptographic code.
"""

# AES S-box (first 16 bytes)
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

# AES Inverse S-box (first 16 bytes)
AES_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
])

# AES Round constants
AES_RCON = bytes([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36,
])

# SHA-256 initial hash values (H0-H7)
SHA256_H = bytes([
    0x6a, 0x09, 0xe6, 0x67,  # H0
    0xbb, 0x67, 0xae, 0x85,  # H1
    0x3c, 0x6e, 0xf3, 0x72,  # H2
    0xa5, 0x4f, 0xf5, 0x3a,  # H3
])

# SHA-256 round constants K (first 16 values as bytes)
SHA256_K = bytes([
    0x42, 0x8a, 0x2f, 0x98,
    0x71, 0x37, 0x44, 0x91,
    0xb5, 0xc0, 0xfb, 0xcf,
    0xe9, 0xb5, 0xdb, 0xa5,
])

# SHA-512 initial hash values (first 16 bytes of H0-H1)
SHA512_H = bytes([
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
    0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
])

# MD5 initial values
MD5_INIT = bytes([
    0x01, 0x23, 0x45, 0x67,  # A
    0x89, 0xab, 0xcd, 0xef,  # B
    0xfe, 0xdc, 0xba, 0x98,  # C
    0x76, 0x54, 0x32, 0x10,  # D
])

# ChaCha20 constants "expand 32-byte k"
CHACHA20_CONSTANTS = b"expand 32-byte k"

# Salsa20 constants "expand 32-byte k"
SALSA20_CONSTANTS = b"expand 32-byte k"

# DES S-box 1 (first 16 bytes)
DES_SBOX1 = bytes([
    14, 4, 13, 1, 2, 15, 11, 8,
    3, 10, 6, 12, 5, 9, 0, 7,
])

# Blowfish P-array (first 16 bytes as hex)
BLOWFISH_P = bytes([
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
])

# RC4 initialization pattern (sequential bytes)
RC4_INIT = bytes(range(16))

# RSA common public exponents
RSA_E_65537 = (65537).to_bytes(3, 'big')
RSA_E_3 = (3).to_bytes(1, 'big')

# ECDSA/ECDH curve parameters (secp256k1 prime, first bytes)
SECP256K1_P = bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
])

# NIST P-256 curve parameter (first bytes of prime)
P256_P = bytes([
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Post-Quantum Cryptography signatures

# Kyber (ML-KEM) zetas for NTT (first 16 bytes as example pattern)
KYBER_ZETAS = bytes([
    0x01, 0x00, 0xd1, 0x0c, 0x9b, 0x0c, 0x84, 0x06,
    0x82, 0x03, 0xb1, 0x05, 0x6e, 0x04, 0x1c, 0x07,
])

# Dilithium (ML-DSA) constants
DILITHIUM_Q = (8380417).to_bytes(4, 'little')

# SPHINCS+ constants
SPHINCS_ADDR_BYTES = 32


# Organized constant database for searching
CRYPTO_CONSTANTS = {
    "aes_sbox": {
        "sbox": AES_SBOX,
        "inv_sbox": AES_INV_SBOX,
    },
    "aes_rcon": {
        "rcon": AES_RCON,
    },
    "sha256": {
        "initial_hash": SHA256_H,
        "round_constants": SHA256_K,
    },
    "sha512": {
        "initial_hash": SHA512_H,
    },
    "md5": {
        "initial_values": MD5_INIT,
    },
    "chacha": {
        "constants": CHACHA20_CONSTANTS,
    },
    "salsa20": {
        "constants": SALSA20_CONSTANTS,
    },
    "des_sbox": {
        "sbox1": DES_SBOX1,
    },
    "blowfish": {
        "p_array": BLOWFISH_P,
    },
    "rc4": {
        "init": RC4_INIT,
    },
    "rsa": {
        "e_65537": RSA_E_65537,
        "e_3": RSA_E_3,
    },
    "ecc": {
        "secp256k1_p": SECP256K1_P,
        "p256_p": P256_P,
    },
    "pqc_kyber": {
        "zetas": KYBER_ZETAS,
    },
    "pqc_dilithium": {
        "q": DILITHIUM_Q,
    },
}


# Algorithm identification by constant presence
ALGORITHM_SIGNATURES = {
    "AES": ["aes_sbox", "aes_rcon"],
    "SHA-256": ["sha256"],
    "SHA-512": ["sha512"],
    "MD5": ["md5"],
    "ChaCha20": ["chacha"],
    "Salsa20": ["salsa20"],
    "DES/3DES": ["des_sbox"],
    "Blowfish": ["blowfish"],
    "RC4": ["rc4"],
    "RSA": ["rsa"],
    "ECDSA/ECDH": ["ecc"],
    "Kyber/ML-KEM": ["pqc_kyber"],
    "Dilithium/ML-DSA": ["pqc_dilithium"],
}


def get_all_patterns() -> dict[str, bytes]:
    """
    Get all crypto patterns as a flat dictionary.
    
    Returns:
        Dictionary mapping pattern names to byte patterns
    """
    patterns = {}
    for category, category_patterns in CRYPTO_CONSTANTS.items():
        for name, pattern in category_patterns.items():
            patterns[f"{category}_{name}"] = pattern
    return patterns


def identify_algorithm(found_patterns: list[str]) -> list[str]:
    """
    Identify likely algorithms based on found patterns.
    
    Args:
        found_patterns: List of pattern category names that were found
        
    Returns:
        List of likely algorithm names
    """
    algorithms = []
    
    for algo, required_patterns in ALGORITHM_SIGNATURES.items():
        if any(p in found_patterns for p in required_patterns):
            algorithms.append(algo)
    
    return algorithms

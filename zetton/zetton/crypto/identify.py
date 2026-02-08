"""
Cryptographic algorithm identification.

This module provides tools for identifying cryptographic implementations
in binary code using both classical pattern matching and quantum-assisted
search techniques.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zetton.core.binary import Binary
    from zetton.quantum.engine import QuantumEngine

logger = logging.getLogger(__name__)


@dataclass
class CryptoFinding:
    """Represents a cryptographic finding in a binary."""
    algorithm: str
    confidence: float
    offset: int
    section: str
    pattern_type: str
    pattern_name: str
    details: dict = field(default_factory=dict)
    
    def __str__(self) -> str:
        return (
            f"{self.algorithm} ({self.confidence:.1%} confidence) "
            f"at offset 0x{self.offset:x} in {self.section}"
        )


class CryptoIdentifier:
    """
    Identifies cryptographic implementations in binaries.
    
    Uses a combination of:
    1. Constant pattern matching (S-boxes, IVs, round constants)
    2. Structural analysis (key schedules, round functions)
    3. Entropy analysis (encrypted data regions)
    4. Quantum-assisted search for large binaries
    
    Example:
        >>> identifier = CryptoIdentifier(binary)
        >>> findings = identifier.identify()
        >>> for f in findings:
        ...     print(f)
    """
    
    # Algorithm name mapping from pattern categories
    ALGORITHM_NAMES = {
        "aes_sbox": "AES",
        "aes_rcon": "AES",
        "sha256": "SHA-256",
        "sha512": "SHA-512",
        "md5": "MD5",
        "chacha": "ChaCha20",
        "salsa20": "Salsa20",
        "des_sbox": "DES/3DES",
        "blowfish": "Blowfish",
        "rc4": "RC4",
        "rsa": "RSA",
        "ecc": "ECDSA/ECDH",
        "pqc_kyber": "Kyber (ML-KEM)",
        "pqc_dilithium": "Dilithium (ML-DSA)",
    }
    
    def __init__(self, binary: Binary):
        """
        Initialize crypto identifier.
        
        Args:
            binary: Binary to analyze
        """
        self.binary = binary
        self.findings: list[CryptoFinding] = []
    
    def identify(
        self,
        quantum_assist: bool = True,
        quantum_engine: QuantumEngine | None = None
    ) -> list[CryptoFinding]:
        """
        Perform comprehensive crypto identification.
        
        Args:
            quantum_assist: Use quantum-assisted search
            quantum_engine: QuantumEngine instance (required if quantum_assist=True)
            
        Returns:
            List of CryptoFinding objects
        """
        self.findings = []
        
        # Pattern-based identification
        self._identify_by_constants(quantum_assist, quantum_engine)
        
        # Entropy analysis
        self._identify_by_entropy()
        
        # Import analysis
        self._identify_by_imports()
        
        # Deduplicate and sort by confidence
        self._deduplicate_findings()
        
        return sorted(self.findings, key=lambda f: -f.confidence)
    
    def _pattern_to_algorithm(self, category: str) -> str:
        """Convert pattern category to algorithm name."""
        return self.ALGORITHM_NAMES.get(category, category.upper())
    
    def _get_section_at_offset(self, offset: int) -> str:
        """Get section name containing the given offset."""
        for section in self.binary.sections:
            if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                return section.name
        return "unknown"
    
    def _identify_by_constants(
        self,
        quantum_assist: bool,
        quantum_engine: QuantumEngine | None
    ) -> None:
        """Identify crypto by searching for known constants."""
        from zetton.crypto.constants import CRYPTO_CONSTANTS
        
        for category, patterns in CRYPTO_CONSTANTS.items():
            for pattern_name, pattern in patterns.items():
                if quantum_assist and quantum_engine is not None:
                    # Use quantum search
                    from zetton.quantum.grover import GroverSearch
                    searcher = GroverSearch(quantum_engine)
                    results = searcher.find_pattern(
                        self.binary.raw_data, pattern, max_results=5
                    )
                    
                    for result in results:
                        section = self._get_section_at_offset(result.offset)
                        self.findings.append(CryptoFinding(
                            algorithm=self._pattern_to_algorithm(category),
                            confidence=min(result.confidence * 1.2, 1.0),
                            offset=result.offset,
                            section=section,
                            pattern_type=category,
                            pattern_name=pattern_name,
                            details={
                                "quantum_advantage": result.quantum_advantage,
                                "iterations": result.iterations_used,
                                "search_method": "quantum",
                            }
                        ))
                else:
                    # Classical search
                    for offset in self.binary.search_bytes(pattern):
                        section = self._get_section_at_offset(offset)
                        self.findings.append(CryptoFinding(
                            algorithm=self._pattern_to_algorithm(category),
                            confidence=0.85,
                            offset=offset,
                            section=section,
                            pattern_type=category,
                            pattern_name=pattern_name,
                            details={"search_method": "classical"}
                        ))
    
    def _identify_by_entropy(self) -> None:
        """Identify potential encrypted/compressed regions by entropy."""
        WINDOW_SIZE = 256
        HIGH_ENTROPY_THRESHOLD = 7.5
        
        data = self.binary.raw_data
        high_entropy_regions = []
        
        for i in range(0, len(data) - WINDOW_SIZE, WINDOW_SIZE):
            window = data[i:i + WINDOW_SIZE]
            entropy = self.binary.calculate_entropy(window)
            
            if entropy >= HIGH_ENTROPY_THRESHOLD:
                high_entropy_regions.append({
                    "offset": i,
                    "entropy": entropy,
                    "size": WINDOW_SIZE,
                })
        
        # Merge adjacent regions
        merged = self._merge_regions(high_entropy_regions)
        
        for region in merged:
            section = self._get_section_at_offset(region["offset"])
            self.findings.append(CryptoFinding(
                algorithm="Encrypted/Compressed Data",
                confidence=0.6,
                offset=region["offset"],
                section=section,
                pattern_type="entropy",
                pattern_name="high_entropy_region",
                details={
                    "entropy": region["entropy"],
                    "size": region["size"],
                    "search_method": "entropy_analysis",
                }
            ))
    
    def _merge_regions(self, regions: list[dict]) -> list[dict]:
        """Merge adjacent high-entropy regions."""
        if not regions:
            return []
        
        merged = [regions[0].copy()]
        
        for region in regions[1:]:
            last = merged[-1]
            if region["offset"] <= last["offset"] + last["size"]:
                # Merge
                new_end = region["offset"] + region["size"]
                last["size"] = new_end - last["offset"]
                last["entropy"] = max(last["entropy"], region["entropy"])
            else:
                merged.append(region.copy())
        
        return merged
    
    def _identify_by_imports(self) -> None:
        """Identify crypto by analyzing imported functions."""
        CRYPTO_IMPORTS = {
            # OpenSSL
            "EVP_EncryptInit": ("OpenSSL", "Symmetric Encryption"),
            "EVP_DecryptInit": ("OpenSSL", "Symmetric Decryption"),
            "RSA_public_encrypt": ("OpenSSL", "RSA"),
            "AES_encrypt": ("OpenSSL", "AES"),
            "SHA256_Init": ("OpenSSL", "SHA-256"),
            "MD5_Init": ("OpenSSL", "MD5"),
            
            # Windows Crypto API
            "CryptEncrypt": ("Windows CryptoAPI", "Encryption"),
            "CryptDecrypt": ("Windows CryptoAPI", "Decryption"),
            "CryptCreateHash": ("Windows CryptoAPI", "Hashing"),
            "BCryptEncrypt": ("Windows BCrypt", "Encryption"),
            "BCryptDecrypt": ("Windows BCrypt", "Decryption"),
            
            # libsodium
            "crypto_secretbox": ("libsodium", "XSalsa20-Poly1305"),
            "crypto_box": ("libsodium", "X25519-XSalsa20-Poly1305"),
            "crypto_sign": ("libsodium", "Ed25519"),
            
            # PQC libraries
            "PQCLEAN_KYBER": ("PQClean", "Kyber (ML-KEM)"),
            "PQCLEAN_DILITHIUM": ("PQClean", "Dilithium (ML-DSA)"),
            "OQS_KEM_kyber": ("liboqs", "Kyber (ML-KEM)"),
            "OQS_SIG_dilithium": ("liboqs", "Dilithium (ML-DSA)"),
        }
        
        for imp in self.binary.imports:
            for func_pattern, (library, algorithm) in CRYPTO_IMPORTS.items():
                if func_pattern in imp.name:
                    self.findings.append(CryptoFinding(
                        algorithm=algorithm,
                        confidence=0.95,
                        offset=imp.address,
                        section="imports",
                        pattern_type="import",
                        pattern_name=imp.name,
                        details={
                            "library": library,
                            "import_library": imp.library,
                            "search_method": "import_analysis",
                        }
                    ))
    
    def _deduplicate_findings(self) -> None:
        """Remove duplicate findings, keeping highest confidence."""
        seen = {}
        
        for finding in self.findings:
            key = (finding.algorithm, finding.offset)
            if key not in seen or finding.confidence > seen[key].confidence:
                seen[key] = finding
        
        self.findings = list(seen.values())
    
    def summary(self) -> dict:
        """
        Get summary of crypto findings.
        
        Returns:
            Dictionary with summary statistics
        """
        if not self.findings:
            return {"algorithms": [], "count": 0}
        
        algorithms = {}
        for finding in self.findings:
            if finding.algorithm not in algorithms:
                algorithms[finding.algorithm] = {
                    "count": 0,
                    "max_confidence": 0,
                    "sections": set(),
                }
            algorithms[finding.algorithm]["count"] += 1
            algorithms[finding.algorithm]["max_confidence"] = max(
                algorithms[finding.algorithm]["max_confidence"],
                finding.confidence
            )
            algorithms[finding.algorithm]["sections"].add(finding.section)
        
        # Convert sets to lists for JSON serialization
        for algo in algorithms.values():
            algo["sections"] = list(algo["sections"])
        
        return {
            "algorithms": algorithms,
            "total_findings": len(self.findings),
            "unique_algorithms": len(algorithms),
            "high_confidence_count": sum(
                1 for f in self.findings if f.confidence >= 0.8
            ),
        }

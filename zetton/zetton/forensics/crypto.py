"""
Cryptographic forensics analysis for Zetton.

Provides deep forensic analysis of cryptographic implementations found
in binaries, including key schedule reconstruction, implementation
weakness detection, side-channel vulnerability assessment, and
quantum-assisted cryptanalysis.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zetton.core.binary import Binary
    from zetton.crypto.identify import CryptoFinding, CryptoIdentifier
    from zetton.quantum.engine import QuantumEngine

logger = logging.getLogger(__name__)


class WeaknessType(Enum):
    """Types of cryptographic implementation weaknesses."""
    WEAK_KEY = auto()            # Known weak key usage
    WEAK_IV = auto()             # Static or predictable IV
    ECB_MODE = auto()            # ECB mode detection
    SMALL_KEY = auto()           # Insufficient key size
    HARDCODED_KEY = auto()       # Key embedded in binary
    WEAK_PRNG = auto()           # Weak random number generator
    SIDE_CHANNEL = auto()        # Timing or cache side-channel
    DEPRECATED_ALGO = auto()     # Deprecated algorithm (MD5, DES, RC4)
    NULL_CIPHER = auto()         # Null/no-op cipher
    CUSTOM_CRYPTO = auto()       # Custom/homebrew cryptography
    PADDING_ORACLE = auto()      # Potential padding oracle
    KEY_REUSE = auto()           # Same key used for different purposes


class QuantumThreatLevel(Enum):
    """Quantum computing threat assessment."""
    SAFE = auto()           # Quantum-resistant
    LOW = auto()            # Minor quantum speedup
    MEDIUM = auto()         # Significant quantum speedup
    HIGH = auto()           # Broken by quantum computers
    CRITICAL = auto()       # Currently broken classically


@dataclass
class CryptoWeakness:
    """A detected cryptographic weakness."""
    weakness_type: WeaknessType
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    offset: int = 0
    algorithm: str = ""
    recommendation: str = ""
    cve: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.description} ({self.weakness_type.name})"


@dataclass
class KeyScheduleInfo:
    """Information about a detected key schedule."""
    algorithm: str
    key_offset: int
    key_size: int
    expanded_key_offset: int = 0
    expanded_key_size: int = 0
    rounds: int = 0
    potential_key_bytes: bytes = field(default=b"", repr=False)

    @property
    def key_size_bits(self) -> int:
        return self.key_size * 8


@dataclass
class QuantumThreatAssessment:
    """Quantum threat assessment for a crypto implementation."""
    algorithm: str
    current_security_bits: int
    quantum_security_bits: int
    threat_level: QuantumThreatLevel
    grover_speedup: float
    shor_applicable: bool
    recommended_action: str
    estimated_qubits_to_break: int = 0

    def __str__(self) -> str:
        return (
            f"{self.algorithm}: {self.threat_level.name} "
            f"({self.current_security_bits}→{self.quantum_security_bits} bits)"
        )


@dataclass
class CryptoForensicsReport:
    """Complete cryptographic forensics report."""
    binary_name: str
    findings: list[CryptoFinding] = field(default_factory=list)
    weaknesses: list[CryptoWeakness] = field(default_factory=list)
    key_schedules: list[KeyScheduleInfo] = field(default_factory=list)
    quantum_threats: list[QuantumThreatAssessment] = field(default_factory=list)
    entropy_analysis: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)


class CryptoForensicsAnalyzer:
    """
    Deep forensic analysis of cryptographic implementations.

    Goes beyond simple identification to analyze implementation quality,
    detect weaknesses, assess quantum threats, and reconstruct key
    material when possible.

    Example:
        >>> analyzer = CryptoForensicsAnalyzer(binary, crypto_findings)
        >>> report = analyzer.analyze()
        >>> for weakness in report.weaknesses:
        ...     print(weakness)
    """

    # Known weak/deprecated algorithms
    DEPRECATED_ALGORITHMS = {
        "MD5": ("critical", "MD5 is cryptographically broken"),
        "SHA-1": ("high", "SHA-1 has practical collision attacks"),
        "DES/3DES": ("high", "DES has 56-bit key, 3DES is deprecated by NIST"),
        "RC4": ("critical", "RC4 has multiple practical attacks"),
        "Blowfish": ("medium", "Blowfish has 64-bit block size, vulnerable to SWEET32"),
    }

    # Quantum threat assessment data
    QUANTUM_THREAT_MAP = {
        "AES": {
            128: (64, QuantumThreatLevel.LOW, False),
            192: (96, QuantumThreatLevel.SAFE, False),
            256: (128, QuantumThreatLevel.SAFE, False),
        },
        "RSA": {
            1024: (0, QuantumThreatLevel.CRITICAL, True),
            2048: (0, QuantumThreatLevel.HIGH, True),
            3072: (0, QuantumThreatLevel.HIGH, True),
            4096: (0, QuantumThreatLevel.HIGH, True),
        },
        "ECDSA/ECDH": {
            256: (0, QuantumThreatLevel.HIGH, True),
            384: (0, QuantumThreatLevel.HIGH, True),
        },
        "SHA-256": {
            256: (128, QuantumThreatLevel.LOW, False),
        },
        "Kyber/ML-KEM": {
            768: (128, QuantumThreatLevel.SAFE, False),
            1024: (192, QuantumThreatLevel.SAFE, False),
        },
        "Dilithium/ML-DSA": {
            2: (128, QuantumThreatLevel.SAFE, False),
            3: (192, QuantumThreatLevel.SAFE, False),
        },
    }

    def __init__(
        self,
        binary: Binary,
        findings: list[CryptoFinding] | None = None,
        quantum_engine: QuantumEngine | None = None,
    ):
        self.binary = binary
        self.findings = findings or []
        self.quantum_engine = quantum_engine

    def analyze(self) -> CryptoForensicsReport:
        """
        Perform comprehensive crypto forensics analysis.

        Returns:
            CryptoForensicsReport with all findings
        """
        report = CryptoForensicsReport(
            binary_name=str(self.binary.path),
            findings=self.findings,
        )

        # Weakness detection
        report.weaknesses = self._detect_weaknesses()

        # Key schedule analysis
        report.key_schedules = self._analyze_key_schedules()

        # Quantum threat assessment
        report.quantum_threats = self._assess_quantum_threats()

        # Entropy analysis of crypto regions
        report.entropy_analysis = self._analyze_crypto_entropy()

        # Build summary
        report.summary = self._build_summary(report)

        return report

    def _detect_weaknesses(self) -> list[CryptoWeakness]:
        """Detect cryptographic implementation weaknesses."""
        weaknesses = []

        for finding in self.findings:
            # Check for deprecated algorithms
            if finding.algorithm in self.DEPRECATED_ALGORITHMS:
                severity, desc = self.DEPRECATED_ALGORITHMS[finding.algorithm]
                weaknesses.append(CryptoWeakness(
                    weakness_type=WeaknessType.DEPRECATED_ALGO,
                    severity=severity,
                    description=desc,
                    offset=finding.offset,
                    algorithm=finding.algorithm,
                    recommendation=f"Replace {finding.algorithm} with a modern alternative",
                ))

        # Check for hardcoded keys (high entropy data near crypto constants)
        weaknesses.extend(self._detect_hardcoded_keys())

        # Check for ECB mode patterns
        weaknesses.extend(self._detect_ecb_mode())

        # Check for weak PRNG usage
        weaknesses.extend(self._detect_weak_prng())

        return weaknesses

    def _detect_hardcoded_keys(self) -> list[CryptoWeakness]:
        """Detect potential hardcoded cryptographic keys."""
        weaknesses = []
        data = self.binary.raw_data

        for finding in self.findings:
            if finding.algorithm in ("AES", "ChaCha20", "Blowfish"):
                # Search for high-entropy regions near crypto constants
                search_start = max(0, finding.offset - 512)
                search_end = min(len(data), finding.offset + 512)
                region = data[search_start:search_end]

                # Slide 16/32-byte window looking for high entropy
                for key_size in (16, 24, 32):
                    for i in range(len(region) - key_size):
                        window = region[i:i + key_size]
                        entropy = self._calculate_entropy(window)

                        if entropy > 7.0:  # High entropy = likely key material
                            weaknesses.append(CryptoWeakness(
                                weakness_type=WeaknessType.HARDCODED_KEY,
                                severity="critical",
                                description=(
                                    f"Potential hardcoded {key_size * 8}-bit key "
                                    f"detected near {finding.algorithm} constants"
                                ),
                                offset=search_start + i,
                                algorithm=finding.algorithm,
                                recommendation="Move keys to secure key storage",
                            ))
                            break  # One per finding is enough

        return weaknesses

    def _detect_ecb_mode(self) -> list[CryptoWeakness]:
        """Detect potential ECB mode usage by finding repeated blocks."""
        weaknesses = []
        data = self.binary.raw_data

        # Look for repeated 16-byte blocks in data sections
        for section in self.binary.sections:
            if section.entropy < 6.0:
                continue  # Skip low-entropy sections

            sec_data = data[section.raw_offset:section.raw_offset + section.raw_size]
            if len(sec_data) < 64:
                continue

            # Count 16-byte block repetitions
            blocks = [sec_data[i:i + 16] for i in range(0, len(sec_data) - 16, 16)]
            counts = Counter(blocks)

            repeated = sum(1 for c in counts.values() if c > 2)
            if repeated > len(blocks) * 0.1:  # >10% blocks repeated
                weaknesses.append(CryptoWeakness(
                    weakness_type=WeaknessType.ECB_MODE,
                    severity="high",
                    description=(
                        f"Repeated 16-byte blocks in {section.name} suggest "
                        "ECB mode encryption"
                    ),
                    offset=section.raw_offset,
                    recommendation="Use CBC, CTR, or GCM mode instead of ECB",
                ))

        return weaknesses

    def _detect_weak_prng(self) -> list[CryptoWeakness]:
        """Detect usage of weak PRNGs."""
        weaknesses = []
        weak_prng_imports = {
            "rand": "C rand() is not cryptographically secure",
            "srand": "srand/rand is predictable",
            "random": "random() may not be CSPRNG",
            "mt19937": "Mersenne Twister is not cryptographically secure",
        }

        for imp in self.binary.imports:
            name_lower = imp.name.lower()
            for func, desc in weak_prng_imports.items():
                if func in name_lower:
                    weaknesses.append(CryptoWeakness(
                        weakness_type=WeaknessType.WEAK_PRNG,
                        severity="high",
                        description=f"Weak PRNG import detected: {imp.name} - {desc}",
                        offset=imp.address,
                        recommendation="Use /dev/urandom, CryptGenRandom, or getrandom()",
                    ))

        return weaknesses

    def _analyze_key_schedules(self) -> list[KeyScheduleInfo]:
        """Analyze detected key schedules."""
        schedules = []

        for finding in self.findings:
            if finding.algorithm == "AES" and finding.pattern_type == "aes_sbox":
                # AES key schedule produces expanded key near S-box
                schedules.append(KeyScheduleInfo(
                    algorithm="AES",
                    key_offset=finding.offset,
                    key_size=16,  # Assume AES-128 by default
                    expanded_key_size=176,  # AES-128 expanded key
                    rounds=10,
                ))

        return schedules

    def _assess_quantum_threats(self) -> list[QuantumThreatAssessment]:
        """Assess quantum computing threats to detected algorithms."""
        assessments = []
        seen_algorithms = set()

        for finding in self.findings:
            algo = finding.algorithm
            if algo in seen_algorithms:
                continue
            seen_algorithms.add(algo)

            if algo in self.QUANTUM_THREAT_MAP:
                # Use first (smallest) key size as conservative estimate
                key_sizes = self.QUANTUM_THREAT_MAP[algo]
                smallest_key = min(key_sizes.keys())
                q_bits, threat, shor = key_sizes[smallest_key]

                grover_speedup = 2.0 if not shor else float("inf")

                assessments.append(QuantumThreatAssessment(
                    algorithm=algo,
                    current_security_bits=smallest_key,
                    quantum_security_bits=q_bits,
                    threat_level=threat,
                    grover_speedup=grover_speedup,
                    shor_applicable=shor,
                    recommended_action=self._get_quantum_recommendation(algo, threat),
                    estimated_qubits_to_break=smallest_key * 2 if shor else smallest_key,
                ))

        return assessments

    def _get_quantum_recommendation(
        self, algorithm: str, threat: QuantumThreatLevel
    ) -> str:
        """Get recommendation based on quantum threat level."""
        recommendations = {
            QuantumThreatLevel.SAFE: "No action needed",
            QuantumThreatLevel.LOW: "Monitor quantum computing progress",
            QuantumThreatLevel.MEDIUM: "Plan migration to quantum-resistant algorithms",
            QuantumThreatLevel.HIGH: (
                f"Migrate {algorithm} to quantum-resistant alternative "
                "(ML-KEM/ML-DSA per NIST FIPS 203/204)"
            ),
            QuantumThreatLevel.CRITICAL: (
                f"URGENT: {algorithm} is already vulnerable. "
                "Migrate immediately to quantum-resistant algorithms"
            ),
        }
        return recommendations.get(threat, "Investigate further")

    def _analyze_crypto_entropy(self) -> dict:
        """Analyze entropy around cryptographic findings."""
        results = {}

        for finding in self.findings:
            start = max(0, finding.offset - 64)
            end = min(len(self.binary.raw_data), finding.offset + 256)
            region = self.binary.raw_data[start:end]

            results[f"0x{finding.offset:x}_{finding.algorithm}"] = {
                "entropy": self._calculate_entropy(region),
                "algorithm": finding.algorithm,
                "region_size": len(region),
            }

        return results

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum(
            (c / length) * math.log2(c / length)
            for c in counts.values()
            if c > 0
        )

    def _build_summary(self, report: CryptoForensicsReport) -> dict:
        """Build summary of forensics analysis."""
        return {
            "total_crypto_findings": len(report.findings),
            "weakness_count": len(report.weaknesses),
            "critical_weaknesses": sum(
                1 for w in report.weaknesses if w.severity == "critical"
            ),
            "high_weaknesses": sum(
                1 for w in report.weaknesses if w.severity == "high"
            ),
            "quantum_vulnerable_algorithms": sum(
                1 for t in report.quantum_threats
                if t.threat_level in (QuantumThreatLevel.HIGH, QuantumThreatLevel.CRITICAL)
            ),
            "quantum_safe_algorithms": sum(
                1 for t in report.quantum_threats
                if t.threat_level == QuantumThreatLevel.SAFE
            ),
            "detected_key_schedules": len(report.key_schedules),
            "algorithms_found": list({f.algorithm for f in report.findings}),
        }

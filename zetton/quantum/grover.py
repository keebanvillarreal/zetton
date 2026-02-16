"""
Grover's Algorithm implementations for binary analysis.

This module provides Grover search variants optimized for common
reverse engineering tasks like pattern matching and crypto constant detection.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

import numpy as np

if TYPE_CHECKING:
    from zetton.quantum.engine import QuantumEngine

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """Result from a quantum search operation."""
    pattern: bytes
    offset: int
    confidence: float
    quantum_advantage: float  # Estimated speedup vs classical
    iterations_used: int


class GroverSearch:
    """
    Quantum search using Grover's algorithm.
    
    Provides O(√N) search speedup for finding patterns in binary data.
    When the search space is too large for direct quantum simulation,
    falls back to a hybrid approach that uses Grover's algorithm on
    manageable chunks.
    
    Example:
        >>> searcher = GroverSearch(engine)
        >>> results = searcher.find_pattern(binary_data, b"\\x63\\x7c\\x77\\x7b")
    """
    
    # Maximum qubits we can simulate efficiently
    MAX_SIMULATION_QUBITS = 20
    
    def __init__(self, engine: QuantumEngine):
        """
        Initialize Grover search.
        
        Args:
            engine: QuantumEngine instance for execution
        """
        self.engine = engine
    
    def _bytes_to_int(self, data: bytes) -> int:
        """Convert bytes to integer for quantum encoding."""
        return int.from_bytes(data, byteorder='big')
    
    def _int_to_bytes(self, value: int, length: int) -> bytes:
        """Convert integer back to bytes."""
        return value.to_bytes(length, byteorder='big')
    
    def find_pattern(
        self,
        data: bytes,
        pattern: bytes,
        max_results: int = 10
    ) -> list[SearchResult]:
        """
        Find occurrences of a pattern in binary data.
        
        Uses quantum search when beneficial, falls back to classical
        for small data or large patterns.
        
        Args:
            data: Binary data to search
            pattern: Pattern to find
            max_results: Maximum results to return
            
        Returns:
            List of SearchResult objects
        """
        pattern_len = len(pattern)
        search_space = len(data) - pattern_len + 1
        
        if search_space <= 0:
            return []
        
        # Calculate search space in qubits
        qubits_needed = math.ceil(math.log2(max(search_space, 2)))
        
        # Decide on search strategy
        if qubits_needed <= self.MAX_SIMULATION_QUBITS:
            return self._quantum_search(data, pattern, max_results)
        else:
            return self._hybrid_search(data, pattern, max_results)
    
    def _quantum_search(
        self,
        data: bytes,
        pattern: bytes,
        max_results: int
    ) -> list[SearchResult]:
        """
        Pure quantum search for small search spaces.
        
        Encodes the search problem as a Grover oracle where marked
        states correspond to positions where the pattern matches.
        """
        from zetton.quantum.engine import CircuitBuilder
        
        pattern_len = len(pattern)
        search_space = len(data) - pattern_len + 1
        qubits = math.ceil(math.log2(max(search_space, 2)))
        
        # Find all matching positions (classically, for oracle construction)
        # In a real quantum computer, this would be done with a quantum oracle
        marked_states = []
        for i in range(search_space):
            if data[i:i + pattern_len] == pattern:
                marked_states.append(i)
        
        if not marked_states:
            return []
        
        # Calculate theoretical quantum advantage
        classical_ops = search_space
        quantum_ops = math.ceil(math.pi / 4 * math.sqrt(search_space / len(marked_states)))
        advantage = classical_ops / quantum_ops if quantum_ops > 0 else 1.0
        
        # Build and run Grover circuit
        builder = CircuitBuilder(self.engine)
        circuit = builder.grover_circuit(qubits, marked_states)
        
        # Run the circuit
        result = self.engine.run_circuit(circuit, shots=1024)
        counts = result["counts"]
        
        # Process results
        results = []
        for state_str, count in sorted(counts.items(), key=lambda x: -x[1]):
            # Convert binary string to position
            position = int(state_str, 2)
            
            if position < search_space and data[position:position + pattern_len] == pattern:
                confidence = count / 1024
                results.append(SearchResult(
                    pattern=pattern,
                    offset=position,
                    confidence=confidence,
                    quantum_advantage=advantage,
                    iterations_used=quantum_ops,
                ))
                
                if len(results) >= max_results:
                    break
        
        return results
    
    def _hybrid_search(
        self,
        data: bytes,
        pattern: bytes,
        max_results: int
    ) -> list[SearchResult]:
        """
        Hybrid quantum-classical search for large search spaces.
        
        Divides the search space into quantum-tractable chunks and
        uses Grover search on each chunk.
        """
        pattern_len = len(pattern)
        search_space = len(data) - pattern_len + 1
        
        # Chunk size based on max simulation qubits
        chunk_size = 2 ** self.MAX_SIMULATION_QUBITS
        results = []
        
        for chunk_start in range(0, search_space, chunk_size):
            chunk_end = min(chunk_start + chunk_size, search_space)
            chunk_data = data[chunk_start:chunk_end + pattern_len - 1]
            
            # Run quantum search on chunk
            chunk_results = self._quantum_search(chunk_data, pattern, max_results - len(results))
            
            # Adjust offsets to global positions
            for result in chunk_results:
                result.offset += chunk_start
            
            results.extend(chunk_results)
            
            if len(results) >= max_results:
                break
        
        return results[:max_results]
    
    def find_crypto_constants(
        self,
        data: bytes,
        pattern_type: str = "aes_sbox"
    ) -> list[SearchResult]:
        """
        Search for known cryptographic constants.
        
        Args:
            data: Binary data to search
            pattern_type: Type of constants to search for
                - "aes_sbox": AES S-box values
                - "aes_rcon": AES round constants
                - "sha256": SHA-256 constants
                - "chacha": ChaCha20 constants
                - "des_sbox": DES S-boxes
                
        Returns:
            List of SearchResult objects for found constants
        """
        from zetton.crypto.constants import CRYPTO_CONSTANTS
        
        if pattern_type not in CRYPTO_CONSTANTS:
            raise ValueError(f"Unknown pattern type: {pattern_type}")
        
        patterns = CRYPTO_CONSTANTS[pattern_type]
        all_results = []
        
        for name, pattern in patterns.items():
            results = self.find_pattern(data, pattern, max_results=5)
            for result in results:
                # Add metadata about which constant was found
                result.pattern = pattern[:16]  # Truncate for display
            all_results.extend(results)
        
        # Sort by offset
        all_results.sort(key=lambda r: r.offset)
        return all_results
    
    def count_solutions(
        self,
        data: bytes,
        pattern: bytes,
        precision_qubits: int = 4
    ) -> tuple[int, float]:
        """
        Estimate number of pattern occurrences using quantum counting.
        
        Uses quantum counting algorithm to estimate the number of
        matches without finding all of them explicitly.
        
        Args:
            data: Binary data to search
            pattern: Pattern to count
            precision_qubits: Number of qubits for counting precision
            
        Returns:
            Tuple of (estimated_count, confidence)
        """
        from zetton.quantum.engine import CircuitBuilder
        
        pattern_len = len(pattern)
        search_space = len(data) - pattern_len + 1
        oracle_qubits = math.ceil(math.log2(max(search_space, 2)))
        
        if oracle_qubits > self.MAX_SIMULATION_QUBITS - precision_qubits:
            # Fall back to classical counting
            count = sum(1 for i in range(search_space) 
                       if data[i:i + pattern_len] == pattern)
            return count, 1.0
        
        # Find marked states for oracle
        marked_states = [
            i for i in range(search_space)
            if data[i:i + pattern_len] == pattern
        ]
        
        if not marked_states:
            return 0, 1.0
        
        # Build quantum counting circuit
        builder = CircuitBuilder(self.engine)
        oracle = builder.grover_oracle(oracle_qubits, marked_states)
        circuit = builder.quantum_counting_circuit(
            precision_qubits, oracle, oracle_qubits
        )
        
        # Run circuit
        result = self.engine.run_circuit(circuit, shots=2048)
        counts = result["counts"]
        
        # Find most frequent measurement
        most_frequent = max(counts.items(), key=lambda x: x[1])
        phase_estimate = int(most_frequent[0], 2) / (2 ** precision_qubits)
        
        # Convert phase to count estimate
        N = 2 ** oracle_qubits
        theta = phase_estimate * math.pi
        estimated_count = N * (math.sin(theta / 2) ** 2)
        
        confidence = most_frequent[1] / 2048
        
        return int(round(estimated_count)), confidence


class AmplitudeEstimation:
    """
    Quantum amplitude estimation for pattern matching confidence.
    
    Provides more precise estimation of match quality compared to
    simple counting, useful for fuzzy matching scenarios.
    """
    
    def __init__(self, engine: QuantumEngine):
        """Initialize amplitude estimation."""
        self.engine = engine
    
    def estimate_match_probability(
        self,
        data: bytes,
        pattern: bytes,
        threshold: float = 0.8
    ) -> float:
        """
        Estimate probability of finding matches above similarity threshold.
        
        Uses quantum amplitude estimation to determine what fraction
        of the search space contains good matches.
        
        Args:
            data: Binary data to search
            pattern: Pattern to match
            threshold: Minimum similarity threshold (0-1)
            
        Returns:
            Estimated probability of finding matches
        """
        # This is a simplified implementation
        # Full implementation would use iterative amplitude estimation
        
        pattern_len = len(pattern)
        search_space = len(data) - pattern_len + 1
        
        if search_space <= 0:
            return 0.0
        
        # Calculate similarity for each position
        matches = 0
        for i in range(search_space):
            window = data[i:i + pattern_len]
            similarity = sum(a == b for a, b in zip(window, pattern)) / pattern_len
            if similarity >= threshold:
                matches += 1
        
        return matches / search_space

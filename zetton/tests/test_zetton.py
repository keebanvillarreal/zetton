"""Tests for Zetton quantum engine."""

import pytest


class TestQuantumEngine:
    """Test suite for QuantumEngine."""
    
    def test_engine_initialization(self):
        """Test that engine initializes correctly."""
        from zetton.quantum.engine import QuantumEngine, BackendType
        
        engine = QuantumEngine()
        assert engine is not None
        assert engine.backend_info is not None
    
    def test_circuit_creation(self):
        """Test circuit creation."""
        pytest.importorskip("qiskit")
        
        from zetton.quantum.engine import QuantumEngine
        
        engine = QuantumEngine()
        circuit = engine.create_circuit(3, 3)
        
        assert circuit.num_qubits == 3
        assert circuit.num_clbits == 3
    
    def test_grover_oracle(self):
        """Test Grover oracle construction."""
        pytest.importorskip("qiskit")
        
        from zetton.quantum.engine import QuantumEngine, CircuitBuilder
        
        engine = QuantumEngine()
        builder = CircuitBuilder(engine)
        
        oracle = builder.grover_oracle(3, [5])
        assert oracle is not None
        assert oracle.num_qubits == 3
    
    def test_grover_circuit(self):
        """Test complete Grover circuit."""
        pytest.importorskip("qiskit")
        
        from zetton.quantum.engine import QuantumEngine, CircuitBuilder
        
        engine = QuantumEngine()
        builder = CircuitBuilder(engine)
        
        circuit = builder.grover_circuit(3, [5], iterations=1)
        assert circuit is not None
        assert circuit.num_qubits == 3
        assert circuit.num_clbits == 3
    
    def test_circuit_execution(self):
        """Test circuit execution on simulator."""
        pytest.importorskip("qiskit")
        pytest.importorskip("qiskit_aer")
        
        from zetton.quantum.engine import QuantumEngine, CircuitBuilder
        
        engine = QuantumEngine()
        builder = CircuitBuilder(engine)
        
        # Create and run a simple Grover circuit
        circuit = builder.grover_circuit(3, [5], iterations=1)
        result = engine.run_circuit(circuit, shots=100)
        
        assert "counts" in result
        assert result["success"]


class TestGroverSearch:
    """Test suite for GroverSearch."""
    
    def test_pattern_search(self):
        """Test pattern search in binary data."""
        pytest.importorskip("qiskit")
        pytest.importorskip("qiskit_aer")
        
        from zetton.quantum.engine import QuantumEngine
        from zetton.quantum.grover import GroverSearch
        
        engine = QuantumEngine()
        searcher = GroverSearch(engine)
        
        # Create test data with a known pattern
        data = b"\x00" * 100 + b"\x63\x7c\x77\x7b" + b"\x00" * 100
        pattern = b"\x63\x7c\x77\x7b"
        
        results = searcher.find_pattern(data, pattern)
        
        assert len(results) > 0
        assert results[0].offset == 100
    
    def test_crypto_constant_search(self):
        """Test crypto constant detection."""
        pytest.importorskip("qiskit")
        pytest.importorskip("qiskit_aer")
        
        from zetton.quantum.engine import QuantumEngine
        from zetton.quantum.grover import GroverSearch
        from zetton.crypto.constants import AES_SBOX
        
        engine = QuantumEngine()
        searcher = GroverSearch(engine)
        
        # Create test data with AES S-box
        data = b"\x00" * 50 + AES_SBOX + b"\x00" * 50
        
        results = searcher.find_crypto_constants(data, "aes_sbox")
        
        assert len(results) > 0


class TestBinary:
    """Test suite for Binary class."""
    
    def test_elf_detection(self):
        """Test ELF format detection."""
        from zetton.core.binary import Binary, BinaryFormat
        
        # Minimal ELF header
        elf_data = b"\x7fELF" + b"\x00" * 60
        binary = Binary.from_bytes(elf_data)
        
        assert binary.format == BinaryFormat.ELF
    
    def test_pe_detection(self):
        """Test PE format detection."""
        from zetton.core.binary import Binary, BinaryFormat
        
        # Minimal PE header
        pe_data = b"MZ" + b"\x00" * 62
        binary = Binary.from_bytes(pe_data)
        
        assert binary.format == BinaryFormat.PE
    
    def test_entropy_calculation(self):
        """Test entropy calculation."""
        from zetton.core.binary import Binary
        
        # Low entropy data (all zeros)
        low_entropy = b"\x00" * 256
        binary = Binary.from_bytes(low_entropy)
        assert binary.calculate_entropy() == 0.0
        
        # High entropy data (random-ish)
        high_entropy = bytes(range(256))
        binary = Binary.from_bytes(high_entropy)
        assert binary.calculate_entropy() == 8.0  # Maximum entropy
    
    def test_byte_search(self):
        """Test byte pattern search."""
        from zetton.core.binary import Binary
        
        data = b"AAAA" + b"PATTERN" + b"BBBB" + b"PATTERN" + b"CCCC"
        binary = Binary.from_bytes(data)
        
        offsets = list(binary.search_bytes(b"PATTERN"))
        assert len(offsets) == 2
        assert offsets[0] == 4
        assert offsets[1] == 18


class TestCryptoIdentifier:
    """Test suite for CryptoIdentifier."""
    
    def test_aes_detection(self):
        """Test AES S-box detection."""
        from zetton.core.binary import Binary
        from zetton.crypto.identify import CryptoIdentifier
        from zetton.crypto.constants import AES_SBOX
        
        # Binary with embedded AES S-box
        data = b"\x7fELF" + b"\x00" * 60 + AES_SBOX + b"\x00" * 100
        binary = Binary.from_bytes(data)
        
        identifier = CryptoIdentifier(binary)
        findings = identifier.identify(quantum_assist=False)
        
        aes_findings = [f for f in findings if "AES" in f.algorithm]
        assert len(aes_findings) > 0
    
    def test_sha256_detection(self):
        """Test SHA-256 constant detection."""
        from zetton.core.binary import Binary
        from zetton.crypto.identify import CryptoIdentifier
        from zetton.crypto.constants import SHA256_H
        
        # Binary with embedded SHA-256 constants
        data = b"\x7fELF" + b"\x00" * 60 + SHA256_H + b"\x00" * 100
        binary = Binary.from_bytes(data)
        
        identifier = CryptoIdentifier(binary)
        findings = identifier.identify(quantum_assist=False)
        
        sha_findings = [f for f in findings if "SHA" in f.algorithm]
        assert len(sha_findings) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

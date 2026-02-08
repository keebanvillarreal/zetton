#!/usr/bin/env python3
"""
Zetton Demonstration Example

This script demonstrates Zetton's quantum-assisted binary analysis capabilities.
It creates a sample binary with embedded crypto constants and shows how Zetton
can detect them using both classical and quantum-assisted methods.
"""

import struct
import tempfile
from pathlib import Path


def create_sample_binary() -> bytes:
    """
    Create a minimal ELF binary with embedded crypto constants.
    
    This simulates a binary that uses AES and SHA-256.
    """
    # AES S-box (first 32 bytes)
    aes_sbox = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    ])
    
    # SHA-256 initial hash values
    sha256_h = bytes([
        0x6a, 0x09, 0xe6, 0x67,
        0xbb, 0x67, 0xae, 0x85,
        0x3c, 0x6e, 0xf3, 0x72,
        0xa5, 0x4f, 0xf5, 0x3a,
        0x51, 0x0e, 0x52, 0x7f,
        0x9b, 0x05, 0x68, 0x8c,
        0x1f, 0x83, 0xd9, 0xab,
        0x5b, 0xe0, 0xcd, 0x19,
    ])
    
    # ChaCha20 constants
    chacha_const = b"expand 32-byte k"
    
    # Build minimal ELF header (64-bit little-endian)
    elf_header = bytearray(64)
    
    # ELF magic
    elf_header[0:4] = b"\x7fELF"
    
    # Class (64-bit)
    elf_header[4] = 2
    
    # Endianness (little)
    elf_header[5] = 1
    
    # Version
    elf_header[6] = 1
    
    # OS/ABI (System V)
    elf_header[7] = 0
    
    # Padding
    elf_header[8:16] = b"\x00" * 8
    
    # Type (executable)
    struct.pack_into("<H", elf_header, 16, 2)
    
    # Machine (x86-64)
    struct.pack_into("<H", elf_header, 18, 0x3e)
    
    # Version
    struct.pack_into("<I", elf_header, 20, 1)
    
    # Entry point
    struct.pack_into("<Q", elf_header, 24, 0x401000)
    
    # Program header offset
    struct.pack_into("<Q", elf_header, 32, 64)
    
    # Section header offset (we'll skip this for simplicity)
    struct.pack_into("<Q", elf_header, 40, 0)
    
    # Flags
    struct.pack_into("<I", elf_header, 48, 0)
    
    # ELF header size
    struct.pack_into("<H", elf_header, 52, 64)
    
    # Program header entry size
    struct.pack_into("<H", elf_header, 54, 56)
    
    # Number of program headers
    struct.pack_into("<H", elf_header, 56, 1)
    
    # Build program header (LOAD segment)
    program_header = bytearray(56)
    
    # Type (LOAD)
    struct.pack_into("<I", program_header, 0, 1)
    
    # Flags (R+X)
    struct.pack_into("<I", program_header, 4, 5)
    
    # Offset
    struct.pack_into("<Q", program_header, 8, 0)
    
    # Virtual address
    struct.pack_into("<Q", program_header, 16, 0x400000)
    
    # Physical address
    struct.pack_into("<Q", program_header, 24, 0x400000)
    
    # File size
    struct.pack_into("<Q", program_header, 32, 0x1000)
    
    # Memory size
    struct.pack_into("<Q", program_header, 40, 0x1000)
    
    # Alignment
    struct.pack_into("<Q", program_header, 48, 0x1000)
    
    # Build code section with embedded crypto
    code = bytearray(0x1000 - 64 - 56)  # Pad to 4KB
    
    # Add some x86-64 code (just NOPs and return for simplicity)
    code[0:10] = b"\x90" * 10  # NOPs
    code[10] = 0xc3  # RET
    
    # Embed crypto constants at various offsets
    code[0x100:0x100 + len(aes_sbox)] = aes_sbox
    code[0x200:0x200 + len(sha256_h)] = sha256_h
    code[0x300:0x300 + len(chacha_const)] = chacha_const
    
    # Some padding that looks like encrypted data (high entropy)
    import random
    random.seed(42)
    encrypted_data = bytes(random.randint(0, 255) for _ in range(256))
    code[0x400:0x400 + len(encrypted_data)] = encrypted_data
    
    # Combine all parts
    binary = bytes(elf_header) + bytes(program_header) + bytes(code)
    
    return binary


def demo_classical_analysis():
    """Demonstrate classical (non-quantum) analysis."""
    print("\n" + "=" * 60)
    print("CLASSICAL ANALYSIS DEMO")
    print("=" * 60)
    
    from zetton.core.binary import Binary
    from zetton.crypto.identify import CryptoIdentifier
    
    # Create sample binary
    binary_data = create_sample_binary()
    binary = Binary.from_bytes(binary_data, "sample_crypto.elf")
    
    print(f"\nBinary Info:")
    print(f"  Format: {binary.format.name}")
    print(f"  Architecture: {binary.architecture.name}")
    print(f"  Size: {len(binary.raw_data)} bytes")
    print(f"  Entry: 0x{binary.entry_point:x}")
    
    # Run crypto identification
    identifier = CryptoIdentifier(binary)
    findings = identifier.identify(quantum_assist=False)
    
    print(f"\nCrypto Findings ({len(findings)} total):")
    for f in findings:
        print(f"  - {f.algorithm}: {f.confidence:.0%} confidence at 0x{f.offset:x}")
    
    return binary


def demo_quantum_analysis():
    """Demonstrate quantum-assisted analysis."""
    print("\n" + "=" * 60)
    print("QUANTUM-ASSISTED ANALYSIS DEMO")
    print("=" * 60)
    
    try:
        from qiskit import QuantumCircuit
        from qiskit_aer import AerSimulator
        qiskit_available = True
    except ImportError:
        print("\nQiskit not installed. Showing simulated quantum analysis.")
        print("Install with: pip install qiskit qiskit-aer")
        qiskit_available = False
        return
    
    from zetton.core.binary import Binary
    from zetton.crypto.identify import CryptoIdentifier
    from zetton.quantum.engine import QuantumEngine
    from zetton.quantum.grover import GroverSearch
    
    # Create sample binary
    binary_data = create_sample_binary()
    binary = Binary.from_bytes(binary_data, "sample_crypto.elf")
    
    # Initialize quantum engine
    print("\nInitializing quantum engine...")
    engine = QuantumEngine()
    print(f"  Backend: {engine.backend_info['type']}")
    print(f"  Max qubits: {engine.backend_info['max_qubits']}")
    
    # Run quantum-assisted crypto identification
    print("\nRunning quantum-assisted crypto identification...")
    identifier = CryptoIdentifier(binary)
    findings = identifier.identify(quantum_assist=True, quantum_engine=engine)
    
    print(f"\nQuantum-Assisted Findings ({len(findings)} total):")
    for f in findings:
        advantage = f.details.get("quantum_advantage", 1.0)
        method = f.details.get("search_method", "unknown")
        print(f"  - {f.algorithm}: {f.confidence:.0%} confidence")
        print(f"    Offset: 0x{f.offset:x}, Method: {method}")
        if advantage > 1:
            print(f"    Quantum advantage: {advantage:.1f}x speedup")


def demo_grover_search():
    """Demonstrate Grover's algorithm for pattern search."""
    print("\n" + "=" * 60)
    print("GROVER'S ALGORITHM DEMO")
    print("=" * 60)
    
    try:
        from qiskit import QuantumCircuit
        from qiskit_aer import AerSimulator
    except ImportError:
        print("\nQiskit not installed. Skipping Grover demo.")
        return
    
    from zetton.quantum.engine import QuantumEngine, CircuitBuilder
    
    # Small example: search for marked state in 8-element space
    print("\nSearching for marked states in 8-element space (3 qubits)...")
    print("Marked states: [3, 6] (binary: 011, 110)")
    
    engine = QuantumEngine()
    builder = CircuitBuilder(engine)
    
    # Build Grover circuit
    circuit = builder.grover_circuit(
        num_qubits=3,
        marked_states=[3, 6],
        iterations=1  # Optimal for 2 solutions in 8 elements
    )
    
    print(f"\nCircuit depth: {circuit.depth()}")
    print(f"Gate count: {len(circuit.data)}")
    
    # Run the circuit
    result = engine.run_circuit(circuit, shots=1000)
    counts = result["counts"]
    
    print("\nMeasurement results:")
    for state, count in sorted(counts.items(), key=lambda x: -x[1]):
        prob = count / 1000
        binary_rep = state
        decimal_rep = int(state, 2)
        marker = " <-- MARKED" if decimal_rep in [3, 6] else ""
        print(f"  |{binary_rep}⟩ ({decimal_rep}): {prob:.1%}{marker}")
    
    # Show quantum advantage
    classical_ops = 8  # Linear search
    quantum_ops = 1    # Single Grover iteration
    print(f"\nClassical operations needed: O({classical_ops})")
    print(f"Quantum operations used: O(√{8}) ≈ {quantum_ops}")


def demo_crypto_constants():
    """Show the crypto constants database."""
    print("\n" + "=" * 60)
    print("CRYPTO CONSTANTS DATABASE")
    print("=" * 60)
    
    from zetton.crypto.constants import CRYPTO_CONSTANTS, ALGORITHM_SIGNATURES
    
    print("\nSupported algorithms:")
    for algo, patterns in ALGORITHM_SIGNATURES.items():
        print(f"  - {algo}: {', '.join(patterns)}")
    
    print("\nPattern categories:")
    for category, patterns in CRYPTO_CONSTANTS.items():
        total_bytes = sum(len(p) for p in patterns.values())
        print(f"  - {category}: {len(patterns)} patterns, {total_bytes} bytes total")


def main():
    """Run all demos."""
    print("=" * 60)
    print("  ZETTON - Quantum-Assisted Binary Analysis Framework")
    print("  Demonstration Script")
    print("=" * 60)
    
    # Show crypto constants
    demo_crypto_constants()
    
    # Classical analysis
    demo_classical_analysis()
    
    # Quantum analysis
    demo_quantum_analysis()
    
    # Grover's algorithm demo
    demo_grover_search()
    
    print("\n" + "=" * 60)
    print("Demo complete! Try Zetton on your own binaries:")
    print("  zetton analyze <binary>")
    print("  zetton crypto --quantum <binary>")
    print("  zetton disasm <binary>")
    print("=" * 60)


if __name__ == "__main__":
    main()

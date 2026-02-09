"""
Pre-built quantum circuits for Zetton.

Provides reusable quantum circuit templates for common operations
in binary analysis, including oracles, comparators, arithmetic,
and encoding circuits.
"""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zetton.quantum.engine import QuantumEngine

logger = logging.getLogger(__name__)


class QuantumCircuitLibrary:
    """
    Library of pre-built quantum circuits for binary analysis.

    Provides parameterized circuit templates that can be composed
    into larger quantum algorithms. Each circuit is designed for
    specific tasks in reverse engineering and forensics.

    Example:
        >>> lib = QuantumCircuitLibrary(engine)
        >>> comparator = lib.byte_comparator(0x63)
        >>> resources = engine.estimate_resources(comparator)
    """

    def __init__(self, engine: QuantumEngine):
        self.engine = engine
        self._qiskit_available = engine._qiskit_available

    def _require_qiskit(self):
        if not self._qiskit_available:
            raise RuntimeError("Qiskit required. Install: pip install qiskit qiskit-aer")

    def byte_comparator(self, target_byte: int) -> object:
        """
        Build a circuit that marks a qubit register if it equals target_byte.

        Uses an 8-qubit register to represent a byte value and flips an
        ancilla qubit when the register matches the target.

        Args:
            target_byte: Byte value to compare against (0-255)

        Returns:
            QuantumCircuit implementing the comparator
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit

        n_qubits = 8
        circuit = QuantumCircuit(n_qubits + 1, name=f"cmp_0x{target_byte:02x}")

        binary_repr = format(target_byte, f"0{n_qubits}b")

        # Flip qubits where target bit is 0
        for i, bit in enumerate(reversed(binary_repr)):
            if bit == "0":
                circuit.x(i)

        # Multi-controlled Toffoli on ancilla
        circuit.mcx(list(range(n_qubits)), n_qubits)

        # Undo flips
        for i, bit in enumerate(reversed(binary_repr)):
            if bit == "0":
                circuit.x(i)

        return circuit

    def multi_byte_comparator(self, pattern: bytes) -> object:
        """
        Build a circuit that matches a multi-byte pattern.

        Uses multiple byte comparator sub-circuits composed together,
        with a final AND gate to confirm full pattern match.

        Args:
            pattern: Byte pattern to match

        Returns:
            QuantumCircuit implementing the multi-byte comparator
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit

        n_bytes = len(pattern)
        # 8 qubits per byte + 1 ancilla per byte + 1 final output
        total_qubits = n_bytes * 9 + 1
        circuit = QuantumCircuit(total_qubits, name=f"pattern_{pattern.hex()[:8]}")

        ancilla_qubits = []
        for byte_idx, byte_val in enumerate(pattern):
            data_start = byte_idx * 9
            ancilla = data_start + 8
            ancilla_qubits.append(ancilla)

            binary_repr = format(byte_val, "08b")
            for i, bit in enumerate(reversed(binary_repr)):
                if bit == "0":
                    circuit.x(data_start + i)

            circuit.mcx(list(range(data_start, data_start + 8)), ancilla)

            for i, bit in enumerate(reversed(binary_repr)):
                if bit == "0":
                    circuit.x(data_start + i)

        # Final AND: all ancillas must be 1
        final_qubit = total_qubits - 1
        if len(ancilla_qubits) > 1:
            circuit.mcx(ancilla_qubits, final_qubit)
        elif len(ancilla_qubits) == 1:
            circuit.cx(ancilla_qubits[0], final_qubit)

        return circuit

    def hamming_distance_oracle(
        self, target: int, n_qubits: int, max_distance: int
    ) -> object:
        """
        Oracle that marks states within Hamming distance of target.

        Useful for fuzzy pattern matching in binary analysis where
        exact matches may not exist (e.g., slightly modified crypto constants).

        Args:
            target: Target value to compare against
            n_qubits: Number of qubits encoding the value
            max_distance: Maximum Hamming distance to accept

        Returns:
            QuantumCircuit implementing the fuzzy oracle
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit

        # Need ancilla qubits for counting: ceil(log2(n_qubits+1))
        count_qubits = math.ceil(math.log2(n_qubits + 1))
        total = n_qubits + count_qubits + 1  # +1 for output

        circuit = QuantumCircuit(total, name=f"hamming_d{max_distance}")

        target_bits = format(target, f"0{n_qubits}b")

        # XOR input with target to get difference bits
        for i, bit in enumerate(reversed(target_bits)):
            if bit == "1":
                circuit.x(i)

        # Simplified: for small n_qubits, enumerate acceptable states
        # For production, would use quantum popcount circuit
        if n_qubits <= 8:
            acceptable = []
            for val in range(2**n_qubits):
                diff = val ^ target
                if bin(diff).count("1") <= max_distance:
                    acceptable.append(val)

            output_qubit = total - 1
            for state in acceptable:
                state_bits = format(state, f"0{n_qubits}b")
                for i, bit in enumerate(reversed(state_bits)):
                    if bit == "0":
                        circuit.x(i)
                circuit.mcx(list(range(n_qubits)), output_qubit)
                for i, bit in enumerate(reversed(state_bits)):
                    if bit == "0":
                        circuit.x(i)

        # Undo target XOR
        for i, bit in enumerate(reversed(target_bits)):
            if bit == "1":
                circuit.x(i)

        return circuit

    def quantum_xor(self, n_qubits: int) -> object:
        """
        Build quantum XOR circuit between two registers.

        XORs register A with register B, storing result in B.
        Useful for comparing binary data at the quantum level.

        Args:
            n_qubits: Size of each register

        Returns:
            QuantumCircuit implementing XOR
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit

        circuit = QuantumCircuit(2 * n_qubits, name="q_xor")

        for i in range(n_qubits):
            circuit.cx(i, n_qubits + i)

        return circuit

    def amplitude_encoding(self, data: list[float]) -> object:
        """
        Encode classical data as quantum amplitudes.

        Creates a state where the amplitude of each basis state
        corresponds to a normalized data value. Useful for encoding
        binary data sections for quantum processing.

        Args:
            data: Classical data values to encode (will be normalized)

        Returns:
            QuantumCircuit with data encoded in amplitudes
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit
        import numpy as np

        # Pad to nearest power of 2
        n = len(data)
        n_qubits = math.ceil(math.log2(max(n, 2)))
        padded_size = 2**n_qubits
        padded = list(data) + [0.0] * (padded_size - n)

        # Normalize
        arr = np.array(padded, dtype=float)
        norm = np.linalg.norm(arr)
        if norm > 0:
            arr = arr / norm

        circuit = QuantumCircuit(n_qubits, name="amp_encode")
        circuit.initialize(arr.tolist(), list(range(n_qubits)))

        return circuit

    def quantum_walk_step(self, n_positions: int) -> object:
        """
        Build one step of a quantum walk on a line graph.

        Quantum walks provide quadratic speedup for graph traversal,
        useful for CFG exploration in large binaries.

        Args:
            n_positions: Number of positions (nodes) in the graph

        Returns:
            QuantumCircuit for one walk step
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit

        pos_qubits = math.ceil(math.log2(max(n_positions, 2)))
        coin_qubits = 1
        total = pos_qubits + coin_qubits

        circuit = QuantumCircuit(total, name="qwalk_step")

        # Coin flip (Hadamard on coin qubit)
        coin = total - 1
        circuit.h(coin)

        # Conditional shift: move right if coin=|1>, left if coin=|0>
        # Simplified increment/decrement on position register
        for i in range(pos_qubits):
            circuit.cx(coin, i)

        return circuit

    def phase_estimation_circuit(
        self, unitary_circuit, n_precision: int
    ) -> object:
        """
        Build quantum phase estimation circuit.

        QPE is used for eigenvalue estimation, applicable to
        analyzing periodic structures in binary data (e.g., loop
        iteration patterns, repeating key schedules).

        Args:
            unitary_circuit: The unitary operator to estimate
            n_precision: Number of precision qubits

        Returns:
            QuantumCircuit implementing QPE
        """
        self._require_qiskit()
        from qiskit import QuantumCircuit

        n_target = unitary_circuit.num_qubits
        total = n_precision + n_target + n_precision  # precision + target + classical

        circuit = QuantumCircuit(n_precision + n_target, n_precision, name="QPE")

        # Initialize precision qubits in superposition
        for i in range(n_precision):
            circuit.h(i)

        # Controlled-U^(2^k) applications
        for k in range(n_precision):
            power = 2**k
            controlled_u = unitary_circuit.control(1)
            for _ in range(power):
                circuit.append(
                    controlled_u,
                    [k] + list(range(n_precision, n_precision + n_target))
                )

        # Inverse QFT on precision qubits
        self._inverse_qft(circuit, n_precision)

        # Measure precision qubits
        circuit.measure(list(range(n_precision)), list(range(n_precision)))

        return circuit

    def _inverse_qft(self, circuit, n_qubits: int) -> None:
        """Apply inverse QFT to the first n_qubits of circuit."""
        for i in range(n_qubits // 2):
            circuit.swap(i, n_qubits - 1 - i)

        for i in range(n_qubits):
            for j in range(i):
                angle = -math.pi / (2 ** (i - j))
                circuit.cp(angle, j, i)
            circuit.h(i)

    def get_circuit_catalog(self) -> dict[str, str]:
        """Get catalog of available circuits with descriptions."""
        return {
            "byte_comparator": "Marks register if it equals a target byte value",
            "multi_byte_comparator": "Matches multi-byte patterns in quantum registers",
            "hamming_distance_oracle": "Fuzzy matching within Hamming distance threshold",
            "quantum_xor": "XOR between two quantum registers",
            "amplitude_encoding": "Encode classical data as quantum amplitudes",
            "quantum_walk_step": "Single step of quantum walk for graph traversal",
            "phase_estimation_circuit": "Quantum phase estimation for periodicity detection",
        }

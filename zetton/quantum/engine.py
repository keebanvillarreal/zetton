"""
Quantum Engine for Zetton.

This module provides the core quantum computing infrastructure, including
circuit construction, simulation backends, and execution management.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

import numpy as np

logger = logging.getLogger(__name__)


class BackendType(Enum):
    """Available quantum backend types."""
    SIMULATOR_STATEVECTOR = auto()  # Exact simulation (limited qubits)
    SIMULATOR_AER = auto()           # Shot-based simulation
    SIMULATOR_MATRIX = auto()        # Matrix product state simulation
    IBM_QUANTUM = auto()             # IBM Quantum hardware
    AWS_BRAKET = auto()              # AWS Braket hardware


@dataclass
class QuantumJob:
    """Represents a quantum computation job."""
    job_id: str
    circuit_name: str
    backend: str
    shots: int
    status: str = "pending"
    results: dict | None = None
    error: str | None = None


@dataclass
class ExecutionConfig:
    """Configuration for quantum execution."""
    shots: int = 1024
    optimization_level: int = 1
    seed: int | None = None
    max_parallel_threads: int = 0  # 0 = auto
    noise_model: Any = None


class QuantumEngine:
    """
    Core quantum execution engine for Zetton.
    
    Manages quantum circuit construction, backend selection, and execution.
    Provides both synchronous and asynchronous interfaces for running
    quantum algorithms.
    
    Example:
        >>> engine = QuantumEngine()
        >>> engine.set_backend(BackendType.SIMULATOR_AER)
        >>> results = engine.run_circuit(my_circuit, shots=1000)
    """
    
    def __init__(
        self,
        backend: BackendType = BackendType.SIMULATOR_AER,
        config: ExecutionConfig | None = None
    ):
        """
        Initialize the quantum engine.
        
        Args:
            backend: Default backend to use
            config: Execution configuration
        """
        self.config = config or ExecutionConfig()
        self._backend_type = backend
        self._backend = None
        self._jobs: dict[str, QuantumJob] = {}
        self._qiskit_available = self._check_qiskit()
        
        if self._qiskit_available:
            self._initialize_backend(backend)
    
    def _check_qiskit(self) -> bool:
        """Check if Qiskit is available."""
        try:
            import qiskit
            from qiskit_aer import AerSimulator
            return True
        except ImportError:
            logger.warning(
                "Qiskit not available. Install with: pip install qiskit qiskit-aer"
            )
            return False
    
    def _initialize_backend(self, backend_type: BackendType) -> None:
        """Initialize the specified backend."""
        if not self._qiskit_available:
            return
        
        from qiskit_aer import AerSimulator
        
        if backend_type == BackendType.SIMULATOR_STATEVECTOR:
            self._backend = AerSimulator(method='statevector')
        elif backend_type == BackendType.SIMULATOR_AER:
            self._backend = AerSimulator()
        elif backend_type == BackendType.SIMULATOR_MATRIX:
            self._backend = AerSimulator(method='matrix_product_state')
        elif backend_type == BackendType.IBM_QUANTUM:
            self._backend = self._connect_ibm()
        elif backend_type == BackendType.AWS_BRAKET:
            self._backend = self._connect_braket()
        
        self._backend_type = backend_type
    
    def _connect_ibm(self):
        """Connect to IBM Quantum backend."""
        try:
            from qiskit_ibm_runtime import QiskitRuntimeService
            service = QiskitRuntimeService()
            # Get least busy backend with enough qubits
            return service.least_busy(min_num_qubits=5)
        except ImportError:
            logger.error("IBM Quantum runtime not installed")
            return None
        except Exception as e:
            logger.error(f"Failed to connect to IBM Quantum: {e}")
            return None
    
    def _connect_braket(self):
        """Connect to AWS Braket backend."""
        try:
            from braket.aws import AwsDevice
            # Default to IonQ simulator
            return AwsDevice("arn:aws:braket:::device/quantum-simulator/amazon/sv1")
        except ImportError:
            logger.error("AWS Braket SDK not installed")
            return None
        except Exception as e:
            logger.error(f"Failed to connect to AWS Braket: {e}")
            return None
    
    def set_backend(self, backend: BackendType) -> None:
        """
        Change the execution backend.
        
        Args:
            backend: New backend type
        """
        self._initialize_backend(backend)
    
    @property
    def backend_info(self) -> dict:
        """Get information about current backend."""
        return {
            "type": self._backend_type.name,
            "available": self._backend is not None,
            "qiskit_available": self._qiskit_available,
            "max_qubits": self._get_max_qubits(),
        }
    
    def _get_max_qubits(self) -> int:
        """Get maximum qubits supported by current backend."""
        if not self._qiskit_available or self._backend is None:
            return 0
        
        # Simulator limits depend on available memory
        if self._backend_type in [
            BackendType.SIMULATOR_STATEVECTOR,
            BackendType.SIMULATOR_AER
        ]:
            return 30  # Practical limit for statevector simulation
        elif self._backend_type == BackendType.SIMULATOR_MATRIX:
            return 50  # MPS can handle more qubits
        else:
            # Hardware backends have fixed qubit counts
            try:
                return self._backend.num_qubits
            except:
                return 0
    
    def create_circuit(self, num_qubits: int, num_classical: int | None = None):
        """
        Create a new quantum circuit.
        
        Args:
            num_qubits: Number of qubits
            num_classical: Number of classical bits (defaults to num_qubits)
            
        Returns:
            Qiskit QuantumCircuit object
        """
        if not self._qiskit_available:
            raise RuntimeError("Qiskit not available")
        
        from qiskit import QuantumCircuit
        
        if num_classical is None:
            num_classical = num_qubits
        
        return QuantumCircuit(num_qubits, num_classical)
    
    def run_circuit(
        self,
        circuit,
        shots: int | None = None,
        optimization_level: int | None = None
    ) -> dict:
        """
        Execute a quantum circuit and return results.
        
        Args:
            circuit: Qiskit QuantumCircuit to execute
            shots: Number of shots (overrides config)
            optimization_level: Transpiler optimization level
            
        Returns:
            Dictionary with measurement results
        """
        if not self._qiskit_available:
            raise RuntimeError("Qiskit not available")
        
        if self._backend is None:
            raise RuntimeError("No backend configured")
        
        from qiskit import transpile
        
        shots = shots or self.config.shots
        opt_level = optimization_level or self.config.optimization_level
        
        # Transpile for target backend
        transpiled = transpile(
            circuit,
            self._backend,
            optimization_level=opt_level,
            seed_transpiler=self.config.seed,
        )
        
        # Execute
        job = self._backend.run(transpiled, shots=shots)
        result = job.result()
        
        # Extract counts
        counts = result.get_counts()
        
        return {
            "counts": counts,
            "shots": shots,
            "success": result.success,
            "backend": self._backend_type.name,
        }
    
    def run_statevector(self, circuit) -> np.ndarray:
        """
        Get the full statevector from a circuit (no measurement).
        
        Args:
            circuit: Quantum circuit (should not have measurements)
            
        Returns:
            Numpy array with statevector amplitudes
        """
        if not self._qiskit_available:
            raise RuntimeError("Qiskit not available")
        
        from qiskit.quantum_info import Statevector
        
        sv = Statevector.from_instruction(circuit)
        return sv.data
    
    def estimate_resources(self, circuit) -> dict:
        """
        Estimate resources needed to run a circuit.
        
        Args:
            circuit: Quantum circuit to analyze
            
        Returns:
            Resource estimates
        """
        if not self._qiskit_available:
            return {"error": "Qiskit not available"}
        
        return {
            "num_qubits": circuit.num_qubits,
            "depth": circuit.depth(),
            "gate_count": len(circuit.data),
            "gates": dict(circuit.count_ops()),
            "classical_bits": circuit.num_clbits,
        }


class CircuitBuilder:
    """
    Helper class for building common quantum circuits.
    
    Provides pre-built circuit templates for common operations used
    in quantum-assisted binary analysis.
    """
    
    def __init__(self, engine: QuantumEngine):
        """
        Initialize circuit builder.
        
        Args:
            engine: QuantumEngine instance
        """
        self.engine = engine
    
    def grover_oracle(self, num_qubits: int, marked_states: list[int]):
        """
        Build a Grover oracle marking specific states.
        
        Args:
            num_qubits: Number of qubits
            marked_states: List of states to mark (as integers)
            
        Returns:
            Oracle circuit
        """
        from qiskit import QuantumCircuit
        
        oracle = QuantumCircuit(num_qubits, name="Oracle")
        
        for state in marked_states:
            # Convert state to binary
            binary = format(state, f'0{num_qubits}b')
            
            # Apply X gates for 0s
            for i, bit in enumerate(reversed(binary)):
                if bit == '0':
                    oracle.x(i)
            
            # Multi-controlled Z gate
            if num_qubits == 1:
                oracle.z(0)
            else:
                oracle.h(num_qubits - 1)
                oracle.mcx(list(range(num_qubits - 1)), num_qubits - 1)
                oracle.h(num_qubits - 1)
            
            # Undo X gates
            for i, bit in enumerate(reversed(binary)):
                if bit == '0':
                    oracle.x(i)
        
        return oracle
    
    def grover_diffuser(self, num_qubits: int):
        """
        Build Grover diffusion operator.
        
        Args:
            num_qubits: Number of qubits
            
        Returns:
            Diffuser circuit
        """
        from qiskit import QuantumCircuit
        
        diffuser = QuantumCircuit(num_qubits, name="Diffuser")
        
        # Apply H gates
        diffuser.h(range(num_qubits))
        
        # Apply X gates
        diffuser.x(range(num_qubits))
        
        # Multi-controlled Z
        diffuser.h(num_qubits - 1)
        diffuser.mcx(list(range(num_qubits - 1)), num_qubits - 1)
        diffuser.h(num_qubits - 1)
        
        # Undo X and H
        diffuser.x(range(num_qubits))
        diffuser.h(range(num_qubits))
        
        return diffuser
    
    def grover_circuit(
        self,
        num_qubits: int,
        marked_states: list[int],
        iterations: int | None = None
    ):
        """
        Build complete Grover search circuit.
        
        Args:
            num_qubits: Number of qubits (search space = 2^n)
            marked_states: States to find
            iterations: Number of Grover iterations (auto if None)
            
        Returns:
            Complete Grover circuit with measurement
        """
        from qiskit import QuantumCircuit
        import math
        
        # Calculate optimal iterations if not specified
        if iterations is None:
            N = 2 ** num_qubits
            M = len(marked_states)
            iterations = int(round(math.pi / 4 * math.sqrt(N / M)))
            iterations = max(1, iterations)
        
        # Build circuit
        circuit = QuantumCircuit(num_qubits, num_qubits)
        
        # Initial superposition
        circuit.h(range(num_qubits))
        
        # Grover iterations
        oracle = self.grover_oracle(num_qubits, marked_states)
        diffuser = self.grover_diffuser(num_qubits)
        
        for _ in range(iterations):
            circuit.compose(oracle, inplace=True)
            circuit.compose(diffuser, inplace=True)
        
        # Measurement
        circuit.measure(range(num_qubits), range(num_qubits))
        
        return circuit
    
    def quantum_counting_circuit(
        self,
        num_counting_qubits: int,
        oracle,
        num_oracle_qubits: int
    ):
        """
        Build quantum counting circuit to estimate number of solutions.
        
        Args:
            num_counting_qubits: Precision qubits for counting
            oracle: Oracle circuit marking solutions
            num_oracle_qubits: Number of qubits in oracle
            
        Returns:
            Quantum counting circuit
        """
        from qiskit import QuantumCircuit
        from qiskit.circuit.library import QFT
        
        total_qubits = num_counting_qubits + num_oracle_qubits
        circuit = QuantumCircuit(total_qubits, num_counting_qubits)
        
        counting_qubits = list(range(num_counting_qubits))
        oracle_qubits = list(range(num_counting_qubits, total_qubits))
        
        # Hadamard on counting qubits
        circuit.h(counting_qubits)
        
        # Hadamard on oracle qubits for superposition
        circuit.h(oracle_qubits)
        
        # Controlled Grover iterations
        diffuser = self.grover_diffuser(num_oracle_qubits)
        
        for i, ctrl_qubit in enumerate(counting_qubits):
            for _ in range(2 ** i):
                # Controlled oracle
                controlled_oracle = oracle.control(1)
                circuit.compose(
                    controlled_oracle,
                    [ctrl_qubit] + oracle_qubits,
                    inplace=True
                )
                # Controlled diffuser
                controlled_diffuser = diffuser.control(1)
                circuit.compose(
                    controlled_diffuser,
                    [ctrl_qubit] + oracle_qubits,
                    inplace=True
                )
        
        # Inverse QFT on counting qubits
        iqft = QFT(num_counting_qubits, inverse=True)
        circuit.compose(iqft, counting_qubits, inplace=True)
        
        # Measure counting qubits
        circuit.measure(counting_qubits, range(num_counting_qubits))
        
        return circuit

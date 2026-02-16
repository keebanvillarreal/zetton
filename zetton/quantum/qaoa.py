"""
QAOA (Quantum Approximate Optimization Algorithm) for Zetton.

Applies QAOA to combinatorial optimization problems arising in binary
analysis, including constraint satisfaction (SAT solving for symbolic
execution), graph partitioning (function boundary detection), and
optimal path finding (CFG exploration).
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zetton.quantum.engine import QuantumEngine

logger = logging.getLogger(__name__)


@dataclass
class QAOAResult:
    """Result from a QAOA optimization run."""
    optimal_bitstring: str
    optimal_cost: float
    all_solutions: dict[str, float] = field(default_factory=dict)
    convergence_history: list[float] = field(default_factory=list)
    parameters: dict[str, list[float]] = field(default_factory=dict)
    num_iterations: int = 0
    success: bool = False


@dataclass
class SATClause:
    """A clause in a SAT problem (CNF form)."""
    literals: list[int]  # Positive = variable, negative = NOT variable

    def evaluate(self, assignment: dict[int, bool]) -> bool:
        """Evaluate clause with given variable assignment."""
        for lit in self.literals:
            var = abs(lit)
            val = assignment.get(var, False)
            if lit > 0 and val:
                return True
            if lit < 0 and not val:
                return True
        return False

    def __str__(self) -> str:
        parts = []
        for lit in self.literals:
            if lit > 0:
                parts.append(f"x{lit}")
            else:
                parts.append(f"¬x{abs(lit)}")
        return "(" + " ∨ ".join(parts) + ")"


@dataclass
class SATInstance:
    """A SAT problem instance in CNF form."""
    num_variables: int
    clauses: list[SATClause]

    @property
    def num_clauses(self) -> int:
        return len(self.clauses)

    def evaluate(self, assignment: dict[int, bool]) -> tuple[bool, int]:
        """
        Evaluate SAT instance.

        Returns:
            Tuple of (all_satisfied, num_satisfied_clauses)
        """
        satisfied = sum(1 for c in self.clauses if c.evaluate(assignment))
        return satisfied == self.num_clauses, satisfied

    @classmethod
    def from_path_constraints(
        cls, constraints: list[dict]
    ) -> SATInstance:
        """
        Create SAT instance from symbolic execution path constraints.

        Args:
            constraints: List of constraint dicts with 'type', 'variable',
                        and 'value' keys from symbolic execution

        Returns:
            SATInstance encoding the constraints
        """
        clauses = []
        var_map = {}
        next_var = 1

        for constraint in constraints:
            ctype = constraint.get("type", "eq")
            variable = constraint.get("variable", "")
            value = constraint.get("value", 0)

            if variable not in var_map:
                # Encode variable bits
                for bit in range(8):  # 8 bits per byte
                    var_map[f"{variable}_bit{bit}"] = next_var
                    next_var += 1

            # Encode constraint as clauses
            if ctype == "eq":
                for bit in range(8):
                    var_id = var_map[f"{variable}_bit{bit}"]
                    bit_val = (value >> bit) & 1
                    if bit_val:
                        clauses.append(SATClause([var_id]))
                    else:
                        clauses.append(SATClause([-var_id]))

            elif ctype == "neq":
                # At least one bit must differ
                diff_lits = []
                for bit in range(8):
                    var_id = var_map[f"{variable}_bit{bit}"]
                    bit_val = (value >> bit) & 1
                    if bit_val:
                        diff_lits.append(-var_id)
                    else:
                        diff_lits.append(var_id)
                clauses.append(SATClause(diff_lits))

        return cls(num_variables=next_var - 1, clauses=clauses)


class QAOASolver:
    """
    QAOA solver for optimization problems in binary analysis.

    Implements QAOA for:
    1. MAX-SAT: Satisfying path constraints from symbolic execution
    2. Graph partitioning: Function boundary detection in stripped binaries
    3. Max-cut: Identifying independent code regions

    Example:
        >>> solver = QAOASolver(quantum_engine)
        >>> sat = SATInstance(3, [SATClause([1, -2]), SATClause([2, 3])])
        >>> result = solver.solve_maxsat(sat, p=2)
        >>> print(f"Solution: {result.optimal_bitstring}")
    """

    def __init__(self, engine: QuantumEngine, seed: int | None = None):
        self.engine = engine
        self.seed = seed
        self._qiskit_available = engine._qiskit_available

    def _require_qiskit(self):
        if not self._qiskit_available:
            raise RuntimeError("Qiskit required for QAOA")

    def solve_maxsat(
        self,
        instance: SATInstance,
        p: int = 1,
        max_iterations: int = 100,
        shots: int = 1024,
    ) -> QAOAResult:
        """
        Solve MAX-SAT using QAOA.

        Finds variable assignment that satisfies the maximum number of
        clauses. Useful for solving path constraints in symbolic execution.

        Args:
            instance: SAT problem instance
            p: QAOA depth (number of alternating layers)
            max_iterations: Maximum classical optimizer iterations
            shots: Number of circuit measurement shots

        Returns:
            QAOAResult with optimal assignment
        """
        self._require_qiskit()
        import numpy as np

        n = instance.num_variables
        if n > self.engine.config.shots:
            logger.warning(f"Large problem ({n} vars), may be slow")

        # Build cost Hamiltonian coefficients
        cost_coeffs = self._build_maxsat_cost(instance)

        # Initial parameters: gamma and beta for each layer
        rng = np.random.default_rng(self.seed)
        gamma = rng.uniform(0, 2 * np.pi, size=p).tolist()
        beta = rng.uniform(0, np.pi, size=p).tolist()

        # Classical optimization loop
        best_cost = float("-inf")
        best_bitstring = "0" * n
        convergence = []

        for iteration in range(max_iterations):
            # Build and run QAOA circuit
            circuit = self._build_qaoa_circuit(n, cost_coeffs, gamma, beta, p)
            result = self.engine.run_circuit(circuit, shots=shots)
            counts = result.get("counts", {})

            # Evaluate all measured bitstrings
            current_best_cost = float("-inf")
            for bitstring, count in counts.items():
                cost = self._evaluate_maxsat_cost(bitstring, instance)
                if cost > current_best_cost:
                    current_best_cost = cost
                    if cost > best_cost:
                        best_cost = cost
                        best_bitstring = bitstring

            convergence.append(best_cost)

            # Simple parameter update (gradient-free)
            # In production, use COBYLA, SPSA, or other optimizer
            gamma = [g + rng.normal(0, 0.1) for g in gamma]
            beta = [b + rng.normal(0, 0.1) for b in beta]

            # Check convergence
            if best_cost >= instance.num_clauses:
                break  # All clauses satisfied

        return QAOAResult(
            optimal_bitstring=best_bitstring,
            optimal_cost=best_cost,
            all_solutions={best_bitstring: best_cost},
            convergence_history=convergence,
            parameters={"gamma": gamma, "beta": beta},
            num_iterations=iteration + 1,
            success=best_cost >= instance.num_clauses,
        )

    def solve_graph_partition(
        self,
        adjacency: dict[int, list[int]],
        p: int = 1,
        shots: int = 1024,
    ) -> QAOAResult:
        """
        Solve graph partitioning using QAOA (Max-Cut formulation).

        Partitions a graph (e.g., CFG blocks) into two groups that
        minimize inter-group edges. Useful for function boundary
        detection in stripped binaries.

        Args:
            adjacency: Graph adjacency list {node: [neighbors]}
            p: QAOA depth
            shots: Measurement shots

        Returns:
            QAOAResult with partition assignment
        """
        self._require_qiskit()
        import numpy as np

        nodes = sorted(adjacency.keys())
        n = len(nodes)
        node_to_idx = {node: i for i, node in enumerate(nodes)}

        # Build Max-Cut cost coefficients
        edges = []
        for node, neighbors in adjacency.items():
            for neighbor in neighbors:
                if node_to_idx[node] < node_to_idx.get(neighbor, float("inf")):
                    edges.append((node_to_idx[node], node_to_idx[neighbor]))

        rng = np.random.default_rng(self.seed)
        gamma = rng.uniform(0, 2 * np.pi, size=p).tolist()
        beta = rng.uniform(0, np.pi, size=p).tolist()

        # Build and run
        circuit = self._build_maxcut_circuit(n, edges, gamma, beta, p)
        result = self.engine.run_circuit(circuit, shots=shots)
        counts = result.get("counts", {})

        # Find best cut
        best_cut = 0
        best_bitstring = "0" * n

        for bitstring, count in counts.items():
            cut_value = sum(
                1 for i, j in edges
                if bitstring[i] != bitstring[j]
            )
            if cut_value > best_cut:
                best_cut = cut_value
                best_bitstring = bitstring

        return QAOAResult(
            optimal_bitstring=best_bitstring,
            optimal_cost=best_cut,
            all_solutions={best_bitstring: float(best_cut)},
            parameters={"gamma": gamma, "beta": beta},
            success=True,
        )

    def _build_maxsat_cost(self, instance: SATInstance) -> list[dict]:
        """Build cost Hamiltonian coefficients for MAX-SAT."""
        coeffs = []
        for clause in instance.clauses:
            coeffs.append({
                "literals": clause.literals,
                "weight": 1.0,
            })
        return coeffs

    def _build_qaoa_circuit(
        self, n_qubits: int, cost_coeffs: list[dict],
        gamma: list[float], beta: list[float], p: int
    ) -> object:
        """Build QAOA circuit for MAX-SAT."""
        from qiskit import QuantumCircuit

        circuit = QuantumCircuit(n_qubits, n_qubits)

        # Initial superposition
        circuit.h(range(n_qubits))

        for layer in range(p):
            # Cost layer
            for coeff in cost_coeffs:
                literals = coeff["literals"]
                weight = coeff["weight"]
                if len(literals) == 1:
                    var = abs(literals[0]) - 1
                    if var < n_qubits:
                        sign = 1 if literals[0] > 0 else -1
                        circuit.rz(sign * gamma[layer] * weight, var)
                elif len(literals) == 2:
                    v1 = abs(literals[0]) - 1
                    v2 = abs(literals[1]) - 1
                    if v1 < n_qubits and v2 < n_qubits:
                        circuit.cx(v1, v2)
                        circuit.rz(gamma[layer] * weight, v2)
                        circuit.cx(v1, v2)

            # Mixer layer
            for q in range(n_qubits):
                circuit.rx(2 * beta[layer], q)

        # Measure
        circuit.measure(range(n_qubits), range(n_qubits))

        return circuit

    def _build_maxcut_circuit(
        self, n_qubits: int, edges: list[tuple[int, int]],
        gamma: list[float], beta: list[float], p: int
    ) -> object:
        """Build QAOA circuit for Max-Cut."""
        from qiskit import QuantumCircuit

        circuit = QuantumCircuit(n_qubits, n_qubits)
        circuit.h(range(n_qubits))

        for layer in range(p):
            # Cost layer: ZZ interaction for each edge
            for i, j in edges:
                circuit.cx(i, j)
                circuit.rz(gamma[layer], j)
                circuit.cx(i, j)

            # Mixer layer
            for q in range(n_qubits):
                circuit.rx(2 * beta[layer], q)

        circuit.measure(range(n_qubits), range(n_qubits))
        return circuit

    def _evaluate_maxsat_cost(
        self, bitstring: str, instance: SATInstance
    ) -> float:
        """Evaluate how many clauses a bitstring satisfies."""
        assignment = {}
        for i, bit in enumerate(bitstring):
            assignment[i + 1] = bit == "1"

        _, satisfied = instance.evaluate(assignment)
        return float(satisfied)

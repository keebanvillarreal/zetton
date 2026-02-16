"""
Data flow analysis for Zetton.

Performs reaching definitions, live variable analysis, use-def chains,
and taint tracking across control flow graphs. Useful for identifying
data dependencies, tracking crypto key material, and detecting
suspicious data flows in malware analysis.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zetton.analyzers.cfg import FunctionCFG, BasicBlock
    from zetton.analyzers.disasm import Instruction

logger = logging.getLogger(__name__)


class TaintSource(Enum):
    """Sources of tainted data."""
    USER_INPUT = auto()       # stdin, argv, network input
    FILE_READ = auto()        # File I/O operations
    NETWORK = auto()          # Network recv/read
    ENVIRONMENT = auto()      # getenv, registry reads
    CRYPTO_KEY = auto()       # Cryptographic key material
    HEAP_ALLOC = auto()       # Dynamic memory allocation
    RETURN_VALUE = auto()     # Return from untrusted function


class TaintSink(Enum):
    """Sinks where tainted data is dangerous."""
    EXEC = auto()             # System/exec calls
    FORMAT_STRING = auto()    # printf-family format args
    MEMORY_WRITE = auto()     # Arbitrary memory write
    NETWORK_SEND = auto()     # Network output
    FILE_WRITE = auto()       # File write operations
    CRYPTO_OPERATION = auto() # Crypto function argument
    BRANCH_CONDITION = auto() # Conditional branch decision


@dataclass
class Register:
    """Represents a CPU register."""
    name: str
    size: int = 8  # bytes

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Register):
            return self.name == other.name
        return NotImplemented


@dataclass
class MemoryLocation:
    """Represents a memory location (stack slot or global)."""
    base: str           # Register or "global"
    offset: int = 0
    size: int = 8

    def __hash__(self) -> int:
        return hash((self.base, self.offset))

    @property
    def is_stack(self) -> bool:
        return self.base in ("rbp", "rsp", "ebp", "esp", "sp")

    @property
    def is_global(self) -> bool:
        return self.base == "global"

    def __str__(self) -> str:
        if self.is_global:
            return f"[0x{self.offset:x}]"
        sign = "+" if self.offset >= 0 else ""
        return f"[{self.base}{sign}{self.offset:#x}]"


@dataclass
class Definition:
    """A definition (write) of a variable at a program point."""
    address: int                # Instruction address
    variable: str               # Register name or memory location string
    block_address: int = 0      # Containing basic block

    def __hash__(self) -> int:
        return hash((self.address, self.variable))


@dataclass
class Use:
    """A use (read) of a variable at a program point."""
    address: int
    variable: str
    block_address: int = 0

    def __hash__(self) -> int:
        return hash((self.address, self.variable))


@dataclass
class TaintInfo:
    """Taint tracking information for a variable."""
    source: TaintSource
    source_address: int
    propagation_path: list[int] = field(default_factory=list)
    confidence: float = 1.0

    def __str__(self) -> str:
        return (
            f"Taint({self.source.name}) from 0x{self.source_address:x} "
            f"via {len(self.propagation_path)} instructions"
        )


@dataclass
class DataFlowResult:
    """Results of data flow analysis for a function."""
    function_address: int
    reaching_definitions: dict[int, set[Definition]] = field(default_factory=dict)
    live_variables: dict[int, set[str]] = field(default_factory=dict)
    use_def_chains: dict[Use, set[Definition]] = field(default_factory=dict)
    def_use_chains: dict[Definition, set[Use]] = field(default_factory=dict)
    taint_results: list[dict] = field(default_factory=list)

    @property
    def has_taint_violations(self) -> bool:
        return len(self.taint_results) > 0


class DataFlowAnalyzer:
    """
    Performs data flow analysis on control flow graphs.

    Supports reaching definitions, live variable analysis, use-def/def-use
    chains, and taint propagation tracking.

    Example:
        >>> analyzer = DataFlowAnalyzer(cfg)
        >>> result = analyzer.analyze()
        >>> print(f"Taint violations: {len(result.taint_results)}")
    """

    # Common x86_64 registers
    GENERAL_REGS = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    }

    # Functions that introduce taint
    TAINT_SOURCES = {
        "read": TaintSource.USER_INPUT,
        "fread": TaintSource.FILE_READ,
        "recv": TaintSource.NETWORK,
        "recvfrom": TaintSource.NETWORK,
        "getenv": TaintSource.ENVIRONMENT,
        "scanf": TaintSource.USER_INPUT,
        "gets": TaintSource.USER_INPUT,
        "fgets": TaintSource.USER_INPUT,
        "malloc": TaintSource.HEAP_ALLOC,
        "calloc": TaintSource.HEAP_ALLOC,
        "realloc": TaintSource.HEAP_ALLOC,
    }

    # Functions that are dangerous sinks
    TAINT_SINKS = {
        "system": TaintSink.EXEC,
        "execve": TaintSink.EXEC,
        "popen": TaintSink.EXEC,
        "printf": TaintSink.FORMAT_STRING,
        "sprintf": TaintSink.FORMAT_STRING,
        "fprintf": TaintSink.FORMAT_STRING,
        "send": TaintSink.NETWORK_SEND,
        "sendto": TaintSink.NETWORK_SEND,
        "write": TaintSink.FILE_WRITE,
        "fwrite": TaintSink.FILE_WRITE,
        "memcpy": TaintSink.MEMORY_WRITE,
        "strcpy": TaintSink.MEMORY_WRITE,
    }

    def __init__(self, cfg: FunctionCFG, max_iterations: int = 100):
        """
        Initialize data flow analyzer.

        Args:
            cfg: Control flow graph to analyze
            max_iterations: Maximum fixpoint iterations
        """
        self.cfg = cfg
        self.max_iterations = max_iterations

    def analyze(self) -> DataFlowResult:
        """
        Run complete data flow analysis.

        Returns:
            DataFlowResult with all analysis results
        """
        result = DataFlowResult(function_address=self.cfg.function_address)

        # Extract defs and uses from all blocks
        block_defs, block_uses = self._extract_defs_uses()

        # Reaching definitions (forward analysis)
        result.reaching_definitions = self._compute_reaching_definitions(
            block_defs, block_uses
        )

        # Live variables (backward analysis)
        result.live_variables = self._compute_live_variables(
            block_defs, block_uses
        )

        # Build use-def and def-use chains
        self._build_ud_du_chains(result, block_defs, block_uses)

        # Taint analysis
        result.taint_results = self._compute_taint_propagation(block_defs, block_uses)

        return result

    def _extract_defs_uses(self) -> tuple[dict, dict]:
        """
        Extract definitions and uses from each basic block.

        Returns:
            Tuple of (block_defs, block_uses) dictionaries
        """
        block_defs: dict[int, set[Definition]] = {}
        block_uses: dict[int, set[Use]] = {}

        for addr, block in self.cfg.blocks.items():
            defs = set()
            uses = set()

            for insn in block.instructions:
                insn_defs, insn_uses = self._analyze_instruction(insn, addr)
                defs.update(insn_defs)
                uses.update(insn_uses)

            block_defs[addr] = defs
            block_uses[addr] = uses

        return block_defs, block_uses

    def _analyze_instruction(
        self, insn, block_addr: int
    ) -> tuple[set[Definition], set[Use]]:
        """
        Determine definitions and uses for a single instruction.

        Uses a simplified model: destination operand is a def,
        source operands are uses.
        """
        defs = set()
        uses = set()
        mnemonic = insn.mnemonic.lower()
        operands = insn.operands.strip()

        if not operands:
            return defs, uses

        parts = [p.strip() for p in operands.split(",")]

        # MOV-like: def destination, use source
        if mnemonic in ("mov", "movzx", "movsx", "lea", "movabs"):
            if len(parts) >= 2:
                defs.add(Definition(insn.address, parts[0], block_addr))
                uses.add(Use(insn.address, parts[1], block_addr))

        # Arithmetic: def and use destination, use source
        elif mnemonic in ("add", "sub", "xor", "and", "or", "shl", "shr", "sar", "imul"):
            if len(parts) >= 2:
                defs.add(Definition(insn.address, parts[0], block_addr))
                uses.add(Use(insn.address, parts[0], block_addr))
                uses.add(Use(insn.address, parts[1], block_addr))
            elif len(parts) == 1:
                uses.add(Use(insn.address, parts[0], block_addr))

        # Compare/test: uses only
        elif mnemonic in ("cmp", "test"):
            for p in parts:
                uses.add(Use(insn.address, p, block_addr))

        # Push: use source
        elif mnemonic == "push":
            if parts:
                uses.add(Use(insn.address, parts[0], block_addr))

        # Pop: def destination
        elif mnemonic == "pop":
            if parts:
                defs.add(Definition(insn.address, parts[0], block_addr))

        # Call: defines rax (return value), uses argument registers
        elif mnemonic == "call":
            defs.add(Definition(insn.address, "rax", block_addr))
            for reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                uses.add(Use(insn.address, reg, block_addr))

        return defs, uses

    def _compute_reaching_definitions(
        self, block_defs: dict, block_uses: dict
    ) -> dict[int, set[Definition]]:
        """
        Compute reaching definitions using iterative worklist algorithm.

        A definition d reaches point p if there exists a path from d to p
        along which d is not killed (overwritten).
        """
        # IN[b] = union of OUT[pred] for all predecessors
        # OUT[b] = GEN[b] union (IN[b] - KILL[b])

        in_sets: dict[int, set[Definition]] = {
            addr: set() for addr in self.cfg.blocks
        }
        out_sets: dict[int, set[Definition]] = {
            addr: set() for addr in self.cfg.blocks
        }

        # Compute GEN and KILL sets
        gen_sets = block_defs

        kill_sets: dict[int, set[Definition]] = defaultdict(set)
        all_defs = set()
        for defs in block_defs.values():
            all_defs.update(defs)

        for addr, defs in block_defs.items():
            defined_vars = {d.variable for d in defs}
            for d in all_defs:
                if d.variable in defined_vars and d not in defs:
                    kill_sets[addr].add(d)

        # Worklist iteration
        worklist = deque(self.cfg.blocks.keys())
        iterations = 0

        while worklist and iterations < self.max_iterations:
            iterations += 1
            block_addr = worklist.popleft()
            block = self.cfg.blocks[block_addr]

            # IN = union of OUT of predecessors
            new_in = set()
            for pred in block.predecessors:
                if pred in out_sets:
                    new_in |= out_sets[pred]

            in_sets[block_addr] = new_in

            # OUT = GEN union (IN - KILL)
            new_out = gen_sets.get(block_addr, set()) | (
                new_in - kill_sets.get(block_addr, set())
            )

            if new_out != out_sets[block_addr]:
                out_sets[block_addr] = new_out
                for succ in block.successors:
                    if succ not in worklist:
                        worklist.append(succ)

        return in_sets

    def _compute_live_variables(
        self, block_defs: dict, block_uses: dict
    ) -> dict[int, set[str]]:
        """
        Compute live variables using backward analysis.

        A variable is live at point p if there exists a path from p to
        a use of that variable along which it is not redefined.
        """
        # IN[b] = USE[b] union (OUT[b] - DEF[b])
        # OUT[b] = union of IN[succ] for all successors

        use_vars: dict[int, set[str]] = {
            addr: {u.variable for u in uses}
            for addr, uses in block_uses.items()
        }
        def_vars: dict[int, set[str]] = {
            addr: {d.variable for d in defs}
            for addr, defs in block_defs.items()
        }

        in_sets: dict[int, set[str]] = {
            addr: set() for addr in self.cfg.blocks
        }
        out_sets: dict[int, set[str]] = {
            addr: set() for addr in self.cfg.blocks
        }

        # Backward worklist
        worklist = deque(self.cfg.blocks.keys())
        iterations = 0

        while worklist and iterations < self.max_iterations:
            iterations += 1
            block_addr = worklist.popleft()
            block = self.cfg.blocks[block_addr]

            # OUT = union of IN of successors
            new_out = set()
            for succ in block.successors:
                if succ in in_sets:
                    new_out |= in_sets[succ]
            out_sets[block_addr] = new_out

            # IN = USE union (OUT - DEF)
            new_in = use_vars.get(block_addr, set()) | (
                new_out - def_vars.get(block_addr, set())
            )

            if new_in != in_sets[block_addr]:
                in_sets[block_addr] = new_in
                for pred in block.predecessors:
                    if pred not in worklist:
                        worklist.append(pred)

        return out_sets  # Live-out at each block

    def _build_ud_du_chains(
        self, result: DataFlowResult,
        block_defs: dict, block_uses: dict
    ) -> None:
        """Build use-definition and definition-use chains."""
        all_defs = {}
        for addr, defs in block_defs.items():
            for d in defs:
                all_defs.setdefault(d.variable, []).append(d)

        all_uses = {}
        for addr, uses in block_uses.items():
            for u in uses:
                all_uses.setdefault(u.variable, []).append(u)

        # UD chains: for each use, find reaching definitions
        for var, uses in all_uses.items():
            if var not in all_defs:
                continue
            for use in uses:
                reaching = result.reaching_definitions.get(use.block_address, set())
                matching = {d for d in reaching if d.variable == var}
                if matching:
                    result.use_def_chains[use] = matching

        # DU chains: inverse of UD
        for use, defs in result.use_def_chains.items():
            for d in defs:
                result.def_use_chains.setdefault(d, set()).add(use)

    def _compute_taint_propagation(
        self, block_defs: dict, block_uses: dict
    ) -> list[dict]:
        """
        Track taint from sources to sinks.

        Returns list of taint violation reports.
        """
        violations = []
        tainted: dict[str, TaintInfo] = {}

        # Walk blocks in topological-ish order (BFS from entry)
        visited = set()
        worklist = deque([self.cfg.entry_block])

        while worklist:
            block_addr = worklist.popleft()
            if block_addr in visited:
                continue
            visited.add(block_addr)

            block = self.cfg.blocks.get(block_addr)
            if block is None:
                continue

            for insn in block.instructions:
                # Check for taint source calls
                if insn.is_call:
                    call_target = insn.operands.strip().lower()
                    for func_name, source_type in self.TAINT_SOURCES.items():
                        if func_name in call_target:
                            taint = TaintInfo(
                                source=source_type,
                                source_address=insn.address,
                                propagation_path=[insn.address],
                            )
                            tainted["rax"] = taint
                            break

                    # Check for taint sink calls
                    for func_name, sink_type in self.TAINT_SINKS.items():
                        if func_name in call_target:
                            # Check if any argument register is tainted
                            for arg_reg in ("rdi", "rsi", "rdx", "rcx"):
                                if arg_reg in tainted:
                                    violations.append({
                                        "sink": func_name,
                                        "sink_type": sink_type.name,
                                        "sink_address": f"0x{insn.address:x}",
                                        "tainted_register": arg_reg,
                                        "source": tainted[arg_reg].source.name,
                                        "source_address": f"0x{tainted[arg_reg].source_address:x}",
                                        "path_length": len(tainted[arg_reg].propagation_path),
                                    })

                # Propagate taint through MOV-like instructions
                mnemonic = insn.mnemonic.lower()
                parts = [p.strip() for p in insn.operands.split(",")]

                if mnemonic in ("mov", "movzx", "movsx", "lea") and len(parts) >= 2:
                    src = parts[1]
                    dst = parts[0]
                    if src in tainted:
                        new_taint = TaintInfo(
                            source=tainted[src].source,
                            source_address=tainted[src].source_address,
                            propagation_path=tainted[src].propagation_path + [insn.address],
                            confidence=tainted[src].confidence * 0.95,
                        )
                        tainted[dst] = new_taint

                # XOR reg, reg clears taint
                if mnemonic == "xor" and len(parts) >= 2 and parts[0] == parts[1]:
                    tainted.pop(parts[0], None)

            # Continue to successors
            for succ in block.successors:
                worklist.append(succ)

        return violations

    def get_summary(self, result: DataFlowResult) -> dict:
        """Get a summary of data flow analysis results."""
        return {
            "function_address": f"0x{result.function_address:x}",
            "reaching_definitions_count": sum(
                len(defs) for defs in result.reaching_definitions.values()
            ),
            "live_variables_per_block": {
                f"0x{addr:x}": len(vars_)
                for addr, vars_ in result.live_variables.items()
            },
            "ud_chains": len(result.use_def_chains),
            "du_chains": len(result.def_use_chains),
            "taint_violations": len(result.taint_results),
            "taint_details": result.taint_results,
        }

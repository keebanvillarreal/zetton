"""
Control Flow Graph (CFG) analysis for Zetton.

Constructs and analyzes control flow graphs from disassembled code,
identifying basic blocks, edges, loops, and structural patterns.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from zetton.core.binary import Binary
    from zetton.analyzers.disasm import Disassembler, Function, Instruction
    from zetton.quantum.engine import QuantumEngine

logger = logging.getLogger(__name__)


class EdgeType(Enum):
    FALL_THROUGH = auto()
    CONDITIONAL_TRUE = auto()
    CONDITIONAL_FALSE = auto()
    UNCONDITIONAL = auto()
    CALL = auto()
    RETURN = auto()
    EXCEPTION = auto()
    SWITCH_CASE = auto()


class BlockType(Enum):
    NORMAL = auto()
    ENTRY = auto()
    EXIT = auto()
    CALL_SITE = auto()
    LOOP_HEADER = auto()
    SWITCH = auto()


@dataclass
class BasicBlock:
    """A basic block: linear sequence of instructions with one entry/exit."""
    address: int
    size: int
    instructions: list = field(default_factory=list)
    block_type: BlockType = BlockType.NORMAL
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)

    @property
    def end_address(self) -> int:
        if self.instructions:
            last = self.instructions[-1]
            return last.address + last.size
        return self.address + self.size

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def last_instruction(self):
        return self.instructions[-1] if self.instructions else None

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BasicBlock):
            return self.address == other.address
        return NotImplemented


@dataclass
class CFGEdge:
    source: int
    target: int
    edge_type: EdgeType
    condition: str = ""

    def __hash__(self) -> int:
        return hash((self.source, self.target, self.edge_type))


@dataclass
class Loop:
    header: int
    body: set[int] = field(default_factory=set)
    back_edges: list[CFGEdge] = field(default_factory=list)
    exit_blocks: set[int] = field(default_factory=set)
    nesting_depth: int = 0
    estimated_iterations: int | None = None

    @property
    def size(self) -> int:
        return len(self.body)


@dataclass
class FunctionCFG:
    """Complete CFG for a single function."""
    function_address: int
    function_name: str
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: list[CFGEdge] = field(default_factory=list)
    loops: list[Loop] = field(default_factory=list)
    entry_block: int = 0
    exit_blocks: set[int] = field(default_factory=set)
    dominators: dict[int, set[int]] = field(default_factory=dict)

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def cyclomatic_complexity(self) -> int:
        """McCabe cyclomatic complexity: E - N + 2."""
        return self.edge_count - self.block_count + 2

    def get_block(self, address: int) -> BasicBlock | None:
        return self.blocks.get(address)

    def get_successors(self, address: int) -> list[BasicBlock]:
        block = self.blocks.get(address)
        if block is None:
            return []
        return [self.blocks[s] for s in block.successors if s in self.blocks]

    def get_predecessors(self, address: int) -> list[BasicBlock]:
        block = self.blocks.get(address)
        if block is None:
            return []
        return [self.blocks[p] for p in block.predecessors if p in self.blocks]

    def to_dot(self) -> str:
        """Export CFG as Graphviz DOT format."""
        lines = [
            f'digraph "{self.function_name}" {{',
            '    node [shape=box, fontname="Courier", fontsize=10];',
            '    edge [fontsize=8];',
        ]

        for addr, block in sorted(self.blocks.items()):
            label_lines = [f"0x{addr:x} ({block.block_type.name})"]
            for insn in block.instructions[:10]:
                label_lines.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.operands}")
            if len(block.instructions) > 10:
                label_lines.append(f"... ({len(block.instructions) - 10} more)")

            label = "\\l".join(label_lines) + "\\l"

            color = {
                BlockType.ENTRY: "green",
                BlockType.EXIT: "red",
                BlockType.CALL_SITE: "blue",
                BlockType.LOOP_HEADER: "orange",
            }.get(block.block_type, "black")

            lines.append(f'    "0x{addr:x}" [label="{label}", color="{color}"];')

        for edge in self.edges:
            style = {
                EdgeType.CONDITIONAL_TRUE: 'color="green", label="T"',
                EdgeType.CONDITIONAL_FALSE: 'color="red", label="F"',
                EdgeType.UNCONDITIONAL: 'color="blue"',
                EdgeType.CALL: 'color="purple", style="dashed"',
                EdgeType.FALL_THROUGH: "",
            }.get(edge.edge_type, "")

            lines.append(f'    "0x{edge.source:x}" -> "0x{edge.target:x}" [{style}];')

        lines.append("}")
        return "\n".join(lines)


class CFGBuilder:
    """
    Builds control flow graphs from disassembled functions.

    Example:
        >>> cfg_builder = CFGBuilder(disassembler)
        >>> func_cfg = cfg_builder.build_function_cfg(0x401000)
        >>> print(f"Complexity: {func_cfg.cyclomatic_complexity}")
        >>> print(func_cfg.to_dot())
    """

    def __init__(self, disassembler, max_depth: int = 50):
        self.disasm = disassembler
        self.max_depth = max_depth

    def build_function_cfg(
        self,
        function_address: int,
        function_name: str = "",
        max_instructions: int = 100_000,
    ) -> FunctionCFG:
        """Build a complete CFG for a function."""
        cfg = FunctionCFG(
            function_address=function_address,
            function_name=function_name or f"sub_{function_address:x}",
            entry_block=function_address,
        )

        leaders = self._find_leaders(function_address, max_instructions)
        if not leaders:
            return cfg

        self._build_blocks(cfg, leaders)
        self._build_edges(cfg)
        self._classify_blocks(cfg)
        self._compute_dominators(cfg)
        self._detect_loops(cfg)

        return cfg

    def _find_leaders(self, start_address: int, max_instructions: int) -> set[int]:
        """Find basic block leaders."""
        leaders = {start_address}
        visited = set()
        worklist = deque([start_address])
        count = 0

        while worklist and count < max_instructions:
            addr = worklist.popleft()
            if addr in visited:
                continue
            visited.add(addr)

            try:
                instructions = list(self.disasm.disassemble_range(addr, addr + 0x1000))
            except Exception:
                continue

            for insn in instructions:
                count += 1
                if count >= max_instructions:
                    break

                if insn.is_jump or insn.is_call:
                    target = self._parse_branch_target(insn)
                    if target is not None:
                        leaders.add(target)
                        if insn.is_jump and target not in visited:
                            worklist.append(target)

                    next_addr = insn.address + insn.size
                    leaders.add(next_addr)

                    if insn.is_jump and not self._is_conditional(insn):
                        break

                elif insn.is_ret:
                    break

        return leaders

    def _build_blocks(self, cfg: FunctionCFG, leaders: set[int]) -> None:
        """Build basic blocks from leader addresses."""
        sorted_leaders = sorted(leaders)

        for i, leader_addr in enumerate(sorted_leaders):
            end_addr = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else leader_addr + 0x100

            try:
                instructions = list(self.disasm.disassemble_range(leader_addr, end_addr))
            except Exception:
                continue

            trimmed = []
            for insn in instructions:
                trimmed.append(insn)
                if insn.is_ret or insn.is_jump:
                    break

            if trimmed:
                block = BasicBlock(
                    address=leader_addr,
                    size=sum(i.size for i in trimmed),
                    instructions=trimmed,
                )
                cfg.blocks[leader_addr] = block

    def _build_edges(self, cfg: FunctionCFG) -> None:
        """Build edges between basic blocks."""
        for addr, block in cfg.blocks.items():
            last = block.last_instruction
            if last is None:
                continue

            if last.is_ret:
                cfg.exit_blocks.add(addr)
                continue

            if last.is_jump:
                target = self._parse_branch_target(last)

                if self._is_conditional(last):
                    if target is not None and target in cfg.blocks:
                        cfg.edges.append(CFGEdge(addr, target, EdgeType.CONDITIONAL_TRUE))
                        block.successors.append(target)
                        cfg.blocks[target].predecessors.append(addr)

                    fall = last.address + last.size
                    if fall in cfg.blocks:
                        cfg.edges.append(CFGEdge(addr, fall, EdgeType.CONDITIONAL_FALSE))
                        block.successors.append(fall)
                        cfg.blocks[fall].predecessors.append(addr)
                else:
                    if target is not None and target in cfg.blocks:
                        cfg.edges.append(CFGEdge(addr, target, EdgeType.UNCONDITIONAL))
                        block.successors.append(target)
                        cfg.blocks[target].predecessors.append(addr)

            elif last.is_call:
                fall = last.address + last.size
                if fall in cfg.blocks:
                    cfg.edges.append(CFGEdge(addr, fall, EdgeType.FALL_THROUGH))
                    block.successors.append(fall)
                    cfg.blocks[fall].predecessors.append(addr)
            else:
                fall = block.end_address
                if fall in cfg.blocks:
                    cfg.edges.append(CFGEdge(addr, fall, EdgeType.FALL_THROUGH))
                    block.successors.append(fall)
                    cfg.blocks[fall].predecessors.append(addr)

    def _classify_blocks(self, cfg: FunctionCFG) -> None:
        """Classify block types."""
        if cfg.entry_block in cfg.blocks:
            cfg.blocks[cfg.entry_block].block_type = BlockType.ENTRY

        for addr in cfg.exit_blocks:
            if addr in cfg.blocks:
                cfg.blocks[addr].block_type = BlockType.EXIT

        for addr, block in cfg.blocks.items():
            if block.last_instruction and block.last_instruction.is_call:
                if block.block_type == BlockType.NORMAL:
                    block.block_type = BlockType.CALL_SITE

    def _compute_dominators(self, cfg: FunctionCFG) -> None:
        """Compute dominator sets (iterative algorithm)."""
        if not cfg.blocks:
            return

        all_blocks = set(cfg.blocks.keys())
        entry = cfg.entry_block

        cfg.dominators = {b: set(all_blocks) for b in all_blocks}
        if entry in cfg.dominators:
            cfg.dominators[entry] = {entry}

        changed = True
        max_iter = len(all_blocks) * 3

        for _ in range(max_iter):
            if not changed:
                break
            changed = False

            for block_addr in all_blocks:
                if block_addr == entry:
                    continue

                block = cfg.blocks[block_addr]
                pred_doms = [
                    cfg.dominators[p] for p in block.predecessors
                    if p in cfg.dominators
                ]

                if pred_doms:
                    new_dom = set.intersection(*pred_doms) | {block_addr}
                else:
                    new_dom = {block_addr}

                if new_dom != cfg.dominators[block_addr]:
                    cfg.dominators[block_addr] = new_dom
                    changed = True

    def _detect_loops(self, cfg: FunctionCFG) -> None:
        """Detect natural loops via back edges (target dominates source)."""
        cfg.loops = []

        for edge in cfg.edges:
            source_doms = cfg.dominators.get(edge.source, set())
            if edge.target in source_doms:
                # Back edge found: build natural loop
                loop = Loop(header=edge.target)
                loop.back_edges.append(edge)
                loop.body = self._find_natural_loop(cfg, edge.target, edge.source)

                # Find exit blocks
                for block_addr in loop.body:
                    block = cfg.blocks.get(block_addr)
                    if block:
                        for succ in block.successors:
                            if succ not in loop.body:
                                loop.exit_blocks.add(block_addr)

                # Mark header
                if edge.target in cfg.blocks:
                    cfg.blocks[edge.target].block_type = BlockType.LOOP_HEADER

                cfg.loops.append(loop)

        # Compute nesting depth
        for i, loop_a in enumerate(cfg.loops):
            for j, loop_b in enumerate(cfg.loops):
                if i != j and loop_a.body < loop_b.body:
                    loop_a.nesting_depth = max(
                        loop_a.nesting_depth, loop_b.nesting_depth + 1
                    )

    def _find_natural_loop(
        self, cfg: FunctionCFG, header: int, tail: int
    ) -> set[int]:
        """Find all blocks in a natural loop given header and back-edge tail."""
        body = {header, tail}
        worklist = deque([tail])

        while worklist:
            block_addr = worklist.popleft()
            block = cfg.blocks.get(block_addr)
            if block is None:
                continue

            for pred in block.predecessors:
                if pred not in body:
                    body.add(pred)
                    worklist.append(pred)

        return body

    def _parse_branch_target(self, insn) -> int | None:
        """Extract branch target address from instruction operands."""
        operands = insn.operands.strip()
        if not operands:
            return None

        # Handle "0x..." format
        try:
            if operands.startswith("0x") or operands.startswith("0X"):
                return int(operands, 16)
            # Try as plain integer
            return int(operands)
        except ValueError:
            pass

        # Handle register-indirect (can't resolve statically)
        return None

    def _is_conditional(self, insn) -> bool:
        """Check if a jump is conditional."""
        mnemonic = insn.mnemonic.lower()
        # Unconditional jumps
        if mnemonic in ("jmp", "b", "br"):
            return False
        # All other jumps (je, jne, jg, beq, bne, etc.) are conditional
        return True

    def build_call_graph(
        self, function_addresses: list[int]
    ) -> dict[int, set[int]]:
        """
        Build an inter-procedural call graph.

        Args:
            function_addresses: List of function entry points

        Returns:
            Dictionary mapping caller address to set of callee addresses
        """
        call_graph: dict[int, set[int]] = defaultdict(set)

        for func_addr in function_addresses:
            cfg = self.build_function_cfg(func_addr)
            for block in cfg.blocks.values():
                if block.last_instruction and block.last_instruction.is_call:
                    target = self._parse_branch_target(block.last_instruction)
                    if target is not None:
                        call_graph[func_addr].add(target)

        return dict(call_graph)

    def get_analysis_summary(self, cfg: FunctionCFG) -> dict:
        """Get a summary of CFG analysis results."""
        return {
            "function": cfg.function_name,
            "address": f"0x{cfg.function_address:x}",
            "blocks": cfg.block_count,
            "edges": cfg.edge_count,
            "cyclomatic_complexity": cfg.cyclomatic_complexity,
            "loops": len(cfg.loops),
            "max_loop_nesting": max(
                (l.nesting_depth for l in cfg.loops), default=0
            ),
            "exit_blocks": len(cfg.exit_blocks),
            "call_sites": sum(
                1 for b in cfg.blocks.values()
                if b.block_type == BlockType.CALL_SITE
            ),
        }

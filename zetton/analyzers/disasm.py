"""
Disassembly engine for Zetton.

Provides disassembly capabilities using the Capstone engine,
with support for multiple architectures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from zetton.core.binary import Binary

logger = logging.getLogger(__name__)


@dataclass
class Instruction:
    """Represents a disassembled instruction."""
    address: int
    mnemonic: str
    operands: str
    bytes: bytes
    size: int
    
    def __str__(self) -> str:
        hex_bytes = self.bytes.hex()
        return f"0x{self.address:08x}: {hex_bytes:24s} {self.mnemonic:8s} {self.operands}"
    
    @property
    def is_call(self) -> bool:
        """Check if instruction is a call."""
        return self.mnemonic.lower() in ("call", "bl", "blx", "jalr", "jal")
    
    @property
    def is_jump(self) -> bool:
        """Check if instruction is a jump."""
        jump_mnemonics = (
            "jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle",
            "ja", "jb", "jae", "jbe", "jo", "jno", "js", "jns",
            "b", "beq", "bne", "bgt", "blt", "bge", "ble",
        )
        return self.mnemonic.lower() in jump_mnemonics
    
    @property
    def is_ret(self) -> bool:
        """Check if instruction is a return."""
        return self.mnemonic.lower() in ("ret", "retn", "bx lr")


@dataclass
class Function:
    """Represents a function in the binary."""
    address: int
    name: str
    size: int
    instructions: list[Instruction]
    calls: list[int]  # Addresses of called functions
    callers: list[int]  # Addresses that call this function
    
    @property
    def instruction_count(self) -> int:
        return len(self.instructions)


class Disassembler:
    """
    Disassembly engine using Capstone.
    
    Provides disassembly for multiple architectures with support
    for both linear sweep and recursive descent approaches.
    
    Example:
        >>> disasm = Disassembler(binary)
        >>> for insn in disasm.disassemble_range(0x1000, 0x1100):
        ...     print(insn)
    """
    
    def __init__(self, binary: Binary):
        """
        Initialize disassembler.
        
        Args:
            binary: Binary to disassemble
        """
        self.binary = binary
        self._capstone = None
        self._initialize_capstone()
    
    def _initialize_capstone(self) -> None:
        """Initialize Capstone engine for binary's architecture."""
        try:
            import capstone
        except ImportError:
            logger.warning("Capstone not available. Install with: pip install capstone")
            return
        
        from zetton.core.binary import Architecture
        
        # Map architecture to Capstone constants
        arch_map = {
            Architecture.X86: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            Architecture.X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            Architecture.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            Architecture.ARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            Architecture.MIPS: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
            Architecture.RISCV: (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64),
        }
        
        if self.binary.architecture in arch_map:
            arch, mode = arch_map[self.binary.architecture]
            
            # Adjust mode for endianness
            if self.binary.endianness == "big":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                mode |= capstone.CS_MODE_LITTLE_ENDIAN
            
            self._capstone = capstone.Cs(arch, mode)
            self._capstone.detail = True
        else:
            logger.warning(f"Unsupported architecture: {self.binary.architecture}")
    
    def disassemble(self, max_instructions: int = 10000) -> list[Instruction]:
        """
        Disassemble entire binary (code sections).
        
        Args:
            max_instructions: Maximum instructions to disassemble
            
        Returns:
            List of Instruction objects
        """
        instructions = []
        
        for section in self.binary.sections:
            if section.is_executable or ".text" in section.name.lower():
                section_data = self.binary.read_section(section)
                section_insns = list(self.disassemble_bytes(
                    section_data,
                    section.virtual_address,
                    max_instructions - len(instructions)
                ))
                instructions.extend(section_insns)
                
                if len(instructions) >= max_instructions:
                    break
        
        return instructions
    
    def disassemble_bytes(
        self,
        data: bytes,
        base_address: int = 0,
        max_instructions: int | None = None
    ) -> Iterator[Instruction]:
        """
        Disassemble raw bytes.
        
        Args:
            data: Raw bytes to disassemble
            base_address: Base address for instructions
            max_instructions: Maximum instructions to disassemble
            
        Yields:
            Instruction objects
        """
        if self._capstone is None:
            return
        
        count = 0
        for insn in self._capstone.disasm(data, base_address):
            yield Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
                bytes=bytes(insn.bytes),
                size=insn.size,
            )
            
            count += 1
            if max_instructions and count >= max_instructions:
                break
    
    def disassemble_range(
        self,
        start_address: int,
        end_address: int
    ) -> Iterator[Instruction]:
        """
        Disassemble a specific address range.
        
        Args:
            start_address: Start virtual address
            end_address: End virtual address
            
        Yields:
            Instruction objects
        """
        # Find section containing this range
        for section in self.binary.sections:
            if (section.virtual_address <= start_address < 
                section.virtual_address + section.virtual_size):
                
                # Calculate offsets
                offset_start = start_address - section.virtual_address + section.raw_offset
                offset_end = end_address - section.virtual_address + section.raw_offset
                
                data = self.binary.raw_data[offset_start:offset_end]
                yield from self.disassemble_bytes(data, start_address)
                return
        
        logger.warning(f"Address range 0x{start_address:x}-0x{end_address:x} not in any section")
    
    def disassemble_function(
        self,
        address: int,
        max_instructions: int = 1000
    ) -> Function:
        """
        Disassemble a function starting at address.
        
        Uses recursive descent to follow control flow.
        
        Args:
            address: Function entry point
            max_instructions: Maximum instructions to disassemble
            
        Returns:
            Function object
        """
        instructions = []
        calls = []
        visited = set()
        queue = [address]
        
        while queue and len(instructions) < max_instructions:
            current = queue.pop(0)
            
            if current in visited:
                continue
            visited.add(current)
            
            for insn in self.disassemble_range(current, current + 15):
                instructions.append(insn)
                
                if insn.is_call:
                    # Extract call target
                    try:
                        target = self._parse_operand(insn.operands)
                        if target:
                            calls.append(target)
                    except ValueError:
                        pass
                
                if insn.is_jump:
                    # Add jump target to queue
                    try:
                        target = self._parse_operand(insn.operands)
                        if target and target not in visited:
                            queue.append(target)
                    except ValueError:
                        pass
                
                if insn.is_ret:
                    break
        
        # Sort instructions by address
        instructions.sort(key=lambda i: i.address)
        
        # Calculate size
        if instructions:
            size = (instructions[-1].address + instructions[-1].size) - address
        else:
            size = 0
        
        return Function(
            address=address,
            name=self._get_function_name(address),
            size=size,
            instructions=instructions,
            calls=calls,
            callers=[],
        )
    
    def _parse_operand(self, operand: str) -> int | None:
        """Parse operand to extract address."""
        operand = operand.strip()
        
        # Handle hex addresses
        if operand.startswith("0x"):
            try:
                return int(operand, 16)
            except ValueError:
                pass
        
        # Handle decimal
        try:
            return int(operand)
        except ValueError:
            pass
        
        return None
    
    def _get_function_name(self, address: int) -> str:
        """Get function name from symbols or generate one."""
        for symbol in self.binary.symbols:
            if symbol.address == address:
                return symbol.name
        
        return f"sub_{address:x}"
    
    def find_crypto_instructions(self) -> list[tuple[Instruction, str]]:
        """
        Find instructions commonly used in crypto implementations.
        
        Returns:
            List of (instruction, crypto_hint) tuples
        """
        crypto_hints = []
        
        # AES-NI instructions
        aes_instructions = ("aesenc", "aesenclast", "aesdec", "aesdeclast", 
                          "aeskeygenassist", "aesimc")
        
        # SHA extensions
        sha_instructions = ("sha1msg1", "sha1msg2", "sha1nexte", "sha1rnds4",
                          "sha256msg1", "sha256msg2", "sha256rnds2")
        
        # Vectorized operations often used in crypto
        vector_instructions = ("pxor", "pshufd", "pshufb", "pmovzx", "pclmulqdq")
        
        for insn in self.disassemble():
            mnemonic = insn.mnemonic.lower()
            
            if mnemonic in aes_instructions:
                crypto_hints.append((insn, "AES-NI"))
            elif mnemonic in sha_instructions:
                crypto_hints.append((insn, "SHA Extensions"))
            elif mnemonic in vector_instructions:
                crypto_hints.append((insn, "Vector (possible crypto)"))
            elif mnemonic == "ror" or mnemonic == "rol":
                crypto_hints.append((insn, "Rotation (common in crypto)"))
        
        return crypto_hints

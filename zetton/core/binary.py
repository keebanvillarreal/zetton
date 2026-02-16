"""
Binary representation and manipulation for Zetton.

This module provides the core Binary class that represents a loaded binary
file and provides access to its structure, sections, symbols, and raw data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Iterator


class BinaryFormat(Enum):
    """Supported binary formats."""
    ELF = auto()
    PE = auto()
    MACHO = auto()
    RAW = auto()
    UNKNOWN = auto()


class Architecture(Enum):
    """Supported CPU architectures."""
    X86 = auto()
    X86_64 = auto()
    ARM = auto()
    ARM64 = auto()
    MIPS = auto()
    RISCV = auto()
    UNKNOWN = auto()


@dataclass
class Section:
    """Represents a section in the binary."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int = 0
    entropy: float = 0.0
    
    @property
    def is_executable(self) -> bool:
        """Check if section is executable."""
        # This varies by format, simplified for now
        return bool(self.characteristics & 0x20000000)  # PE executable flag
    
    @property
    def is_writable(self) -> bool:
        """Check if section is writable."""
        return bool(self.characteristics & 0x80000000)  # PE writable flag


@dataclass
class Symbol:
    """Represents a symbol in the binary."""
    name: str
    address: int
    size: int = 0
    symbol_type: str = "unknown"
    binding: str = "local"
    section: str = ""


@dataclass
class Import:
    """Represents an imported function."""
    name: str
    library: str
    address: int = 0


@dataclass
class Export:
    """Represents an exported function."""
    name: str
    address: int
    ordinal: int = 0


@dataclass 
class Binary:
    """
    Core representation of a binary file.
    
    This class provides access to all aspects of a parsed binary including
    its format, architecture, sections, symbols, imports, exports, and raw data.
    
    Attributes:
        path: Original file path
        format: Detected binary format (ELF, PE, Mach-O, etc.)
        architecture: CPU architecture
        bits: Address size (32 or 64)
        endianness: Byte order ('little' or 'big')
        entry_point: Entry point address
        base_address: Base load address
        sections: List of binary sections
        symbols: List of symbols
        imports: List of imported functions
        exports: List of exported functions
        raw_data: Raw binary bytes
    """
    
    path: Path
    format: BinaryFormat = BinaryFormat.UNKNOWN
    architecture: Architecture = Architecture.UNKNOWN
    bits: int = 64
    endianness: str = "little"
    entry_point: int = 0
    base_address: int = 0
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    exports: list[Export] = field(default_factory=list)
    raw_data: bytes = field(default=b"", repr=False)
    
    # Hashes for identification
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    
    @classmethod
    def from_file(cls, path: str | Path) -> Binary:
        """
        Load a binary from file.
        
        Args:
            path: Path to binary file
            
        Returns:
            Parsed Binary object
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is unsupported
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")
        
        raw_data = path.read_bytes()
        
        # Create initial binary object
        binary = cls(
            path=path,
            raw_data=raw_data,
            md5=hashlib.md5(raw_data).hexdigest(),
            sha1=hashlib.sha1(raw_data).hexdigest(),
            sha256=hashlib.sha256(raw_data).hexdigest(),
        )
        
        # Detect format and parse
        binary.format = binary._detect_format()
        binary._parse()
        
        return binary
    
    @classmethod
    def from_bytes(cls, data: bytes, name: str = "memory") -> Binary:
        """
        Create a binary from raw bytes.
        
        Args:
            data: Raw binary data
            name: Name identifier for the binary
            
        Returns:
            Parsed Binary object
        """
        binary = cls(
            path=Path(name),
            raw_data=data,
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        
        binary.format = binary._detect_format()
        binary._parse()
        
        return binary
    
    def _detect_format(self) -> BinaryFormat:
        """Detect binary format from magic bytes."""
        if len(self.raw_data) < 4:
            return BinaryFormat.RAW
        
        magic = self.raw_data[:4]
        
        # ELF: 0x7f 'E' 'L' 'F'
        if magic == b"\x7fELF":
            return BinaryFormat.ELF
        
        # PE: 'M' 'Z' (DOS header)
        if magic[:2] == b"MZ":
            return BinaryFormat.PE
        
        # Mach-O: Various magic values
        macho_magics = [
            b"\xfe\xed\xfa\xce",  # 32-bit big-endian
            b"\xce\xfa\xed\xfe",  # 32-bit little-endian  
            b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
            b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
            b"\xca\xfe\xba\xbe",  # Universal binary big-endian
            b"\xbe\xba\xfe\xca",  # Universal binary little-endian
        ]
        if magic in macho_magics:
            return BinaryFormat.MACHO
        
        return BinaryFormat.UNKNOWN
    
    def _parse(self) -> None:
        """Parse binary based on detected format."""
        if self.format == BinaryFormat.ELF:
            self._parse_elf()
        elif self.format == BinaryFormat.PE:
            self._parse_pe()
        elif self.format == BinaryFormat.MACHO:
            self._parse_macho()
        # RAW and UNKNOWN formats don't need parsing
    
    def _parse_elf(self) -> None:
        """Parse ELF binary using LIEF."""
        try:
            import lief
            elf = lief.parse(self.raw_data)
            
            if elf is None:
                return
            
            # Architecture detection
            machine = elf.header.machine_type
            arch_map = {
                lief.ELF.ARCH.I386: (Architecture.X86, 32),
                lief.ELF.ARCH.X86_64: (Architecture.X86_64, 64),
                lief.ELF.ARCH.ARM: (Architecture.ARM, 32),
                lief.ELF.ARCH.AARCH64: (Architecture.ARM64, 64),
                lief.ELF.ARCH.MIPS: (Architecture.MIPS, 32),
                lief.ELF.ARCH.RISCV: (Architecture.RISCV, 64),
            }
            self.architecture, self.bits = arch_map.get(
                machine, (Architecture.UNKNOWN, 64)
            )
            
            # Endianness
            self.endianness = "little" if elf.header.identity_data == lief.ELF.Header.ELF_DATA.LSB else "big"
            
            # Entry point
            self.entry_point = elf.entrypoint
            
            # Sections
            for section in elf.sections:
                if section.name:
                    self.sections.append(Section(
                        name=section.name,
                        virtual_address=section.virtual_address,
                        virtual_size=section.size,
                        raw_offset=section.offset,
                        raw_size=section.size,
                        characteristics=int(section.flags),
                        entropy=section.entropy,
                    ))
            
            # Symbols
            for symbol in elf.symbols:
                if symbol.name:
                    self.symbols.append(Symbol(
                        name=symbol.name,
                        address=symbol.value,
                        size=symbol.size,
                        symbol_type=str(symbol.type).split(".")[-1],
                        binding=str(symbol.binding).split(".")[-1],
                    ))
            
            # Imports
            for func in elf.imported_functions:
                self.imports.append(Import(
                    name=func.name,
                    library=func.library if hasattr(func, 'library') else "",
                    address=func.address,
                ))
            
            # Exports  
            for func in elf.exported_functions:
                self.exports.append(Export(
                    name=func.name,
                    address=func.address,
                ))
                
        except ImportError:
            # LIEF not available, use minimal parsing
            self._parse_elf_minimal()
    
    def _parse_elf_minimal(self) -> None:
        """Minimal ELF parsing without LIEF."""
        import struct
        
        # ELF header parsing
        if len(self.raw_data) < 52:
            return
        
        # e_ident
        ei_class = self.raw_data[4]
        ei_data = self.raw_data[5]
        
        self.bits = 64 if ei_class == 2 else 32
        self.endianness = "little" if ei_data == 1 else "big"
        
        endian = "<" if self.endianness == "little" else ">"
        
        if self.bits == 64:
            # 64-bit ELF header
            e_type, e_machine, e_version = struct.unpack(f"{endian}HHI", self.raw_data[16:24])
            self.entry_point = struct.unpack(f"{endian}Q", self.raw_data[24:32])[0]
        else:
            # 32-bit ELF header
            e_type, e_machine, e_version = struct.unpack(f"{endian}HHI", self.raw_data[16:24])
            self.entry_point = struct.unpack(f"{endian}I", self.raw_data[24:28])[0]
        
        # Architecture from e_machine
        arch_map = {
            0x03: Architecture.X86,
            0x3E: Architecture.X86_64,
            0x28: Architecture.ARM,
            0xB7: Architecture.ARM64,
            0x08: Architecture.MIPS,
            0xF3: Architecture.RISCV,
        }
        self.architecture = arch_map.get(e_machine, Architecture.UNKNOWN)
    
    def _parse_pe(self) -> None:
        """Parse PE binary using LIEF."""
        try:
            import lief
            pe = lief.parse(self.raw_data)
            
            if pe is None:
                return
            
            # Architecture
            machine = pe.header.machine
            if machine == lief.PE.MACHINE_TYPES.AMD64:
                self.architecture = Architecture.X86_64
                self.bits = 64
            elif machine == lief.PE.MACHINE_TYPES.I386:
                self.architecture = Architecture.X86
                self.bits = 32
            elif machine == lief.PE.MACHINE_TYPES.ARM64:
                self.architecture = Architecture.ARM64
                self.bits = 64
            
            self.endianness = "little"  # PE is always little-endian
            
            # Entry point and base
            self.entry_point = pe.optional_header.addressof_entrypoint
            self.base_address = pe.optional_header.imagebase
            
            # Sections
            for section in pe.sections:
                self.sections.append(Section(
                    name=section.name,
                    virtual_address=section.virtual_address,
                    virtual_size=section.virtual_size,
                    raw_offset=section.pointerto_raw_data,
                    raw_size=section.sizeof_raw_data,
                    characteristics=section.characteristics,
                    entropy=section.entropy,
                ))
            
            # Imports
            for imp in pe.imports:
                for entry in imp.entries:
                    self.imports.append(Import(
                        name=entry.name if entry.name else f"ord_{entry.ordinal}",
                        library=imp.name,
                        address=entry.iat_address,
                    ))
            
            # Exports
            if pe.has_exports:
                for exp in pe.exported_functions:
                    self.exports.append(Export(
                        name=exp.name,
                        address=exp.address,
                        ordinal=exp.ordinal,
                    ))
                    
        except ImportError:
            pass  # Minimal PE parsing not implemented yet
    
    def _parse_macho(self) -> None:
        """Parse Mach-O binary using LIEF."""
        try:
            import lief
            macho = lief.parse(self.raw_data)
            
            if macho is None:
                return
            
            # For FAT binaries, use first slice
            if hasattr(macho, '__iter__'):
                macho = list(macho)[0]
            
            # Architecture
            cpu = macho.header.cpu_type
            if cpu == lief.MachO.CPU_TYPES.x86_64:
                self.architecture = Architecture.X86_64
                self.bits = 64
            elif cpu == lief.MachO.CPU_TYPES.x86:
                self.architecture = Architecture.X86
                self.bits = 32
            elif cpu == lief.MachO.CPU_TYPES.ARM64:
                self.architecture = Architecture.ARM64
                self.bits = 64
            elif cpu == lief.MachO.CPU_TYPES.ARM:
                self.architecture = Architecture.ARM
                self.bits = 32
            
            self.endianness = "little"  # Modern Mach-O is little-endian
            self.entry_point = macho.entrypoint
            
            # Sections
            for section in macho.sections:
                self.sections.append(Section(
                    name=f"{section.segment.name}.{section.name}",
                    virtual_address=section.virtual_address,
                    virtual_size=section.size,
                    raw_offset=section.offset,
                    raw_size=section.size,
                    entropy=section.entropy,
                ))
            
            # Symbols and imports/exports
            for symbol in macho.symbols:
                if symbol.has_export_info:
                    self.exports.append(Export(
                        name=symbol.name,
                        address=symbol.value,
                    ))
                elif symbol.name.startswith("_"):
                    self.symbols.append(Symbol(
                        name=symbol.name,
                        address=symbol.value,
                    ))
                    
        except ImportError:
            pass
    
    def info(self) -> dict:
        """
        Get summary information about the binary.
        
        Returns:
            Dictionary with binary metadata
        """
        return {
            "path": str(self.path),
            "format": self.format.name,
            "architecture": self.architecture.name,
            "bits": self.bits,
            "endianness": self.endianness,
            "entry_point": hex(self.entry_point),
            "base_address": hex(self.base_address),
            "size": len(self.raw_data),
            "sections_count": len(self.sections),
            "symbols_count": len(self.symbols),
            "imports_count": len(self.imports),
            "exports_count": len(self.exports),
            "md5": self.md5,
            "sha256": self.sha256,
        }
    
    def get_section(self, name: str) -> Section | None:
        """Get section by name."""
        for section in self.sections:
            if section.name == name:
                return section
        return None
    
    def read_section(self, section: Section | str) -> bytes:
        """
        Read raw bytes from a section.
        
        Args:
            section: Section object or section name
            
        Returns:
            Raw bytes from the section
        """
        if isinstance(section, str):
            section = self.get_section(section)
            if section is None:
                raise ValueError(f"Section not found: {section}")
        
        start = section.raw_offset
        end = start + section.raw_size
        return self.raw_data[start:end]
    
    def read_bytes(self, offset: int, size: int) -> bytes:
        """Read raw bytes at offset."""
        return self.raw_data[offset:offset + size]
    
    def read_string(self, offset: int, max_length: int = 256) -> str:
        """Read null-terminated string at offset."""
        end = self.raw_data.find(b"\x00", offset, offset + max_length)
        if end == -1:
            end = offset + max_length
        return self.raw_data[offset:end].decode("utf-8", errors="replace")
    
    def search_bytes(self, pattern: bytes) -> Iterator[int]:
        """
        Search for byte pattern in binary.
        
        Args:
            pattern: Byte pattern to search for
            
        Yields:
            Offsets where pattern was found
        """
        offset = 0
        while True:
            offset = self.raw_data.find(pattern, offset)
            if offset == -1:
                break
            yield offset
            offset += 1
    
    def calculate_entropy(self, data: bytes | None = None) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Data to calculate entropy for, or None for whole binary
            
        Returns:
            Entropy value between 0 and 8
        """
        import math
        from collections import Counter
        
        if data is None:
            data = self.raw_data
        
        if not data:
            return 0.0
        
        counts = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                freq = count / length
                entropy -= freq * math.log2(freq)
        
        return entropy

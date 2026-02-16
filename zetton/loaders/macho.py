"""
Mach-O (Mach Object) loader for Zetton.

Parses macOS/iOS Mach-O binaries (executables, dylibs, frameworks)
and extracts structure, segments, sections, symbols, and load commands.
Uses LIEF as the primary parsing engine with fallback manual parsing.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zetton.core.binary import Binary

from zetton.core.binary import (
    Architecture,
    BinaryFormat,
    Export,
    Import,
    Section,
    Symbol,
)

logger = logging.getLogger(__name__)

# Mach-O magic numbers
MACHO_MAGIC_32 = 0xFEEDFACE
MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_MAGIC_FAT = 0xCAFEBABE
MACHO_CIGAM_32 = 0xCEFAEDFE  # Reversed byte order
MACHO_CIGAM_64 = 0xCFFAEDFE


class MachoCpuType(IntEnum):
    """Mach-O CPU types."""
    CPU_TYPE_X86 = 7
    CPU_TYPE_X86_64 = 0x01000007
    CPU_TYPE_ARM = 12
    CPU_TYPE_ARM64 = 0x0100000C


class MachoFileType(IntEnum):
    """Mach-O file types."""
    MH_OBJECT = 1
    MH_EXECUTE = 2
    MH_FVMLIB = 3
    MH_CORE = 4
    MH_PRELOAD = 5
    MH_DYLIB = 6
    MH_DYLINKER = 7
    MH_BUNDLE = 8
    MH_DSYM = 10
    MH_KEXT_BUNDLE = 11
    MH_FILESET = 12


class MachoLoadCommand(IntEnum):
    """Common Mach-O load command types."""
    LC_SEGMENT = 0x01
    LC_SYMTAB = 0x02
    LC_THREAD = 0x04
    LC_UNIXTHREAD = 0x05
    LC_DYSYMTAB = 0x0B
    LC_LOAD_DYLIB = 0x0C
    LC_ID_DYLIB = 0x0D
    LC_LOAD_DYLINKER = 0x0E
    LC_SEGMENT_64 = 0x19
    LC_UUID = 0x1B
    LC_CODE_SIGNATURE = 0x1D
    LC_ENCRYPTION_INFO = 0x21
    LC_DYLD_INFO = 0x22
    LC_DYLD_INFO_ONLY = 0x80000022
    LC_MAIN = 0x80000028
    LC_SOURCE_VERSION = 0x2A
    LC_BUILD_VERSION = 0x32


@dataclass
class MachoSegment:
    """Represents a Mach-O segment."""
    name: str
    vm_address: int
    vm_size: int
    file_offset: int
    file_size: int
    max_protection: int
    init_protection: int
    num_sections: int
    flags: int

    @property
    def is_readable(self) -> bool:
        return bool(self.init_protection & 0x1)

    @property
    def is_writable(self) -> bool:
        return bool(self.init_protection & 0x2)

    @property
    def is_executable(self) -> bool:
        return bool(self.init_protection & 0x4)


@dataclass
class MachoLoadCmd:
    """Represents a Mach-O load command."""
    cmd: int
    size: int
    data: dict = field(default_factory=dict)

    @property
    def cmd_name(self) -> str:
        try:
            return MachoLoadCommand(self.cmd).name
        except ValueError:
            return f"UNKNOWN(0x{self.cmd:x})"


@dataclass
class MachoInfo:
    """Extended Mach-O-specific information."""
    cpu_type: int = 0
    cpu_subtype: int = 0
    file_type: int = 0
    flags: int = 0
    uuid: str = ""
    min_os_version: str = ""
    sdk_version: str = ""
    source_version: str = ""
    segments: list[MachoSegment] = field(default_factory=list)
    load_commands: list[MachoLoadCmd] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    is_fat: bool = False
    fat_architectures: list[str] = field(default_factory=list)
    has_code_signature: bool = False
    has_encryption: bool = False
    is_restricted: bool = False
    has_pie: bool = False


class MachoLoader:
    """
    Mach-O binary format loader.

    Provides comprehensive parsing of macOS/iOS Mach-O binaries including
    headers, load commands, segments, sections, symbols, and code signature
    detection. Handles both single-architecture and universal (fat) binaries.

    Example:
        >>> loader = MachoLoader()
        >>> binary = loader.load("/usr/bin/file")
        >>> macho_info = loader.get_macho_info(binary)
        >>> print(f"UUID: {macho_info.uuid}")
        >>> print(f"Dylibs: {macho_info.dylibs}")
    """

    ARCH_MAP = {
        MachoCpuType.CPU_TYPE_X86: (Architecture.X86, 32),
        MachoCpuType.CPU_TYPE_X86_64: (Architecture.X86_64, 64),
        MachoCpuType.CPU_TYPE_ARM: (Architecture.ARM, 32),
        MachoCpuType.CPU_TYPE_ARM64: (Architecture.ARM64, 64),
    }

    # Mach-O header flags
    MH_PIE = 0x200000

    def __init__(self):
        """Initialize the Mach-O loader."""
        self._lief_available = self._check_lief()

    def _check_lief(self) -> bool:
        try:
            import lief
            return True
        except ImportError:
            logger.warning("LIEF not available. Install with: pip install lief")
            return False

    def can_load(self, data: bytes) -> bool:
        """Check if data is a Mach-O binary."""
        if len(data) < 4:
            return False
        magic = struct.unpack_from("<I", data, 0)[0]
        return magic in (
            MACHO_MAGIC_32, MACHO_MAGIC_64,
            MACHO_CIGAM_32, MACHO_CIGAM_64,
            MACHO_MAGIC_FAT,
        )

    def load(self, path: str | Path) -> Binary:
        """
        Load and parse a Mach-O binary file.

        Args:
            path: Path to Mach-O binary

        Returns:
            Populated Binary object
        """
        from zetton.core.binary import Binary

        binary = Binary.from_file(path)

        if not self.can_load(binary.raw_data):
            raise ValueError(f"Not a valid Mach-O binary: {path}")

        binary.format = BinaryFormat.MACHO

        if self._lief_available:
            self._parse_with_lief(binary)
        else:
            self._parse_manual(binary)

        return binary

    def _parse_with_lief(self, binary: Binary) -> None:
        """Parse Mach-O binary using LIEF."""
        import lief

        macho = lief.parse(str(binary.path))
        if macho is None:
            self._parse_manual(binary)
            return

        # Handle fat binaries - use first slice
        if isinstance(macho, lief.MachO.FatBinary):
            if len(macho) == 0:
                return
            macho = macho[0]

        header = macho.header

        # Architecture
        cpu_type = header.cpu_type.value
        if cpu_type in self.ARCH_MAP:
            binary.architecture, binary.bits = self.ARCH_MAP[cpu_type]
        else:
            binary.architecture = Architecture.UNKNOWN

        binary.endianness = "little"  # Modern Mach-O is always LE

        # Entry point
        if macho.has_main_command:
            binary.entry_point = macho.main_command.entrypoint
        elif macho.has_entrypoint:
            binary.entry_point = macho.entrypoint

        # Sections (within segments)
        for section in macho.sections:
            seg_name = section.segment_name if hasattr(section, "segment_name") else ""
            name = f"{seg_name},{section.name}" if seg_name else section.name

            binary.sections.append(Section(
                name=name,
                virtual_address=section.virtual_address,
                virtual_size=section.size,
                raw_offset=section.offset,
                raw_size=section.size,
                characteristics=section.flags,
                entropy=section.entropy,
            ))

        # Symbols
        for symbol in macho.symbols:
            if symbol.name:
                binary.symbols.append(Symbol(
                    name=symbol.name,
                    address=symbol.value,
                    symbol_type=str(symbol.type).split(".")[-1] if hasattr(symbol, "type") else "unknown",
                ))

        # Imports
        if macho.has_dyld_info:
            for binding in macho.dyld_info.bindings:
                if hasattr(binding, "symbol") and binding.symbol:
                    library = ""
                    if hasattr(binding, "library") and binding.library:
                        library = binding.library.name
                    binary.imports.append(Import(
                        name=binding.symbol.name if hasattr(binding.symbol, "name") else str(binding.symbol),
                        library=library,
                        address=binding.address,
                    ))

        # Exports
        if macho.has_dyld_info:
            for exp in macho.dyld_info.exports:
                if hasattr(exp, "symbol") and exp.symbol:
                    binary.exports.append(Export(
                        name=exp.symbol.name if hasattr(exp.symbol, "name") else str(exp.symbol),
                        address=exp.address,
                    ))

    def _parse_manual(self, binary: Binary) -> None:
        """Parse Mach-O binary manually (fallback)."""
        data = binary.raw_data

        magic = struct.unpack_from("<I", data, 0)[0]
        is_64 = magic in (MACHO_MAGIC_64, MACHO_CIGAM_64)
        is_swap = magic in (MACHO_CIGAM_32, MACHO_CIGAM_64)

        endian = ">" if is_swap else "<"
        binary.endianness = "big" if is_swap else "little"
        binary.bits = 64 if is_64 else 32

        # Mach-O header
        if is_64:
            hdr_fmt = f"{endian}IIIIIII"
            hdr_size = 32
        else:
            hdr_fmt = f"{endian}IIIIII"
            hdr_size = 28

        hdr = struct.unpack_from(hdr_fmt, data, 0)
        cpu_type = hdr[1]
        file_type = hdr[3]
        ncmds = hdr[4]
        sizeofcmds = hdr[5]

        # Map architecture
        try:
            cpu = MachoCpuType(cpu_type)
            if cpu in self.ARCH_MAP:
                binary.architecture, _ = self.ARCH_MAP[cpu]
        except ValueError:
            binary.architecture = Architecture.UNKNOWN

        # Parse load commands for segments and sections
        offset = hdr_size
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(f"{endian}II", data, offset)

            if cmd == MachoLoadCommand.LC_SEGMENT_64 and is_64:
                # Parse 64-bit segment
                seg_name = data[offset + 8:offset + 24].split(b"\x00")[0].decode("utf-8", errors="replace")
                vm_addr, vm_size, file_off, file_size = struct.unpack_from(
                    f"{endian}QQQQ", data, offset + 24
                )
                nsects = struct.unpack_from(f"{endian}I", data, offset + 64)[0]

                # Parse sections within segment
                sect_offset = offset + 72
                for _ in range(nsects):
                    if sect_offset + 80 > len(data):
                        break
                    sect_name = data[sect_offset:sect_offset + 16].split(b"\x00")[0].decode("utf-8", errors="replace")
                    seg_ref = data[sect_offset + 16:sect_offset + 32].split(b"\x00")[0].decode("utf-8", errors="replace")
                    s_addr, s_size, s_offset = struct.unpack_from(
                        f"{endian}QQI", data, sect_offset + 32
                    )

                    binary.sections.append(Section(
                        name=f"{seg_ref},{sect_name}",
                        virtual_address=s_addr,
                        virtual_size=s_size,
                        raw_offset=s_offset,
                        raw_size=s_size,
                    ))
                    sect_offset += 80

            elif cmd == MachoLoadCommand.LC_SEGMENT and not is_64:
                seg_name = data[offset + 8:offset + 24].split(b"\x00")[0].decode("utf-8", errors="replace")
                vm_addr, vm_size, file_off, file_size = struct.unpack_from(
                    f"{endian}IIII", data, offset + 24
                )
                nsects = struct.unpack_from(f"{endian}I", data, offset + 48)[0]

                sect_offset = offset + 56
                for _ in range(nsects):
                    if sect_offset + 68 > len(data):
                        break
                    sect_name = data[sect_offset:sect_offset + 16].split(b"\x00")[0].decode("utf-8", errors="replace")
                    seg_ref = data[sect_offset + 16:sect_offset + 32].split(b"\x00")[0].decode("utf-8", errors="replace")
                    s_addr, s_size, s_offset = struct.unpack_from(
                        f"{endian}III", data, sect_offset + 32
                    )
                    binary.sections.append(Section(
                        name=f"{seg_ref},{sect_name}",
                        virtual_address=s_addr,
                        virtual_size=s_size,
                        raw_offset=s_offset,
                        raw_size=s_size,
                    ))
                    sect_offset += 68

            elif cmd == MachoLoadCommand.LC_MAIN:
                entry_offset = struct.unpack_from(f"{endian}Q", data, offset + 8)[0]
                binary.entry_point = entry_offset

            offset += cmdsize

    def get_macho_info(self, binary: Binary) -> MachoInfo:
        """
        Extract extended Mach-O information.

        Args:
            binary: Binary to analyze

        Returns:
            MachoInfo with detailed Mach-O metadata
        """
        if not self.can_load(binary.raw_data):
            raise ValueError("Binary is not Mach-O format")

        info = MachoInfo()

        if self._lief_available:
            self._extract_macho_info_lief(binary, info)
        else:
            self._extract_macho_info_manual(binary, info)

        return info

    def _extract_macho_info_lief(self, binary: Binary, info: MachoInfo) -> None:
        """Extract detailed Mach-O info using LIEF."""
        import lief

        macho = lief.parse(str(binary.path))
        if macho is None:
            return

        # Handle fat binaries
        if isinstance(macho, lief.MachO.FatBinary):
            info.is_fat = True
            info.fat_architectures = [
                str(arch.header.cpu_type).split(".")[-1] for arch in macho
            ]
            if len(macho) == 0:
                return
            macho = macho[0]

        header = macho.header
        info.cpu_type = header.cpu_type.value
        info.cpu_subtype = header.cpu_subtype
        info.file_type = header.file_type.value
        info.flags = header.flags

        info.has_pie = bool(info.flags & self.MH_PIE)

        # UUID
        if macho.has_uuid:
            uuid_bytes = bytes(macho.uuid.uuid)
            info.uuid = uuid_bytes.hex()

        # Segments
        for seg in macho.segments:
            info.segments.append(MachoSegment(
                name=seg.name,
                vm_address=seg.virtual_address,
                vm_size=seg.virtual_size,
                file_offset=seg.file_offset,
                file_size=seg.file_size,
                max_protection=seg.max_protection,
                init_protection=seg.init_protection,
                num_sections=seg.numberof_sections,
                flags=seg.flags,
            ))

        # Dynamic libraries
        for lib in macho.libraries:
            info.dylibs.append(lib.name)

        # Code signature
        if macho.has_code_signature:
            info.has_code_signature = True

        # Encryption info
        if macho.has_encryption_info:
            info.has_encryption = True

    def _extract_macho_info_manual(self, binary: Binary, info: MachoInfo) -> None:
        """Extract basic Mach-O info manually."""
        data = binary.raw_data
        magic = struct.unpack_from("<I", data, 0)[0]
        endian = ">" if magic in (MACHO_CIGAM_32, MACHO_CIGAM_64) else "<"
        info.cpu_type = struct.unpack_from(f"{endian}I", data, 4)[0]
        info.cpu_subtype = struct.unpack_from(f"{endian}I", data, 8)[0]
        info.file_type = struct.unpack_from(f"{endian}I", data, 12)[0]

    def get_security_summary(self, binary: Binary) -> dict:
        """
        Get a summary of Mach-O security features.

        Args:
            binary: Binary to analyze

        Returns:
            Dictionary with security feature status
        """
        macho_info = self.get_macho_info(binary)
        return {
            "PIE": macho_info.has_pie,
            "Code Signature": macho_info.has_code_signature,
            "Encrypted": macho_info.has_encryption,
            "Universal (Fat)": macho_info.is_fat,
            "UUID": macho_info.uuid,
            "Dynamic Libraries": macho_info.dylibs,
        }

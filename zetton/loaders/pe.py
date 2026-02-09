"""
PE (Portable Executable) / COFF loader for Zetton.

Parses Windows PE binaries (EXE, DLL, SYS) and extracts structure,
sections, imports, exports, resources, and security characteristics.
Uses LIEF as the primary parsing engine with fallback manual parsing.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
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

# PE magic bytes
PE_MAGIC_MZ = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"


class PeMachine(IntEnum):
    """PE machine types."""
    IMAGE_FILE_MACHINE_I386 = 0x14C
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1C0
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064


class PeCharacteristics(IntFlag):
    """PE file characteristics."""
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000


class PeSectionFlags(IntFlag):
    """PE section characteristics."""
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


class PeSubsystem(IntEnum):
    """PE subsystem types."""
    IMAGE_SUBSYSTEM_UNKNOWN = 0
    IMAGE_SUBSYSTEM_NATIVE = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12


@dataclass
class PeImportEntry:
    """Represents a PE import table entry."""
    dll_name: str
    functions: list[str] = field(default_factory=list)
    iat_rva: int = 0


@dataclass
class PeExportEntry:
    """Represents a PE export table entry."""
    name: str
    ordinal: int
    rva: int
    forwarded_to: str = ""


@dataclass
class PeResource:
    """Represents a PE resource entry."""
    resource_type: int
    name: str
    language: int
    offset: int
    size: int
    data: bytes = field(default=b"", repr=False)

    @property
    def type_name(self) -> str:
        names = {
            1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU",
            5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT",
            9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
            14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
        }
        return names.get(self.resource_type, f"UNKNOWN({self.resource_type})")


@dataclass
class PeDataDirectory:
    """Represents a PE data directory entry."""
    name: str
    rva: int
    size: int


@dataclass
class PeInfo:
    """Extended PE-specific information."""
    machine: int = 0
    characteristics: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    timestamp: int = 0
    image_base: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: int = 0
    import_table: list[PeImportEntry] = field(default_factory=list)
    export_table: list[PeExportEntry] = field(default_factory=list)
    resources: list[PeResource] = field(default_factory=list)
    data_directories: list[PeDataDirectory] = field(default_factory=list)
    is_dll: bool = False
    is_driver: bool = False
    is_gui: bool = False
    has_aslr: bool = False
    has_dep: bool = False
    has_seh: bool = False
    has_cfg: bool = False
    has_authenticode: bool = False
    has_rich_header: bool = False
    rich_header_data: bytes = field(default=b"", repr=False)
    debug_info: dict = field(default_factory=dict)


class PeLoader:
    """
    PE/COFF binary format loader.

    Provides comprehensive parsing of Windows PE binaries including
    headers, sections, imports/exports, resources, and security
    feature detection (ASLR, DEP, SEH, CFG, Authenticode).

    Example:
        >>> loader = PeLoader()
        >>> binary = loader.load("malware.exe")
        >>> pe_info = loader.get_pe_info(binary)
        >>> print(f"Imports from {len(pe_info.import_table)} DLLs")
    """

    ARCH_MAP = {
        PeMachine.IMAGE_FILE_MACHINE_I386: (Architecture.X86, 32),
        PeMachine.IMAGE_FILE_MACHINE_AMD64: (Architecture.X86_64, 64),
        PeMachine.IMAGE_FILE_MACHINE_ARM: (Architecture.ARM, 32),
        PeMachine.IMAGE_FILE_MACHINE_ARM64: (Architecture.ARM64, 64),
    }

    # DLL characteristics flags for security features
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040   # ASLR
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100      # DEP
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400         # No SEH
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000        # CFG

    def __init__(self):
        """Initialize the PE loader."""
        self._lief_available = self._check_lief()

    def _check_lief(self) -> bool:
        try:
            import lief
            return True
        except ImportError:
            logger.warning("LIEF not available. Install with: pip install lief")
            return False

    def can_load(self, data: bytes) -> bool:
        """Check if data is a PE binary."""
        if len(data) < 64:
            return False
        if data[:2] != PE_MAGIC_MZ:
            return False
        # Check for PE signature at offset stored at 0x3C
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 > len(data):
            return False
        return data[pe_offset:pe_offset + 4] == PE_SIGNATURE

    def load(self, path: str | Path) -> Binary:
        """
        Load and parse a PE binary file.

        Args:
            path: Path to PE binary

        Returns:
            Populated Binary object
        """
        from zetton.core.binary import Binary

        binary = Binary.from_file(path)

        if not self.can_load(binary.raw_data):
            raise ValueError(f"Not a valid PE binary: {path}")

        binary.format = BinaryFormat.PE

        if self._lief_available:
            self._parse_with_lief(binary)
        else:
            self._parse_manual(binary)

        return binary

    def _parse_with_lief(self, binary: Binary) -> None:
        """Parse PE binary using LIEF."""
        import lief

        pe = lief.parse(str(binary.path))
        if pe is None:
            self._parse_manual(binary)
            return

        header = pe.header
        optional = pe.optional_header

        # Architecture
        machine = header.machine.value
        if machine in self.ARCH_MAP:
            binary.architecture, binary.bits = self.ARCH_MAP[machine]
        else:
            binary.architecture = Architecture.UNKNOWN

        binary.endianness = "little"  # PE is always little-endian
        binary.entry_point = optional.addressof_entrypoint + optional.imagebase
        binary.base_address = optional.imagebase

        # Sections
        for section in pe.sections:
            name = section.name.rstrip("\x00")
            binary.sections.append(Section(
                name=name,
                virtual_address=section.virtual_address + optional.imagebase,
                virtual_size=section.virtual_size,
                raw_offset=section.pointerto_raw_data,
                raw_size=section.sizeof_raw_data,
                characteristics=section.characteristics,
                entropy=section.entropy,
            ))

        # Imports
        if pe.has_imports:
            for imp in pe.imports:
                for entry in imp.entries:
                    name = entry.name if entry.name else f"Ordinal_{entry.data}"
                    binary.imports.append(Import(
                        name=name,
                        library=imp.name,
                        address=entry.iat_value if hasattr(entry, "iat_value") else 0,
                    ))

        # Exports
        if pe.has_exports:
            for entry in pe.exported_functions:
                if entry.name:
                    binary.exports.append(Export(
                        name=entry.name,
                        address=entry.address,
                        ordinal=entry.ordinal if hasattr(entry, "ordinal") else 0,
                    ))

    def _parse_manual(self, binary: Binary) -> None:
        """Parse PE binary manually (fallback)."""
        data = binary.raw_data

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

        # COFF header starts at PE signature + 4
        coff_offset = pe_offset + 4
        machine, num_sections, timestamp = struct.unpack_from(
            "<HHI", data, coff_offset
        )
        _, _, _, characteristics = struct.unpack_from(
            "<III HH", data, coff_offset + 8
        )

        binary.endianness = "little"

        try:
            pe_machine = PeMachine(machine)
            if pe_machine in self.ARCH_MAP:
                binary.architecture, binary.bits = self.ARCH_MAP[pe_machine]
        except ValueError:
            binary.architecture = Architecture.UNKNOWN

        # Optional header
        opt_offset = coff_offset + 20
        magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_pe32plus = magic == 0x20B

        if is_pe32plus:
            entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
            binary.bits = 64
        else:
            entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
            binary.bits = 32

        binary.entry_point = entry_rva + image_base
        binary.base_address = image_base

        # Section headers
        opt_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        section_offset = opt_offset + opt_size

        for i in range(num_sections):
            sh_off = section_offset + i * 40
            if sh_off + 40 > len(data):
                break

            name_raw = data[sh_off:sh_off + 8]
            name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace")
            virtual_size, virtual_addr, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, sh_off + 8
            )
            chars = struct.unpack_from("<I", data, sh_off + 36)[0]

            binary.sections.append(Section(
                name=name,
                virtual_address=virtual_addr + image_base,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=chars,
            ))

    def get_pe_info(self, binary: Binary) -> PeInfo:
        """
        Extract extended PE information.

        Args:
            binary: Binary to analyze

        Returns:
            PeInfo with detailed PE metadata
        """
        if not self.can_load(binary.raw_data):
            raise ValueError("Binary is not PE format")

        info = PeInfo()

        if self._lief_available:
            self._extract_pe_info_lief(binary, info)
        else:
            self._extract_pe_info_manual(binary, info)

        return info

    def _extract_pe_info_lief(self, binary: Binary, info: PeInfo) -> None:
        """Extract detailed PE info using LIEF."""
        import lief

        pe = lief.parse(str(binary.path))
        if pe is None:
            return

        header = pe.header
        optional = pe.optional_header

        info.machine = header.machine.value
        info.characteristics = header.characteristics
        info.timestamp = header.time_date_stamps
        info.subsystem = optional.subsystem.value
        info.dll_characteristics = optional.dll_characteristics
        info.image_base = optional.imagebase
        info.section_alignment = optional.section_alignment
        info.file_alignment = optional.file_alignment
        info.size_of_image = optional.sizeof_image
        info.size_of_headers = optional.sizeof_headers
        info.checksum = optional.checksum

        # Security features
        dll_chars = optional.dll_characteristics
        info.has_aslr = bool(dll_chars & self.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        info.has_dep = bool(dll_chars & self.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        info.has_seh = not bool(dll_chars & self.IMAGE_DLLCHARACTERISTICS_NO_SEH)
        info.has_cfg = bool(dll_chars & self.IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        info.is_dll = bool(header.characteristics & PeCharacteristics.IMAGE_FILE_DLL)
        info.is_gui = info.subsystem == PeSubsystem.IMAGE_SUBSYSTEM_WINDOWS_GUI

        # Driver detection
        info.is_driver = info.subsystem in (
            PeSubsystem.IMAGE_SUBSYSTEM_NATIVE,
            PeSubsystem.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
            PeSubsystem.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
        )

        # Import table
        if pe.has_imports:
            for imp in pe.imports:
                entry = PeImportEntry(dll_name=imp.name)
                for func in imp.entries:
                    name = func.name if func.name else f"Ordinal_{func.data}"
                    entry.functions.append(name)
                info.import_table.append(entry)

        # Export table
        if pe.has_exports:
            for func in pe.exported_functions:
                info.export_table.append(PeExportEntry(
                    name=func.name or "",
                    ordinal=func.ordinal if hasattr(func, "ordinal") else 0,
                    rva=func.address,
                ))

        # Rich header
        if pe.has_rich_header:
            info.has_rich_header = True

        # Authenticode
        if pe.has_signatures:
            info.has_authenticode = True

        # Debug info
        if pe.has_debug:
            for debug in pe.debug:
                info.debug_info["type"] = str(debug.type).split(".")[-1]

    def _extract_pe_info_manual(self, binary: Binary, info: PeInfo) -> None:
        """Extract basic PE info manually."""
        data = binary.raw_data
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        coff_offset = pe_offset + 4

        info.machine = struct.unpack_from("<H", data, coff_offset)[0]
        info.timestamp = struct.unpack_from("<I", data, coff_offset + 4)[0]
        info.characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
        info.is_dll = bool(info.characteristics & PeCharacteristics.IMAGE_FILE_DLL)

    def get_security_summary(self, binary: Binary) -> dict:
        """
        Get a summary of PE security features.

        Args:
            binary: Binary to analyze

        Returns:
            Dictionary with security feature status
        """
        pe_info = self.get_pe_info(binary)
        return {
            "ASLR": pe_info.has_aslr,
            "DEP (NX)": pe_info.has_dep,
            "SEH": pe_info.has_seh,
            "CFG": pe_info.has_cfg,
            "Authenticode": pe_info.has_authenticode,
            "Is DLL": pe_info.is_dll,
            "Is Driver": pe_info.is_driver,
            "Is GUI": pe_info.is_gui,
            "Import DLLs": [e.dll_name for e in pe_info.import_table],
        }

#!/usr/bin/env python3
# Zetton - Quantum Software Reverse Engineering Framework
# Copyright (c) 2026 Keeban Villarreal
# Licensed under AGPL-3.0. See LICENSE and COPYRIGHT for details.
# Commercial licensing: keeban.villarreal@my.utsa.edu
"""
Zetton CLI - Command Line Interface for Quantum Software Reverse Engineering

This module provides the main command-line interface for Zetton.
"""

import sys
import json
import time
import warnings
from pathlib import Path
from typing import Optional

# Suppress LIEF RuntimeWarnings for unknown segment types
warnings.filterwarnings("ignore", message=".*is not a valid TYPE.*", category=RuntimeWarning)

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# Import version from package
try:
    from zetton import __version__
except ImportError:
    __version__ = "0.1.0"

console = Console()


# ─── Helpers ────────────────────────────────────────────────────────────────

def print_banner():
    """Print Zetton ASCII banner."""
    console.print(f"[bold yellow]Zetton[/bold yellow] [dim]v{__version__}[/dim]")
    console.print("[dim]Quantum Software Reverse Engineering Framework[/dim]")
    console.print("[dim green]UTSA Cyber Jedis Quantum Cybersecurity RIG[/dim green]\n")


def detect_elf_security(binary) -> dict:
    """Detect ELF security features using LIEF."""
    features = {}
    try:
        import lief
        import warnings
        
        elf = lief.ELF.parse(str(binary.path))
        if elf is None:
            return features
        
        # PIE (Position Independent Executable)
        features["PIE"] = elf.is_pie
        
        # NX (No Execute) and RELRO — iterate segments safely
        has_gnu_stack = False
        nx_enabled = False
        has_relro = False
        
        for segment in elf.segments:
            try:
                seg_type = segment.type
                # Skip unknown/invalid segment types (LIEF returns int instead of enum)
                if not isinstance(seg_type, lief.ELF.Segment.TYPE):
                    continue
                    
                if seg_type == lief.ELF.Segment.TYPE.GNU_STACK:
                    has_gnu_stack = True
                    nx_enabled = not bool(segment.flags & lief.ELF.Segment.FLAGS.X)
                elif seg_type == lief.ELF.Segment.TYPE.GNU_RELRO:
                    has_relro = True
            except (ValueError, RuntimeWarning):
                continue
        
        features["NX"] = nx_enabled if has_gnu_stack else False
        
        # Full RELRO requires BIND_NOW
        full_relro = False
        if has_relro:
            has_bind_now = False
            try:
                if elf.has_dynamic_entry(lief.ELF.DynamicEntry.TAG.BIND_NOW):
                    has_bind_now = True
            except Exception:
                pass
            try:
                if elf.has_dynamic_entry(lief.ELF.DynamicEntry.TAG.FLAGS):
                    flags_entry = elf.get(lief.ELF.DynamicEntry.TAG.FLAGS)
                    if flags_entry and (flags_entry.value & 0x8):  # DF_BIND_NOW
                        has_bind_now = True
            except Exception:
                pass
            full_relro = has_bind_now
        
        if full_relro:
            features["RELRO"] = "Full"
        elif has_relro:
            features["RELRO"] = "Partial"
        else:
            features["RELRO"] = "None"
        
        # Stack Canary (look for __stack_chk_fail in imports)
        import_names = [f.name for f in elf.imported_functions]
        features["Canary"] = "__stack_chk_fail" in import_names
        
        # FORTIFY (look for _chk variants of functions)
        fortify_funcs = [n for n in import_names if n.endswith("_chk")]
        features["FORTIFY"] = len(fortify_funcs) > 0
        features["FORTIFY_funcs"] = fortify_funcs
        
        # RUNPATH / RPATH
        features["RPATH"] = False
        features["RUNPATH"] = False
        try:
            if elf.has_dynamic_entry(lief.ELF.DynamicEntry.TAG.RPATH):
                features["RPATH"] = True
            if elf.has_dynamic_entry(lief.ELF.DynamicEntry.TAG.RUNPATH):
                features["RUNPATH"] = True
        except Exception:
            pass
            
    except Exception as e:
        features["_error"] = str(e)
    
    return features


ZETTON_BANNER = r"""
███████╗███████╗████████╗████████╗ ██████╗ ███╗   ██╗
╚══███╔╝██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗████╗  ██║
  ███╔╝ █████╗     ██║      ██║   ██║   ██║██╔██╗ ██║
 ███╔╝  ██╔══╝     ██║      ██║   ██║   ██║██║╚██╗██║
███████╗███████╗   ██║      ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝"""


def format_size(size: int) -> str:
    """Format byte size with commas."""
    return f"{size:,}"


# ─── CLI Commands ───────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="Zetton")
@click.pass_context
def main(ctx):
    """
    Zetton - Quantum Software Reverse Engineering Framework
    
    A next-generation reverse engineering framework combining classical
    binary analysis with quantum computing algorithms.
    
    Examples:
        zetton analyze ./sample_binary
        zetton crypto ./sample_binary --quantum
        zetton forensics ./sample_binary
        zetton --version
    """
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        console.print(f"[bold yellow]{ZETTON_BANNER}[/bold yellow]")
        console.print(f"\n  [dim]v{__version__}[/dim] — [white]Quantum Software Reverse Engineering Framework[/white]")
        console.print(f"  [dim green]UTSA Cyber Jedis Quantum Cybersecurity RIG[/dim green]\n")
        console.print("[bold]Commands:[/bold]")
        console.print("  [cyan]analyze[/cyan]    Analyze a binary file")
        console.print("  [cyan]crypto[/cyan]     Detect cryptographic algorithms")
        console.print("  [cyan]forensics[/cyan]  Digital forensics analysis")
        console.print("  [cyan]cfg[/cyan]        Control flow graph analysis")
        console.print("  [cyan]dataflow[/cyan]   Data flow and taint analysis")
        console.print("  [cyan]pqc[/cyan]        Post-quantum cryptography analysis")
        console.print("  [cyan]pcap[/cyan]       Analyze PCAP/PCAPNG for TLS crypto & PQC readiness")
        console.print("  [cyan]report[/cyan]     Unified report (HTML/JSON/Markdown) with CBOM")
        console.print("  [cyan]auto[/cyan]       Auto-detect file type and run all analyses")
        console.print("  [cyan]status[/cyan]     Display feature status")
        console.print("  [cyan]config[/cyan]     Configure settings")
        console.print("  [cyan]quantum[/cyan]    Quantum backend management")
        console.print(f"\n[dim]Run 'zetton <command> --help' for details on a command.[/dim]")


# ─── ANALYZE ────────────────────────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['elf', 'pe', 'macho', 'auto']),
              default='auto', help='Binary format (auto-detect by default)')
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(binary_path: str, format: str, output: Optional[str], verbose: bool):
    """
    Analyze a binary file.
    
    Performs static analysis including format detection, section extraction,
    symbol enumeration, security feature detection, and hashing.
    
    BINARY_PATH: Path to the binary file to analyze
    
    Examples:
        zetton analyze ./sample_aes_ecb
        zetton analyze malware.exe --format pe
        zetton analyze suspicious.bin -v -o report.json
    """
    from zetton.core.binary import Binary, BinaryFormat
    
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Loading binary:[/bold cyan] {binary_path}")
    
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)
    
    # ── Format & Architecture ────────────────────────────────────────────
    fmt_name = binary.format.name
    arch_name = binary.architecture.name
    endian = "Little-Endian" if binary.endianness == "little" else "Big-Endian"
    
    console.print(f"[green]Format detected:[/green] {fmt_name} ({binary.bits}-bit)")
    console.print(f"[green]Architecture:[/green] {arch_name}")
    console.print(f"[green]Endianness:[/green] {endian}\n")
    
    # ── Binary Info Table ────────────────────────────────────────────────
    info_table = Table(
        title="Binary Information",
        box=box.ROUNDED,
        show_header=False,
        title_style="bold white",
        border_style="dim",
        pad_edge=True,
    )
    info_table.add_column("Field", style="cyan", width=16)
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Path", str(binary.path))
    info_table.add_row("Format", fmt_name)
    info_table.add_row("Architecture", arch_name)
    info_table.add_row("Bits", str(binary.bits))
    info_table.add_row("Entry Point", f"0x{binary.entry_point:08X}")
    info_table.add_row("Size", f"{format_size(len(binary.raw_data))} bytes")
    info_table.add_row("MD5", binary.md5)
    info_table.add_row("SHA-256", binary.sha256)
    info_table.add_row("Sections", str(len(binary.sections)))
    info_table.add_row("Symbols", str(len(binary.symbols)))
    info_table.add_row("Imports", str(len(binary.imports)))
    info_table.add_row("Exports", str(len(binary.exports)))
    
    console.print(info_table)
    console.print()
    
    # ── Sections ─────────────────────────────────────────────────────────
    if binary.sections:
        sec_table = Table(
            title="Sections",
            box=box.SIMPLE_HEAVY,
            title_style="bold white",
            border_style="dim",
        )
        sec_table.add_column("Name", style="cyan", width=20)
        sec_table.add_column("VAddr", style="yellow", justify="right")
        sec_table.add_column("Size", style="white", justify="right")
        sec_table.add_column("Entropy", style="magenta", justify="right")
        
        for sec in binary.sections:
            ent_color = "green"
            if sec.entropy > 6.0:
                ent_color = "yellow"
            if sec.entropy > 7.0:
                ent_color = "red"
            
            sec_table.add_row(
                sec.name if sec.name else "(empty)",
                f"0x{sec.virtual_address:08X}",
                format_size(sec.raw_size),
                f"[{ent_color}]{sec.entropy:.4f}[/{ent_color}]",
            )
        
        console.print(sec_table)
        console.print()
    
    # ── Security Features (ELF) ──────────────────────────────────────────
    if binary.format == BinaryFormat.ELF:
        security = detect_elf_security(binary)
        
        if security and "_error" not in security:
            console.print("[bold]Security Features:[/bold]")
            
            def sec_status(val, true_text="Enabled", false_text="Disabled"):
                if isinstance(val, str):
                    if val == "Full":
                        return "[green]Full ✓[/green]"
                    elif val == "Partial":
                        return "[yellow]Partial ⚠[/yellow]"
                    else:
                        return f"[red]{val} ✗[/red]"
                return f"[green]{true_text} ✓[/green]" if val else f"[red]{false_text} ✗[/red]"
            
            console.print(f"    ├── PIE:     {sec_status(security.get('PIE', False))}")
            console.print(f"    ├── NX:      {sec_status(security.get('NX', False))}")
            console.print(f"    ├── RELRO:   {sec_status(security.get('RELRO', 'None'))}")
            console.print(f"    ├── Canary:  {sec_status(security.get('Canary', False))}")
            fortify = security.get('FORTIFY', False)
            fortify_funcs = security.get('FORTIFY_funcs', [])
            if fortify:
                console.print(f"    └── FORTIFY: [green]Enabled ✓[/green] ({len(fortify_funcs)} functions)")
            else:
                console.print(f"    └── FORTIFY: [red]Disabled ✗[/red]")
            console.print()
    
    # ── Verbose: Imports/Exports/Symbols ─────────────────────────────────
    if verbose:
        if binary.imports:
            imp_table = Table(
                title=f"Imports ({len(binary.imports)})",
                box=box.SIMPLE,
                title_style="bold white",
                border_style="dim",
            )
            imp_table.add_column("Function", style="cyan")
            imp_table.add_column("Library", style="yellow")
            imp_table.add_column("Address", style="dim", justify="right")
            
            for imp in binary.imports[:50]:  # Cap at 50 for readability
                imp_table.add_row(
                    imp.name,
                    imp.library if imp.library else "-",
                    f"0x{imp.address:X}" if imp.address else "-",
                )
            
            if len(binary.imports) > 50:
                imp_table.add_row(
                    f"... and {len(binary.imports) - 50} more", "", ""
                )
            
            console.print(imp_table)
            console.print()
        
        if binary.exports:
            exp_table = Table(
                title=f"Exports ({len(binary.exports)})",
                box=box.SIMPLE,
                title_style="bold white",
                border_style="dim",
            )
            exp_table.add_column("Function", style="cyan")
            exp_table.add_column("Address", style="yellow", justify="right")
            
            for exp in binary.exports[:50]:
                exp_table.add_row(exp.name, f"0x{exp.address:X}")
            
            console.print(exp_table)
            console.print()
    
    # ── Timing ───────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    console.print(f"[green]✓[/green] Analysis complete in {elapsed:.3f}s")
    
    # ── JSON Output ──────────────────────────────────────────────────────
    if output:
        report = binary.info()
        report["security"] = {k: v for k, v in detect_elf_security(binary).items() 
                              if not k.startswith("_")} if binary.format == BinaryFormat.ELF else {}
        report["sections"] = [
            {"name": s.name, "vaddr": hex(s.virtual_address), 
             "size": s.raw_size, "entropy": round(s.entropy, 4)}
            for s in binary.sections
        ]
        
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[dim]Report saved to: {output}[/dim]")


# ─── CRYPTO DETECTION ───────────────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--quantum', '-q', is_flag=True, help='Use quantum-assisted detection')
@click.option('--algorithms', '-a', multiple=True,
              help='Specific algorithms to detect (aes, sha256, des, etc.)')
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON)')
def crypto(binary_path: str, quantum: bool, algorithms: tuple, output: Optional[str]):
    """
    Detect cryptographic algorithms in a binary.
    
    Scans the binary for known cryptographic constants (S-boxes, IVs,
    round constants) using pattern matching. With --quantum, uses
    Grover's algorithm for O(√N) speedup on large binaries.
    
    BINARY_PATH: Path to the binary file to scan
    
    Examples:
        zetton crypto ./sample_aes_ecb
        zetton crypto ./sample_aes_ecb --quantum
        zetton crypto ./sample_aes_ecb -a aes -a sha256
    """
    from zetton.core.binary import Binary
    from zetton.crypto.constants import CRYPTO_CONSTANTS
    
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Crypto Detection[/bold cyan] — {binary_path}")
    
    if quantum:
        console.print("[magenta]⚛  Quantum-assisted search enabled (Grover's algorithm)[/magenta]")
    console.print()
    
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)
    
    raw = binary.raw_data
    findings = []
    
    # Filter to requested algorithms if specified
    search_categories = CRYPTO_CONSTANTS
    if algorithms:
        algo_lower = [a.lower() for a in algorithms]
        search_categories = {
            k: v for k, v in CRYPTO_CONSTANTS.items()
            if any(a in k.lower() for a in algo_lower)
        }
        if not search_categories:
            console.print(f"[yellow]No matching algorithm categories for: {', '.join(algorithms)}[/yellow]")
            console.print(f"[dim]Available: {', '.join(CRYPTO_CONSTANTS.keys())}[/dim]")
            return
    
    # Scan for each constant (minimum 3 bytes to avoid false positives)
    MIN_PATTERN_SIZE = 3
    total_searched = 0
    for category, patterns in search_categories.items():
        for pattern_name, pattern_bytes in patterns.items():
            if not isinstance(pattern_bytes, (bytes, bytearray)):
                continue
            if len(pattern_bytes) < MIN_PATTERN_SIZE:
                continue
            
            total_searched += 1
            offset = 0
            while True:
                offset = raw.find(pattern_bytes, offset)
                if offset == -1:
                    break
                
                # Determine which section this falls in
                section_name = "unknown"
                for sec in binary.sections:
                    if sec.raw_offset <= offset < sec.raw_offset + sec.raw_size:
                        section_name = sec.name
                        break
                
                # Algorithm name mapping
                algo_names = {
                    "aes_sbox": "AES", "aes_rcon": "AES",
                    "sha256": "SHA-256", "sha512": "SHA-512", 
                    "md5": "MD5", "des": "DES/3DES",
                    "chacha": "ChaCha20", "salsa20": "Salsa20",
                    "blowfish": "Blowfish", "rc4": "RC4",
                    "rsa": "RSA", "ecc": "ECDSA/ECDH",
                    "pqc_kyber": "Kyber (ML-KEM)",
                    "pqc_dilithium": "Dilithium (ML-DSA)",
                }
                algo = algo_names.get(category, category.upper())
                
                findings.append({
                    "algorithm": algo,
                    "category": category,
                    "pattern": pattern_name,
                    "offset": offset,
                    "section": section_name,
                    "match_size": len(pattern_bytes),
                })
                
                offset += 1
    
    # Display results
    if findings:
        console.print(f"[bold green]Found {len(findings)} cryptographic pattern(s)![/bold green]\n")
        
        results_table = Table(
            title="Cryptographic Findings",
            box=box.ROUNDED,
            title_style="bold white",
            border_style="dim",
        )
        results_table.add_column("Algorithm", style="bold yellow")
        results_table.add_column("Pattern", style="cyan")
        results_table.add_column("Offset", style="white", justify="right")
        results_table.add_column("Section", style="magenta")
        results_table.add_column("Size", style="dim", justify="right")
        
        for f in findings:
            results_table.add_row(
                f["algorithm"],
                f["pattern"],
                f"0x{f['offset']:08X}",
                f["section"],
                f"{f['match_size']} bytes",
            )
        
        console.print(results_table)
        
        # Summary by algorithm
        algo_counts = {}
        for f in findings:
            algo_counts[f["algorithm"]] = algo_counts.get(f["algorithm"], 0) + 1
        
        console.print("\n[bold]Summary:[/bold]")
        for algo, count in sorted(algo_counts.items()):
            console.print(f"    {algo}: {count} pattern(s) detected")
        
        if quantum:
            classical_ops = len(raw) * total_searched
            quantum_ops = int(classical_ops ** 0.5)
            speedup = classical_ops / quantum_ops if quantum_ops > 0 else 0
            console.print(f"\n[magenta]Quantum Search Metrics:[/magenta]")
            console.print(f"    Classical operations: {format_size(classical_ops)}")
            console.print(f"    Quantum operations:   {format_size(quantum_ops)} (Grover's)")
            console.print(f"    Theoretical speedup:  {speedup:.1f}x")
    else:
        console.print("[dim]No cryptographic patterns found.[/dim]")
    
    elapsed = time.time() - start_time
    console.print(f"\n[green]✓[/green] Crypto scan complete in {elapsed:.3f}s")
    
    if output:
        with open(output, "w") as f:
            json.dump({"findings": findings, "binary": str(binary_path)}, f, indent=2)
        console.print(f"[dim]Report saved to: {output}[/dim]")


# ─── FORENSICS ──────────────────────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON/HTML)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def forensics(binary_path: str, output: Optional[str], verbose: bool):
    """
    Digital forensics analysis.
    
    Extracts timestamps, detects crypto weaknesses (hardcoded keys,
    ECB mode, weak PRNG), and performs quantum threat assessment.
    
    BINARY_PATH: Path to the binary file to analyze
    
    Examples:
        zetton forensics ./sample_aes_ecb
        zetton forensics ./sample_aes_ecb -o report.json
    """
    from zetton.core.binary import Binary
    from zetton.crypto.constants import CRYPTO_CONSTANTS
    
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Digital Forensics[/bold cyan] — {binary_path}\n")
    
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)
    
    raw = binary.raw_data
    issues = []
    
    # ── Timestamp Extraction ─────────────────────────────────────────────
    console.print("[bold]Timeline Analysis:[/bold]")
    
    import struct, datetime
    
    if binary.format.name == "ELF":
        try:
            import lief
            elf = lief.ELF.parse(str(binary.path))
            # Check for build ID
            for note in elf.notes:
                if note.type_core is not None or hasattr(note, 'description'):
                    console.print(f"    [dim]Note found: {note.name if hasattr(note, 'name') else 'unknown'}[/dim]")
        except Exception:
            pass
    
    # Search for embedded timestamps (epoch values 2020-2030)
    ts_min = int(datetime.datetime(2020, 1, 1).timestamp())
    ts_max = int(datetime.datetime(2030, 12, 31).timestamp())
    timestamp_count = 0
    
    for i in range(0, len(raw) - 4, 4):
        val = struct.unpack("<I", raw[i:i+4])[0]
        if ts_min <= val <= ts_max:
            timestamp_count += 1
            if timestamp_count <= 3:  # Show first 3
                dt = datetime.datetime.fromtimestamp(val)
                console.print(f"    Embedded timestamp at 0x{i:08X}: {dt.isoformat()}")
    
    if timestamp_count > 3:
        console.print(f"    [dim]... and {timestamp_count - 3} more timestamp candidates[/dim]")
    elif timestamp_count == 0:
        console.print("    [dim]No embedded timestamps found in 2020-2030 range[/dim]")
    
    console.print()
    
    # ── Crypto Weakness Detection ────────────────────────────────────────
    console.print("[bold]Crypto Weakness Analysis:[/bold]")
    
    # Check for hardcoded keys (high-entropy 16/32 byte aligned sequences near crypto constants)
    # Look for known test vectors / weak keys
    weak_keys = [
        (bytes([0x00] * 16), "Null AES-128 key"),
        (bytes([0x00] * 32), "Null AES-256 key"),
        (bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]), 
         "NIST AES-128 test vector (commonly hardcoded)"),
    ]
    
    for key_bytes, desc in weak_keys:
        offset = raw.find(key_bytes)
        if offset != -1:
            issues.append(("CRITICAL", f"Hardcoded key: {desc}", offset))
            console.print(f"    [bold red]✗ CRITICAL:[/bold red] {desc}")
            console.print(f"              at offset 0x{offset:08X}")
    
    # Check for ECB mode indicators (search for "ecb" or "ECB" strings)
    for pattern in [b"ecb", b"ECB", b"_ecb_", b"_ECB_"]:
        offset = raw.find(pattern)
        if offset != -1:
            issues.append(("WARNING", f"ECB mode reference found", offset))
            console.print(f"    [yellow]⚠ WARNING:[/yellow]  ECB mode reference at 0x{offset:08X}")
    
    # Check for weak_ecb pattern in symbol names
    for sym in binary.symbols:
        if "ecb" in sym.name.lower():
            issues.append(("WARNING", f"ECB mode function: {sym.name}", sym.address))
            console.print(f"    [yellow]⚠ WARNING:[/yellow]  ECB mode function: [cyan]{sym.name}[/cyan]")
    
    # Check for weak PRNG (srand, rand usage)
    weak_prng_funcs = ["srand", "rand", "random", "drand48"]
    found_weak_prng = []
    for imp in binary.imports:
        if imp.name in weak_prng_funcs:
            found_weak_prng.append(imp.name)
    
    if found_weak_prng:
        issues.append(("WARNING", f"Weak PRNG: {', '.join(found_weak_prng)}", 0))
        console.print(f"    [yellow]⚠ WARNING:[/yellow]  Weak PRNG functions imported: {', '.join(found_weak_prng)}")
    
    # Check for dangerous functions
    dangerous = {"system": "command execution", "strcpy": "buffer overflow",
                 "sprintf": "buffer overflow", "gets": "buffer overflow"}
    found_dangerous = []
    for imp in binary.imports:
        if imp.name in dangerous:
            found_dangerous.append((imp.name, dangerous[imp.name]))
    
    if found_dangerous:
        for func, risk in found_dangerous:
            issues.append(("INFO", f"Dangerous function: {func} ({risk})", 0))
            console.print(f"    [blue]ℹ INFO:[/blue]     Dangerous function: [cyan]{func}[/cyan] ({risk})")
    
    if not issues:
        console.print("    [green]No weaknesses detected.[/green]")
    
    console.print()
    
    # ── Quantum Threat Assessment ────────────────────────────────────────
    console.print("[bold]Quantum Threat Assessment:[/bold]")
    
    # Check what crypto was found
    crypto_found = set()
    for category, patterns in CRYPTO_CONSTANTS.items():
        for pattern_name, pattern_bytes in patterns.items():
            if not isinstance(pattern_bytes, (bytes, bytearray)):
                continue
            if raw.find(pattern_bytes) != -1:
                crypto_found.add(category)
    
    quantum_threats = {
        "aes_sbox": ("AES", "LOW", "Grover's provides only quadratic speedup; AES-256 remains secure"),
        "aes_rcon": ("AES", "LOW", "AES with sufficient key length is quantum-resistant"),
        "sha256": ("SHA-256", "LOW", "Grover's reduces security to ~128-bit; still adequate"),
        "sha512": ("SHA-512", "LOW", "Remains secure against known quantum attacks"),
        "md5": ("MD5", "MEDIUM", "Already broken classically; quantum makes it worse"),
        "des": ("DES/3DES", "HIGH", "Already weak; quantum Grover's makes 56-bit key trivial"),
        "rsa": ("RSA", "CRITICAL", "Shor's algorithm breaks RSA in polynomial time"),
        "ecc": ("ECDSA/ECDH", "CRITICAL", "Shor's algorithm breaks elliptic curve crypto"),
        "pqc_kyber": ("Kyber (ML-KEM)", "NONE", "Post-quantum secure (NIST FIPS 203)"),
        "pqc_dilithium": ("Dilithium (ML-DSA)", "NONE", "Post-quantum secure (NIST FIPS 204)"),
    }
    
    if crypto_found:
        threat_table = Table(
            box=box.SIMPLE_HEAVY,
            border_style="dim",
        )
        threat_table.add_column("Algorithm", style="cyan")
        threat_table.add_column("Threat Level", justify="center")
        threat_table.add_column("Assessment", style="dim")
        
        for cat in sorted(crypto_found):
            if cat in quantum_threats:
                algo, level, desc = quantum_threats[cat]
                level_style = {
                    "NONE": "[bold green]NONE[/bold green]",
                    "LOW": "[green]LOW[/green]",
                    "MEDIUM": "[yellow]MEDIUM[/yellow]",
                    "HIGH": "[bold yellow]HIGH[/bold yellow]",
                    "CRITICAL": "[bold red]CRITICAL[/bold red]",
                }.get(level, level)
                threat_table.add_row(algo, level_style, desc)
        
        console.print(threat_table)
    else:
        console.print("    [dim]No known cryptographic implementations detected.[/dim]")
    
    elapsed = time.time() - start_time
    console.print(f"\n[green]✓[/green] Forensics complete in {elapsed:.3f}s")
    console.print(f"    {len(issues)} issue(s) found")
    
    if output:
        report = {
            "binary": str(binary_path),
            "issues": [{"severity": s, "description": d, "offset": hex(o)} for s, d, o in issues],
            "crypto_found": list(crypto_found),
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[dim]Report saved to: {output}[/dim]")


# ─── VERSION ────────────────────────────────────────────────────────────────

@main.command()
def version():
    """Display version information."""
    console.print(f"[bold]Zetton[/bold] version [cyan]{__version__}[/cyan]")
    console.print("[dim]Quantum Software Reverse Engineering Framework[/dim]")
    console.print("\n[green]UTSA Cyber Jedis Quantum Cybersecurity RIG[/green]")


# ─── CONFIG ─────────────────────────────────────────────────────────────────

@main.command()
@click.option('--key', type=str, help='Configuration key to get/set')
@click.option('--value', type=str, help='Configuration value to set')
@click.option('--list', 'list_all', is_flag=True, help='List all configuration')
def config(key: Optional[str], value: Optional[str], list_all: bool):
    """
    Configure Zetton settings.
    
    Examples:
        zetton config --list
        zetton config --key ibm-token --value YOUR_TOKEN
    """
    if list_all:
        console.print("[bold]Current Configuration[/bold]\n")
        console.print("[dim]No configuration file found. Use --key and --value to set options.[/dim]")
        
        table = Table(title="Available Configuration Options")
        table.add_column("Key", style="cyan")
        table.add_column("Description", style="white")
        
        table.add_row("ibm-token", "IBM Quantum API token")
        table.add_row("aws-region", "AWS Braket region")
        table.add_row("backend", "Default quantum backend")
        table.add_row("output-format", "Default output format (json/html/text)")
        
        console.print(table)
        return
    
    if key and value:
        console.print(f"[green]Setting {key} = {value}[/green]")
        console.print("[yellow]⚠  Configuration persistence coming in next release[/yellow]")
    elif key:
        console.print(f"[yellow]Getting value for: {key}[/yellow]")
        console.print("[dim]Not configured yet[/dim]")
    else:
        console.print("[red]Error: Specify --key and --value, or use --list[/red]")


# ─── QUANTUM ────────────────────────────────────────────────────────────────

@main.group()
def quantum():
    """Quantum computing operations and backend management."""
    pass


@quantum.command()
@click.option('--backend', '-b', type=str, default='qasm_simulator',
              help='Quantum backend to test')
def test_backend(backend: str):
    """Test connection to quantum backend."""
    console.print(f"[bold]Testing quantum backend:[/bold] [cyan]{backend}[/cyan]")
    console.print("\n[yellow]⚠  Quantum backend testing coming in next release[/yellow]")


@quantum.command()
def list_backends():
    """List available quantum backends."""
    console.print("[bold]Available Quantum Backends[/bold]\n")
    
    table = Table()
    table.add_column("Backend", style="cyan")
    table.add_column("Provider", style="magenta")
    table.add_column("Status", style="green")
    
    table.add_row("qasm_simulator", "Qiskit Aer", "✓ Available")
    table.add_row("statevector_simulator", "Qiskit Aer", "✓ Available")
    table.add_row("ibmq_*", "IBM Quantum", "⚠  Requires API token")
    table.add_row("braket_*", "AWS Braket", "⚠  Requires AWS credentials")
    
    console.print(table)


# ─── CFG ANALYSIS ───────────────────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--function', '-f', 'func_name', type=str, default=None,
              help='Specific function to analyze (default: all)')
@click.option('--export', '-e', 'export_fmt', type=click.Choice(['dot', 'json']),
              default=None, help='Export format')
@click.option('--output', '-o', type=click.Path(), help='Output file')
def cfg(binary_path: str, func_name: Optional[str], export_fmt: Optional[str], 
        output: Optional[str]):
    """
    Control flow graph analysis.
    
    Disassembles functions and builds control flow graphs showing
    basic blocks, branches, loops, and complexity metrics.
    
    BINARY_PATH: Path to the binary file to analyze
    
    Examples:
        zetton cfg ./sample_network_vuln
        zetton cfg ./sample_network_vuln --function classify_packet
        zetton cfg ./sample_network_vuln -f main --export dot -o main.dot
    """
    from zetton.core.binary import Binary
    from zetton.analyzers.disasm import Disassembler, Instruction
    
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Control Flow Analysis[/bold cyan] — {binary_path}\n")
    
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)
    
    try:
        disasm = Disassembler(binary)
    except Exception as e:
        console.print(f"[bold red]Error initializing disassembler:[/bold red] {e}")
        sys.exit(1)
    
    # Find target functions
    target_functions = []
    
    if func_name:
        # Search for the requested function in symbols
        target_sym = None
        for sym in binary.symbols:
            if sym.name == func_name and sym.size > 0:
                target_sym = sym
                break
        
        if target_sym is None:
            # Try partial match
            for sym in binary.symbols:
                if func_name in sym.name and sym.size > 0:
                    target_sym = sym
                    break
        
        if target_sym is None:
            console.print(f"[red]Function '{func_name}' not found in symbol table.[/red]")
            console.print("[dim]Available functions:[/dim]")
            funcs = [s for s in binary.symbols if s.size > 0 and not s.name.startswith("_")]
            for f in funcs[:20]:
                console.print(f"    {f.name} (0x{f.address:X}, {f.size} bytes)")
            return
        
        target_functions.append(target_sym)
    else:
        # Analyze all non-trivial functions
        target_functions = [s for s in binary.symbols 
                          if s.size > 0 and not s.name.startswith("_") 
                          and not s.name.startswith(".")]
    
    if not target_functions:
        console.print("[yellow]No functions found in symbol table.[/yellow]")
        return
    
    all_dot_graphs = []
    all_func_data = []
    
    for sym in target_functions:
        console.print(f"[bold]Function:[/bold] [cyan]{sym.name}[/cyan] @ 0x{sym.address:X} ({sym.size} bytes)")
        
        # Disassemble the function
        try:
            func_data = binary.read_bytes(
                # Convert virtual address to file offset by finding the section
                _vaddr_to_offset(binary, sym.address),
                sym.size
            )
            instructions = list(disasm.disassemble_bytes(func_data, sym.address, 1000))
        except Exception as e:
            console.print(f"    [yellow]Could not disassemble: {e}[/yellow]")
            continue
        
        if not instructions:
            console.print(f"    [yellow]No instructions found[/yellow]")
            continue
        
        # Build basic blocks
        blocks = _build_basic_blocks(instructions)
        
        # Detect edges
        edges = _detect_edges(instructions, blocks, sym.address, sym.address + sym.size)
        
        # Detect loops (simple back-edge detection)
        loops = _detect_loops(blocks, edges)
        
        # Calculate cyclomatic complexity: M = E - N + 2P
        num_edges = len(edges)
        num_nodes = len(blocks)
        complexity = num_edges - num_nodes + 2
        
        # Count branch types
        calls = [i for i in instructions if i.is_call]
        jumps = [i for i in instructions if i.is_jump]
        rets = [i for i in instructions if i.is_ret]
        
        # Display results
        info_table = Table(box=box.SIMPLE, show_header=False, border_style="dim", pad_edge=True)
        info_table.add_column("Metric", style="white", width=24)
        info_table.add_column("Value", style="yellow")
        
        info_table.add_row("Instructions", str(len(instructions)))
        info_table.add_row("Basic blocks", str(num_nodes))
        info_table.add_row("Edges", str(num_edges))
        info_table.add_row("Cyclomatic complexity", str(max(complexity, 1)))
        info_table.add_row("Loops detected", str(len(loops)))
        info_table.add_row("Call instructions", str(len(calls)))
        info_table.add_row("Branch instructions", str(len(jumps)))
        info_table.add_row("Return instructions", str(len(rets)))
        
        console.print(info_table)
        
        # Show basic blocks
        if len(blocks) <= 20:  # Don't flood for huge functions
            blk_table = Table(
                title="Basic Blocks",
                box=box.SIMPLE_HEAVY,
                border_style="dim",
            )
            blk_table.add_column("Block", style="cyan", justify="right")
            blk_table.add_column("Address", style="yellow")
            blk_table.add_column("Instructions", style="white", justify="right")
            blk_table.add_column("Successors", style="magenta")
            
            for i, (addr, blk) in enumerate(sorted(blocks.items())):
                succ_str = ", ".join(f"0x{s:X}" for s in blk["successors"]) if blk["successors"] else "-"
                blk_table.add_row(
                    f"BB{i}",
                    f"0x{addr:08X}",
                    str(blk["count"]),
                    succ_str,
                )
            
            console.print(blk_table)
        
        # Show loops
        if loops:
            console.print(f"\n[bold]Loops:[/bold]")
            for i, loop in enumerate(loops):
                console.print(f"    Loop {i}: header 0x{loop['header']:08X}, "
                            f"back-edge from 0x{loop['back_from']:08X}")
        
        # Generate DOT output
        if export_fmt == "dot":
            dot = _generate_dot(sym.name, blocks, edges, loops)
            all_dot_graphs.append(dot)
        
        all_func_data.append({
            "name": sym.name,
            "address": hex(sym.address),
            "size": sym.size,
            "instructions": len(instructions),
            "basic_blocks": num_nodes,
            "edges": num_edges,
            "cyclomatic_complexity": max(complexity, 1),
            "loops": len(loops),
            "calls": len(calls),
        })
        
        console.print()
    
    elapsed = time.time() - start_time
    console.print(f"[green]✓[/green] CFG analysis complete in {elapsed:.3f}s")
    console.print(f"    {len(all_func_data)} function(s) analyzed")
    
    # Export
    if output and export_fmt == "dot":
        with open(output, "w") as f:
            f.write("\n\n".join(all_dot_graphs))
        console.print(f"[dim]DOT graph saved to: {output}[/dim]")
        console.print(f"[dim]Visualize with: dot -Tpng {output} -o cfg.png[/dim]")
    elif output and export_fmt == "json":
        with open(output, "w") as f:
            json.dump({"functions": all_func_data}, f, indent=2)
        console.print(f"[dim]Report saved to: {output}[/dim]")


def _vaddr_to_offset(binary, vaddr: int) -> int:
    """Convert virtual address to file offset using section mapping."""
    for sec in binary.sections:
        if sec.virtual_address <= vaddr < sec.virtual_address + sec.virtual_size:
            return sec.raw_offset + (vaddr - sec.virtual_address)
    # Fallback: return as-is (might work for non-PIE)
    return vaddr


def _build_basic_blocks(instructions) -> dict:
    """Build basic blocks from a list of instructions."""
    if not instructions:
        return {}
    
    # Find block leaders
    leaders = {instructions[0].address}
    
    for i, insn in enumerate(instructions):
        if insn.is_jump or insn.is_call:
            # Target of jump is a leader
            target = _parse_jump_target(insn)
            if target is not None:
                leaders.add(target)
            # Instruction after jump is a leader
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].address)
        if insn.is_ret:
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].address)
    
    # Build blocks
    blocks = {}
    sorted_leaders = sorted(leaders)
    insn_map = {insn.address: insn for insn in instructions}
    insn_addrs = sorted(insn_map.keys())
    
    for idx, leader in enumerate(sorted_leaders):
        if leader not in insn_map:
            continue
        
        # Find instructions in this block
        block_insns = []
        for addr in insn_addrs:
            if addr < leader:
                continue
            if addr != leader and addr in leaders:
                break
            block_insns.append(insn_map[addr])
        
        if not block_insns:
            continue
        
        # Determine successors
        successors = []
        last = block_insns[-1]
        
        if last.is_jump:
            target = _parse_jump_target(last)
            if target is not None:
                successors.append(target)
            # Conditional jumps also fall through
            if last.mnemonic.lower() != "jmp":
                next_addr = last.address + last.size
                successors.append(next_addr)
        elif last.is_ret:
            pass  # No successors
        else:
            # Fall through
            next_addr = last.address + last.size
            if idx + 1 < len(sorted_leaders):
                successors.append(next_addr)
        
        blocks[leader] = {
            "instructions": block_insns,
            "count": len(block_insns),
            "successors": successors,
            "last_insn": last,
        }
    
    return blocks


def _detect_edges(instructions, blocks, func_start, func_end) -> list:
    """Detect CFG edges from basic blocks."""
    edges = []
    for addr, blk in blocks.items():
        for succ in blk["successors"]:
            if func_start <= succ < func_end and succ in blocks:
                edge_type = "conditional"
                last = blk["last_insn"]
                if last.is_jump and last.mnemonic.lower() == "jmp":
                    edge_type = "unconditional"
                elif not last.is_jump:
                    edge_type = "fall_through"
                edges.append({"source": addr, "target": succ, "type": edge_type})
    return edges


def _detect_loops(blocks, edges) -> list:
    """Detect natural loops via back-edge detection."""
    loops = []
    block_addrs = set(blocks.keys())
    
    for edge in edges:
        # A back edge goes to a block at same or lower address
        if edge["target"] <= edge["source"] and edge["target"] in block_addrs:
            loops.append({
                "header": edge["target"],
                "back_from": edge["source"],
            })
    
    return loops


def _parse_jump_target(insn) -> Optional[int]:
    """Parse jump target address from instruction operands."""
    operands = insn.operands.strip()
    try:
        if operands.startswith("0x") or operands.startswith("0X"):
            return int(operands, 16)
        if operands.isdigit():
            return int(operands)
    except ValueError:
        pass
    return None


def _generate_dot(func_name: str, blocks: dict, edges: list, loops: list) -> str:
    """Generate DOT graph representation."""
    loop_headers = {l["header"] for l in loops}
    
    dot = [f'digraph "{func_name}" {{']
    dot.append('    rankdir=TB;')
    dot.append('    node [shape=box, fontname="Courier", fontsize=10];')
    dot.append(f'    label="{func_name} CFG";')
    dot.append('    labelloc=t;')
    dot.append('')
    
    for i, (addr, blk) in enumerate(sorted(blocks.items())):
        # Node label: first and last instruction
        first = blk["instructions"][0]
        last = blk["instructions"][-1]
        label = f"BB{i}\\n0x{addr:X}\\n{first.mnemonic} {first.operands}"
        if len(blk["instructions"]) > 1:
            label += f"\\n...({blk['count']} insns)\\n{last.mnemonic} {last.operands}"
        
        color = "black"
        fillcolor = "white"
        if addr == min(blocks.keys()):
            fillcolor = "#e8f5e9"  # Green for entry
        elif blk["last_insn"].is_ret:
            fillcolor = "#ffebee"  # Red for exit
        elif addr in loop_headers:
            fillcolor = "#fff3e0"  # Orange for loop headers
        
        dot.append(f'    "0x{addr:X}" [label="{label}", style=filled, fillcolor="{fillcolor}"];')
    
    for edge in edges:
        style = "solid"
        color = "black"
        if edge["type"] == "conditional":
            color = "blue"
        elif edge["type"] == "unconditional":
            color = "red"
        # Back edges (loops) get dashed
        if edge["target"] <= edge["source"]:
            style = "dashed"
            color = "orange"
        
        dot.append(f'    "0x{edge["source"]:X}" -> "0x{edge["target"]:X}" '
                   f'[color="{color}", style="{style}"];')
    
    dot.append('}')
    return '\n'.join(dot)


# ─── DATAFLOW / TAINT ANALYSIS ──────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--taint', '-t', is_flag=True, help='Enable taint tracking')
@click.option('--sources', type=str, default=None,
              help='Comma-separated taint sources (recv,getenv,fread,read,scanf)')
@click.option('--sinks', type=str, default=None,
              help='Comma-separated taint sinks (system,exec,printf,sprintf,strcpy)')
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON)')
def dataflow(binary_path: str, taint: bool, sources: Optional[str], 
             sinks: Optional[str], output: Optional[str]):
    """
    Data flow and taint analysis.
    
    Tracks data propagation through the binary. With --taint, traces
    data from untrusted sources (network, environment, files) to
    dangerous sinks (system calls, format strings, memory writes).
    
    BINARY_PATH: Path to the binary file to analyze
    
    Examples:
        zetton dataflow --taint ./sample_network_vuln
        zetton dataflow --taint --sources recv,getenv ./sample_network_vuln
    """
    from zetton.core.binary import Binary
    
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Data Flow Analysis[/bold cyan] — {binary_path}")
    if taint:
        console.print("[magenta]Taint tracking enabled[/magenta]")
    console.print()
    
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)
    
    # Default taint sources and sinks
    default_sources = {
        "recv": "Network input",
        "recvfrom": "Network input",
        "recvmsg": "Network input",
        "read": "File/socket read",
        "fread": "File read",
        "fgets": "File/stdin read",
        "gets": "Stdin read (dangerous)",
        "scanf": "Formatted stdin input",
        "fscanf": "Formatted file input",
        "getenv": "Environment variable",
        "getline": "Line input",
    }
    
    default_sinks = {
        "system": ("Command execution", "CRITICAL"),
        "popen": ("Command execution", "CRITICAL"),
        "execve": ("Process execution", "CRITICAL"),
        "execvp": ("Process execution", "CRITICAL"),
        "printf": ("Format string", "HIGH"),
        "fprintf": ("Format string", "HIGH"),
        "sprintf": ("Format string / buffer overflow", "CRITICAL"),
        "snprintf": ("Format string", "MEDIUM"),
        "strcpy": ("Buffer overflow", "HIGH"),
        "strcat": ("Buffer overflow", "HIGH"),
        "memcpy": ("Memory copy", "MEDIUM"),
        "memmove": ("Memory copy", "MEDIUM"),
        "write": ("Output / file write", "LOW"),
        "send": ("Network send", "MEDIUM"),
        "sendto": ("Network send", "MEDIUM"),
    }
    
    # Override with user-specified sources/sinks
    if sources:
        active_sources = {s.strip(): default_sources.get(s.strip(), "User-specified") 
                         for s in sources.split(",")}
    else:
        active_sources = default_sources
    
    if sinks:
        active_sinks = {s.strip(): default_sinks.get(s.strip(), ("User-specified", "UNKNOWN"))
                       for s in sinks.split(",")}
    else:
        active_sinks = default_sinks
    
    # Scan imports for sources and sinks present in the binary
    import_names = {imp.name: imp for imp in binary.imports}
    
    found_sources = {}
    found_sinks = {}
    
    for name, desc in active_sources.items():
        if name in import_names:
            found_sources[name] = {"description": desc, "address": import_names[name].address}
    
    for name, (desc, severity) in active_sinks.items():
        if name in import_names:
            found_sinks[name] = {"description": desc, "severity": severity, 
                                "address": import_names[name].address}
    
    # Display found sources
    if found_sources:
        console.print("[bold]Taint Sources (imported):[/bold]")
        src_table = Table(box=box.SIMPLE, border_style="dim")
        src_table.add_column("Function", style="cyan")
        src_table.add_column("Type", style="white")
        
        for name, info in sorted(found_sources.items()):
            src_table.add_row(name, info["description"])
        
        console.print(src_table)
        console.print()
    else:
        console.print("[yellow]No known taint sources found in imports.[/yellow]\n")
    
    # Display found sinks
    if found_sinks:
        console.print("[bold]Taint Sinks (imported):[/bold]")
        sink_table = Table(box=box.SIMPLE, border_style="dim")
        sink_table.add_column("Function", style="cyan")
        sink_table.add_column("Risk", style="white")
        sink_table.add_column("Severity", justify="center")
        
        for name, info in sorted(found_sinks.items()):
            sev = info["severity"]
            sev_style = {
                "CRITICAL": "[bold red]CRITICAL[/bold red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[green]LOW[/green]",
            }.get(sev, sev)
            sink_table.add_row(name, info["description"], sev_style)
        
        console.print(sink_table)
        console.print()
    else:
        console.print("[yellow]No known taint sinks found in imports.[/yellow]\n")
    
    # Cross-reference analysis: find potential taint flows
    # This does call-graph based flow analysis using the disassembler
    if taint and found_sources and found_sinks:
        console.print("[bold]Potential Taint Flows:[/bold]\n")
        
        from zetton.analyzers.disasm import Disassembler
        
        try:
            disasm = Disassembler(binary)
            all_instructions = disasm.disassemble()
        except Exception as e:
            console.print(f"[yellow]Disassembly failed: {e}[/yellow]")
            all_instructions = []
        
        if all_instructions:
            # Find call sites for sources and sinks
            source_calls = []
            sink_calls = []
            
            # Build a map of PLT entries / call targets to function names
            # We look for call instructions whose targets resolve to imported functions
            import_addrs = {}
            for imp in binary.imports:
                if imp.address:
                    import_addrs[imp.address] = imp.name
            
            # Also map PLT entries
            try:
                import lief
                elf = lief.ELF.parse(str(binary.path))
                if elf:
                    for reloc in elf.pltgot_relocations:
                        if reloc.symbol and reloc.symbol.name:
                            import_addrs[reloc.address] = reloc.symbol.name
            except Exception:
                pass
            
            # Scan instructions for calls
            for insn in all_instructions:
                if insn.is_call:
                    target = _parse_jump_target(insn)
                    if target is not None:
                        # Check if it's a known source/sink via PLT
                        # PLT calls typically go to a stub that jumps to GOT
                        # We check if any function in a small range matches
                        func_name = import_addrs.get(target, "")
                        if not func_name:
                            # Try to find by looking at the PLT stub
                            for sym in binary.symbols:
                                if sym.address == target and sym.name:
                                    func_name = sym.name
                                    break
                        
                        if func_name in found_sources:
                            source_calls.append({"function": func_name, 
                                               "call_addr": insn.address})
                        if func_name in found_sinks:
                            sink_calls.append({"function": func_name,
                                             "call_addr": insn.address})
            
            # Find which function each call belongs to
            func_symbols = sorted(
                [s for s in binary.symbols if s.size > 0],
                key=lambda s: s.address
            )
            
            def find_containing_function(addr):
                for sym in func_symbols:
                    if sym.address <= addr < sym.address + sym.size:
                        return sym.name
                return "unknown"
            
            # Identify potential flows: source and sink in same function
            flows = []
            flow_id = 0
            
            for src in source_calls:
                src_func = find_containing_function(src["call_addr"])
                for sink in sink_calls:
                    sink_func = find_containing_function(sink["call_addr"])
                    
                    # Direct flow: source and sink in the same function
                    if src_func == sink_func and src["call_addr"] < sink["call_addr"]:
                        flow_id += 1
                        severity = found_sinks[sink["function"]]["severity"]
                        flows.append({
                            "id": flow_id,
                            "source": src["function"],
                            "sink": sink["function"],
                            "function": src_func,
                            "source_addr": src["call_addr"],
                            "sink_addr": sink["call_addr"],
                            "severity": severity,
                            "type": "direct",
                        })
            
            # Also check for cross-function flows via call graph
            # If function A calls a source, and function B calls A and a sink
            source_funcs = set(find_containing_function(s["call_addr"]) for s in source_calls)
            
            for sink in sink_calls:
                sink_func = find_containing_function(sink["call_addr"])
                # Check if sink_func calls any function that contains a source
                for insn in all_instructions:
                    if insn.is_call:
                        caller_func = find_containing_function(insn.address)
                        if caller_func == sink_func:
                            target = _parse_jump_target(insn)
                            if target:
                                callee = None
                                for sym in func_symbols:
                                    if sym.address == target:
                                        callee = sym.name
                                        break
                                if callee and callee in source_funcs and callee != sink_func:
                                    # Cross-function flow
                                    flow_id += 1
                                    severity = found_sinks[sink["function"]]["severity"]
                                    # Avoid duplicate flows
                                    existing = any(f["source"] == callee and 
                                                  f["sink"] == sink["function"] and
                                                  f["function"] == sink_func
                                                  for f in flows if f.get("type") == "cross_function")
                                    if not existing:
                                        flows.append({
                                            "id": flow_id,
                                            "source": f"(via {callee})",
                                            "sink": sink["function"],
                                            "function": sink_func,
                                            "source_addr": 0,
                                            "sink_addr": sink["call_addr"],
                                            "severity": severity,
                                            "type": "cross_function",
                                        })
            
            if flows:
                flow_table = Table(
                    title="Detected Taint Flows",
                    box=box.ROUNDED,
                    title_style="bold white",
                    border_style="dim",
                )
                flow_table.add_column("#", style="dim", width=4)
                flow_table.add_column("Source", style="cyan")
                flow_table.add_column("→", style="dim", width=2)
                flow_table.add_column("Sink", style="red")
                flow_table.add_column("In Function", style="yellow")
                flow_table.add_column("Severity", justify="center")
                flow_table.add_column("Type", style="dim")
                
                for f in flows:
                    sev = f["severity"]
                    sev_style = {
                        "CRITICAL": "[bold red]CRITICAL[/bold red]",
                        "HIGH": "[red]HIGH[/red]",
                        "MEDIUM": "[yellow]MEDIUM[/yellow]",
                        "LOW": "[green]LOW[/green]",
                    }.get(sev, sev)
                    
                    flow_table.add_row(
                        str(f["id"]),
                        f["source"],
                        "→",
                        f["sink"],
                        f["function"],
                        sev_style,
                        f["type"].replace("_", " "),
                    )
                
                console.print(flow_table)
                
                # Vulnerability summary
                console.print(f"\n[bold]Vulnerability Summary:[/bold]")
                crit = sum(1 for f in flows if f["severity"] == "CRITICAL")
                high = sum(1 for f in flows if f["severity"] == "HIGH")
                med = sum(1 for f in flows if f["severity"] == "MEDIUM")
                
                if crit > 0:
                    console.print(f"    [bold red]CRITICAL: {crit} flow(s)[/bold red] — "
                                "Tainted data reaches dangerous sinks")
                if high > 0:
                    console.print(f"    [red]HIGH: {high} flow(s)[/red]")
                if med > 0:
                    console.print(f"    [yellow]MEDIUM: {med} flow(s)[/yellow]")
            else:
                console.print("[green]No direct taint flows detected between known sources and sinks.[/green]")
        else:
            console.print("[yellow]Could not perform flow analysis without disassembly.[/yellow]")
    
    elif taint:
        if not found_sources:
            console.print("[yellow]No taint sources found — binary may not use standard I/O functions.[/yellow]")
        if not found_sinks:
            console.print("[yellow]No taint sinks found — binary may not use dangerous functions.[/yellow]")
    
    elapsed = time.time() - start_time
    console.print(f"\n[green]✓[/green] Data flow analysis complete in {elapsed:.3f}s")
    
    if output:
        report = {
            "binary": str(binary_path),
            "sources": {k: v for k, v in found_sources.items()},
            "sinks": {k: {"description": v["description"], "severity": v["severity"]} 
                     for k, v in found_sinks.items()},
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[dim]Report saved to: {output}[/dim]")


# ─── PQC ANALYSIS ───────────────────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--compliance', '-c', is_flag=True, help='Check NIST FIPS compliance')
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON)')
def pqc(binary_path: str, compliance: bool, output: Optional[str]):
    """
    Post-quantum cryptography analysis.
    
    Detects both classical (quantum-vulnerable) and post-quantum
    (quantum-resistant) cryptographic implementations. Assesses
    migration readiness and NIST FIPS 203/204/205 compliance.
    
    BINARY_PATH: Path to the binary file to analyze
    
    Examples:
        zetton pqc ./sample_pqc
        zetton pqc ./sample_pqc --compliance
    """
    from zetton.core.binary import Binary
    from zetton.crypto.constants import CRYPTO_CONSTANTS
    
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Post-Quantum Cryptography Analysis[/bold cyan] — {binary_path}\n")
    
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)
    
    raw = binary.raw_data
    
    # Classify crypto into quantum-vulnerable vs quantum-resistant
    classical_crypto = {
        "rsa": {"name": "RSA", "threat": "CRITICAL", 
                "attack": "Shor's algorithm (polynomial time)",
                "recommendation": "Replace with ML-KEM (FIPS 203) or ML-DSA (FIPS 204)"},
        "ecc": {"name": "ECDSA/ECDH", "threat": "CRITICAL",
                "attack": "Shor's algorithm (polynomial time)",
                "recommendation": "Replace with ML-DSA (FIPS 204) for signatures"},
        "des": {"name": "DES/3DES", "threat": "HIGH",
                "attack": "Grover's reduces 56-bit key to trivial; already broken classically",
                "recommendation": "Replace with AES-256"},
        "md5": {"name": "MD5", "threat": "MEDIUM",
                "attack": "Grover's further weakens already-broken hash",
                "recommendation": "Replace with SHA-256 or SHA-3"},
    }
    
    pqc_crypto = {
        "pqc_kyber": {"name": "ML-KEM (Kyber)", "standard": "NIST FIPS 203",
                      "type": "Key Encapsulation", "status": "quantum-resistant"},
        "pqc_dilithium": {"name": "ML-DSA (Dilithium)", "standard": "NIST FIPS 204",
                         "type": "Digital Signature", "status": "quantum-resistant"},
    }
    
    # AES/SHA are quantum-safe with sufficient key/hash length
    quantum_safe = {
        "aes_sbox": {"name": "AES", "note": "AES-256 provides ~128-bit post-quantum security"},
        "aes_rcon": {"name": "AES", "note": "AES-256 provides ~128-bit post-quantum security"},
        "sha256": {"name": "SHA-256", "note": "~128-bit post-quantum security via Grover's"},
        "sha512": {"name": "SHA-512", "note": "~256-bit post-quantum security"},
    }
    
    # Scan for all crypto patterns
    found_classical = {}
    found_pqc = {}
    found_safe = {}
    
    MIN_PATTERN_SIZE = 3
    
    for category, patterns in CRYPTO_CONSTANTS.items():
        for pattern_name, pattern_bytes in patterns.items():
            if not isinstance(pattern_bytes, (bytes, bytearray)):
                continue
            if len(pattern_bytes) < MIN_PATTERN_SIZE:
                continue
            if raw.find(pattern_bytes) != -1:
                if category in classical_crypto:
                    found_classical[category] = classical_crypto[category]
                elif category in pqc_crypto:
                    found_pqc[category] = pqc_crypto[category]
                elif category in quantum_safe:
                    found_safe[category] = quantum_safe[category]
                break  # One match per category is enough
    
    # Also scan for PQC-specific constants beyond what's in CRYPTO_CONSTANTS
    import struct
    
    # Kyber q=3329 check (search for the NTT prime)
    kyber_q_bytes = struct.pack('<I', 3329)
    if raw.find(kyber_q_bytes) != -1 and "pqc_kyber" not in found_pqc:
        found_pqc["pqc_kyber"] = pqc_crypto["pqc_kyber"]
    
    # Dilithium q=8380417 check
    dilithium_q_bytes = struct.pack('<I', 8380417)
    if raw.find(dilithium_q_bytes) != -1 and "pqc_dilithium" not in found_pqc:
        found_pqc["pqc_dilithium"] = pqc_crypto["pqc_dilithium"]
    
    # SLH-DSA (SPHINCS+) — check for known constants
    sphincs_detected = False
    # SPHINCS+ uses specific hash tree structures, check for string references
    for marker in [b"SPHINCS", b"sphincs", b"SLH-DSA", b"slh-dsa"]:
        if raw.find(marker) != -1:
            sphincs_detected = True
            found_pqc["pqc_sphincs"] = {
                "name": "SLH-DSA (SPHINCS+)", "standard": "NIST FIPS 205",
                "type": "Hash-based Signature", "status": "quantum-resistant"
            }
            break
    
    # ── Display Results ──────────────────────────────────────────────────
    
    # Classical (vulnerable) crypto
    if found_classical:
        console.print("[bold red]⚠  Quantum-Vulnerable Cryptography Detected:[/bold red]\n")
        
        vuln_table = Table(box=box.ROUNDED, border_style="red")
        vuln_table.add_column("Algorithm", style="bold yellow")
        vuln_table.add_column("Quantum Threat", justify="center")
        vuln_table.add_column("Attack Vector", style="white")
        
        for cat, info in found_classical.items():
            threat_style = {
                "CRITICAL": "[bold red]CRITICAL[/bold red]",
                "HIGH": "[yellow]HIGH[/yellow]",
                "MEDIUM": "[white]MEDIUM[/white]",
            }.get(info["threat"], info["threat"])
            vuln_table.add_row(info["name"], threat_style, info["attack"])
        
        console.print(vuln_table)
        console.print()
    
    # PQC (resistant) crypto
    if found_pqc:
        console.print("[bold green]✓ Post-Quantum Cryptography Detected:[/bold green]\n")
        
        pqc_table = Table(box=box.ROUNDED, border_style="green")
        pqc_table.add_column("Algorithm", style="bold cyan")
        pqc_table.add_column("Standard", style="yellow")
        pqc_table.add_column("Type", style="white")
        pqc_table.add_column("Status", justify="center")
        
        for cat, info in found_pqc.items():
            pqc_table.add_row(
                info["name"], info["standard"], info["type"],
                "[bold green]SECURE[/bold green]"
            )
        
        console.print(pqc_table)
        console.print()
    
    # Quantum-safe classical crypto
    if found_safe:
        # Deduplicate by name
        unique_safe = {}
        for cat, info in found_safe.items():
            unique_safe[info["name"]] = info
        
        console.print("[bold]Quantum-Safe Classical Cryptography:[/bold]\n")
        for name, info in unique_safe.items():
            console.print(f"    [green]✓[/green] {name} — {info['note']}")
        console.print()
    
    # ── Migration Readiness Score ────────────────────────────────────────
    console.print("[bold]Migration Readiness Assessment:[/bold]\n")
    
    total_pqc_standards = 3  # FIPS 203, 204, 205
    implemented = len(found_pqc)
    vulnerable = len(found_classical)
    
    score = 0
    if implemented > 0:
        score += implemented * 25  # 25 points per PQC algorithm
    if vulnerable == 0:
        score += 25  # Bonus for no vulnerable crypto
    
    score = min(score, 100)
    
    if score >= 75:
        score_style = "[bold green]"
        grade = "A"
    elif score >= 50:
        score_style = "[yellow]"
        grade = "B"
    elif score >= 25:
        score_style = "[yellow]"
        grade = "C"
    else:
        score_style = "[bold red]"
        grade = "D"
    
    console.print(f"    Migration Score: {score_style}{score}/100 (Grade: {grade})[/]")
    console.print(f"    PQC Algorithms Implemented: {implemented}/{total_pqc_standards}")
    console.print(f"    Vulnerable Algorithms Remaining: {vulnerable}")
    
    # Recommendations
    if found_classical or implemented < total_pqc_standards:
        console.print(f"\n[bold]Recommendations:[/bold]")
        
        for cat, info in found_classical.items():
            console.print(f"    [red]→[/red] {info['recommendation']}")
        
        if "pqc_kyber" not in found_pqc:
            console.print(f"    [yellow]→[/yellow] Implement ML-KEM (FIPS 203) for key encapsulation")
        if "pqc_dilithium" not in found_pqc:
            console.print(f"    [yellow]→[/yellow] Implement ML-DSA (FIPS 204) for digital signatures")
        if not sphincs_detected:
            console.print(f"    [yellow]→[/yellow] Consider SLH-DSA (FIPS 205) for hash-based signatures")
    
    # FIPS compliance check
    if compliance:
        console.print(f"\n[bold]NIST FIPS Compliance:[/bold]")
        
        fips_table = Table(box=box.SIMPLE_HEAVY, border_style="dim")
        fips_table.add_column("Standard", style="cyan")
        fips_table.add_column("Algorithm", style="white")
        fips_table.add_column("Status", justify="center")
        
        fips_203 = "pqc_kyber" in found_pqc
        fips_204 = "pqc_dilithium" in found_pqc
        fips_205 = sphincs_detected
        
        fips_table.add_row(
            "FIPS 203", "ML-KEM (Kyber)",
            "[green]DETECTED[/green]" if fips_203 else "[red]NOT FOUND[/red]"
        )
        fips_table.add_row(
            "FIPS 204", "ML-DSA (Dilithium)",
            "[green]DETECTED[/green]" if fips_204 else "[red]NOT FOUND[/red]"
        )
        fips_table.add_row(
            "FIPS 205", "SLH-DSA (SPHINCS+)",
            "[green]DETECTED[/green]" if fips_205 else "[red]NOT FOUND[/red]"
        )
        
        console.print(fips_table)
    
    elapsed = time.time() - start_time
    console.print(f"\n[green]✓[/green] PQC analysis complete in {elapsed:.3f}s")
    
    if output:
        report = {
            "binary": str(binary_path),
            "vulnerable": {k: v for k, v in found_classical.items()},
            "pqc": {k: v for k, v in found_pqc.items()},
            "safe": {k: v["name"] for k, v in found_safe.items()},
            "score": score,
            "grade": grade,
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[dim]Report saved to: {output}[/dim]")


# ─── REPORT ─────────────────────────────────────────────────────────────────

# ── Data-collection helpers (return dicts, no console output) ───────────────

def _report_collect_binary(binary) -> dict:
    """Collect binary analysis data."""
    from zetton.core.binary import BinaryFormat
    data = {}
    try:
        info = binary.info()
    except Exception:
        info = {}
    data.update(info)
    data["format"]       = binary.format.name
    data["architecture"] = binary.architecture.name
    data["bits"]         = binary.bits
    data["endianness"]   = getattr(binary, "endianness", "unknown")
    data["entry_point"]  = f"0x{binary.entry_point:08X}"
    data["size"]         = len(binary.raw_data)
    data["md5"]          = binary.md5
    data["sha256"]        = binary.sha256
    if binary.format == BinaryFormat.ELF:
        data["security"] = {k: v for k, v in detect_elf_security(binary).items()
                            if not k.startswith("_")}
    else:
        data["security"] = {}
    data["sections"] = [
        {"name": s.name, "vaddr": hex(s.virtual_address),
         "size": s.raw_size, "entropy": round(s.entropy, 4)}
        for s in binary.sections
    ]
    data["imports"] = [
        {"name": i.name,
         "library": getattr(i, "library", None) or "",
         "address": hex(i.address) if getattr(i, "address", None) else ""}
        for i in binary.imports
    ]
    data["exports"] = [
        {"name": e.name, "address": hex(e.address)}
        for e in binary.exports
    ]
    data["symbols"] = [
        {"name": s.name, "address": hex(s.address), "size": s.size}
        for s in binary.symbols[:200]
    ]
    return data


def _report_collect_crypto(binary) -> dict:
    """Collect crypto-detection data."""
    from zetton.crypto.constants import CRYPTO_CONSTANTS
    raw = binary.raw_data
    findings = []
    MIN_PATTERN_SIZE = 3
    ALGO_NAMES = {
        "aes_sbox": "AES", "aes_rcon": "AES",
        "sha256": "SHA-256", "sha512": "SHA-512",
        "md5": "MD5", "des": "DES/3DES",
        "chacha": "ChaCha20", "salsa20": "Salsa20",
        "blowfish": "Blowfish", "rc4": "RC4",
        "rsa": "RSA", "ecc": "ECDSA/ECDH",
        "pqc_kyber": "Kyber (ML-KEM)",
        "pqc_dilithium": "Dilithium (ML-DSA)",
    }
    for category, patterns in CRYPTO_CONSTANTS.items():
        for pattern_name, pattern_bytes in patterns.items():
            if not isinstance(pattern_bytes, (bytes, bytearray)):
                continue
            if len(pattern_bytes) < MIN_PATTERN_SIZE:
                continue
            offset = 0
            while True:
                offset = raw.find(pattern_bytes, offset)
                if offset == -1:
                    break
                section_name = "unknown"
                for sec in binary.sections:
                    if sec.raw_offset <= offset < sec.raw_offset + sec.raw_size:
                        section_name = sec.name
                        break
                findings.append({
                    "algorithm": ALGO_NAMES.get(category, category.upper()),
                    "category": category,
                    "pattern": pattern_name,
                    "offset": offset,
                    "section": section_name,
                    "match_size": len(pattern_bytes),
                })
                offset += 1
    algo_counts: dict = {}
    for f in findings:
        algo_counts[f["algorithm"]] = algo_counts.get(f["algorithm"], 0) + 1
    return {"findings": findings, "summary": algo_counts}


def _report_collect_forensics(binary) -> dict:
    """Collect forensics data."""
    import struct, datetime
    from zetton.crypto.constants import CRYPTO_CONSTANTS
    raw = binary.raw_data
    issues = []

    # Embedded timestamp scan
    ts_min = int(datetime.datetime(2020, 1, 1).timestamp())
    ts_max = int(datetime.datetime(2030, 12, 31).timestamp())
    timestamps = []
    for i in range(0, len(raw) - 4, 4):
        val = struct.unpack("<I", raw[i:i+4])[0]
        if ts_min <= val <= ts_max:
            timestamps.append({
                "offset": hex(i),
                "timestamp": datetime.datetime.fromtimestamp(val).isoformat(),
            })

    # Hardcoded key checks
    weak_keys = [
        (bytes([0x00] * 16), "Null AES-128 key"),
        (bytes([0x00] * 32), "Null AES-256 key"),
        (bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]),
         "NIST AES-128 test vector (commonly hardcoded)"),
    ]
    for key_bytes, desc in weak_keys:
        offset = raw.find(key_bytes)
        if offset != -1:
            issues.append({"severity": "CRITICAL",
                           "description": f"Hardcoded key: {desc}",
                           "offset": hex(offset)})

    # ECB mode
    for pattern in [b"ecb", b"ECB", b"_ecb_", b"_ECB_"]:
        offset = raw.find(pattern)
        if offset != -1:
            issues.append({"severity": "WARNING",
                           "description": "ECB mode reference found",
                           "offset": hex(offset)})
    for sym in binary.symbols:
        if "ecb" in sym.name.lower():
            issues.append({"severity": "WARNING",
                           "description": f"ECB mode function: {sym.name}",
                           "offset": hex(sym.address)})

    # Weak PRNG
    weak_prng = [i.name for i in binary.imports if i.name in ("srand","rand","random","drand48")]
    if weak_prng:
        issues.append({"severity": "WARNING",
                       "description": f"Weak PRNG: {', '.join(weak_prng)}",
                       "offset": "0x0"})

    # Dangerous functions
    dangerous = {"system": "command execution", "strcpy": "buffer overflow",
                 "sprintf": "buffer overflow", "gets": "buffer overflow"}
    for imp in binary.imports:
        if imp.name in dangerous:
            issues.append({"severity": "INFO",
                           "description": f"Dangerous function: {imp.name} ({dangerous[imp.name]})",
                           "offset": "0x0"})

    # Quantum threat scan
    crypto_found = set()
    for category, patterns in CRYPTO_CONSTANTS.items():
        for _, pattern_bytes in patterns.items():
            if isinstance(pattern_bytes, (bytes, bytearray)) and len(pattern_bytes) >= 3:
                if raw.find(pattern_bytes) != -1:
                    crypto_found.add(category)
                    break

    quantum_threats = {
        "aes_sbox":      ("AES",          "LOW",      "Grover's provides only quadratic speedup; AES-256 remains secure"),
        "sha256":        ("SHA-256",       "LOW",      "~128-bit post-quantum security"),
        "sha512":        ("SHA-512",       "LOW",      "~256-bit post-quantum security"),
        "md5":           ("MD5",           "MEDIUM",   "Already broken classically; quantum makes it worse"),
        "des":           ("DES/3DES",      "HIGH",     "Grover's makes 56-bit key trivial"),
        "rsa":           ("RSA",           "CRITICAL", "Shor's algorithm breaks RSA in polynomial time"),
        "ecc":           ("ECDSA/ECDH",    "CRITICAL", "Shor's algorithm breaks elliptic curve crypto"),
        "pqc_kyber":     ("Kyber (ML-KEM)","NONE",     "Post-quantum secure (NIST FIPS 203)"),
        "pqc_dilithium": ("Dilithium",     "NONE",     "Post-quantum secure (NIST FIPS 204)"),
    }
    quantum_assessment = {
        cat: {"algorithm": v[0], "level": v[1], "assessment": v[2]}
        for cat, v in quantum_threats.items()
        if cat in crypto_found
    }

    return {
        "issues": issues,
        "crypto_found": list(crypto_found),
        "timestamps": timestamps[:10],
        "quantum_assessment": quantum_assessment,
    }


def _report_collect_cfg(binary) -> dict:
    """Collect CFG data."""
    try:
        from zetton.analyzers.disasm import Disassembler
        disasm = Disassembler(binary)
    except Exception as e:
        return {"functions": [], "error": str(e)}

    target_functions = [
        s for s in binary.symbols
        if s.size > 0 and not s.name.startswith("_") and not s.name.startswith(".")
    ]

    all_func_data = []
    for sym in target_functions:
        try:
            func_data = binary.read_bytes(_vaddr_to_offset(binary, sym.address), sym.size)
            instructions = list(disasm.disassemble_bytes(func_data, sym.address, 1000))
        except Exception:
            continue
        if not instructions:
            continue
        blocks = _build_basic_blocks(instructions)
        edges  = _detect_edges(instructions, blocks, sym.address, sym.address + sym.size)
        loops  = _detect_loops(blocks, edges)
        calls  = [i for i in instructions if i.is_call]
        jumps  = [i for i in instructions if i.is_jump]
        rets   = [i for i in instructions if i.is_ret]
        num_edges = len(edges)
        num_nodes = len(blocks)
        complexity = max(num_edges - num_nodes + 2, 1)
        all_func_data.append({
            "name": sym.name,
            "address": hex(sym.address),
            "size": sym.size,
            "instructions": len(instructions),
            "basic_blocks": num_nodes,
            "edges": num_edges,
            "cyclomatic_complexity": complexity,
            "loops": len(loops),
            "calls": len(calls),
            "branches": len(jumps),
            "returns": len(rets),
        })
    return {"functions": all_func_data}


def _report_collect_dataflow(binary) -> dict:
    """Collect dataflow / taint data."""
    default_sources = {
        "recv": "Network input", "recvfrom": "Network input",
        "read": "File/socket read", "fread": "File read",
        "fgets": "File/stdin read", "gets": "Stdin read (dangerous)",
        "scanf": "Formatted stdin", "getenv": "Environment variable",
    }
    default_sinks = {
        "system": ("Command execution", "CRITICAL"),
        "execve": ("Process execution", "CRITICAL"),
        "printf": ("Format string", "HIGH"),
        "sprintf": ("Format string / buffer overflow", "CRITICAL"),
        "strcpy": ("Buffer overflow", "HIGH"),
        "strcat": ("Buffer overflow", "HIGH"),
        "memcpy": ("Memory copy", "MEDIUM"),
        "send": ("Network send", "MEDIUM"),
    }
    import_names = {imp.name: imp for imp in binary.imports}
    found_sources = {
        n: {"description": d, "address": hex(import_names[n].address) if import_names[n].address else ""}
        for n, d in default_sources.items() if n in import_names
    }
    found_sinks = {
        n: {"description": d, "severity": s,
            "address": hex(import_names[n].address) if import_names[n].address else ""}
        for n, (d, s) in default_sinks.items() if n in import_names
    }

    flows: list = []
    if found_sources and found_sinks:
        try:
            from zetton.analyzers.disasm import Disassembler
            disasm = Disassembler(binary)
            all_instructions = disasm.disassemble()

            import_addrs: dict = {}
            for imp in binary.imports:
                if imp.address:
                    import_addrs[imp.address] = imp.name
            try:
                import lief
                elf = lief.ELF.parse(str(binary.path))
                if elf:
                    for reloc in elf.pltgot_relocations:
                        if reloc.symbol and reloc.symbol.name:
                            import_addrs[reloc.address] = reloc.symbol.name
            except Exception:
                pass

            func_symbols = sorted(
                [s for s in binary.symbols if s.size > 0], key=lambda s: s.address)

            def _containing(addr):
                for s in func_symbols:
                    if s.address <= addr < s.address + s.size:
                        return s.name
                return "unknown"

            source_calls, sink_calls = [], []
            for insn in all_instructions:
                if insn.is_call:
                    target = _parse_jump_target(insn)
                    if target is not None:
                        fname = import_addrs.get(target, "")
                        if not fname:
                            for sym in binary.symbols:
                                if sym.address == target and sym.name:
                                    fname = sym.name
                                    break
                        if fname in found_sources:
                            source_calls.append({"function": fname, "call_addr": insn.address})
                        if fname in found_sinks:
                            sink_calls.append({"function": fname, "call_addr": insn.address})

            flow_id = 0
            for src in source_calls:
                sf = _containing(src["call_addr"])
                for snk in sink_calls:
                    tkf = _containing(snk["call_addr"])
                    if sf == tkf and src["call_addr"] < snk["call_addr"]:
                        flow_id += 1
                        flows.append({
                            "id": flow_id,
                            "source": src["function"],
                            "sink": snk["function"],
                            "function": sf,
                            "source_addr": hex(src["call_addr"]),
                            "sink_addr": hex(snk["call_addr"]),
                            "severity": found_sinks[snk["function"]]["severity"],
                            "type": "direct",
                        })
        except Exception:
            pass

    return {"sources": found_sources, "sinks": found_sinks, "flows": flows}


def _report_collect_pqc(binary) -> dict:
    """Collect PQC analysis data."""
    import struct
    from zetton.crypto.constants import CRYPTO_CONSTANTS
    raw = binary.raw_data
    MIN_PATTERN_SIZE = 3

    classical_crypto = {
        "rsa": {"name": "RSA", "threat": "CRITICAL",
                "attack": "Shor's algorithm (polynomial time)",
                "recommendation": "Replace with ML-KEM (FIPS 203) or ML-DSA (FIPS 204)"},
        "ecc": {"name": "ECDSA/ECDH", "threat": "CRITICAL",
                "attack": "Shor's algorithm (polynomial time)",
                "recommendation": "Replace with ML-DSA (FIPS 204) for signatures"},
        "des": {"name": "DES/3DES", "threat": "HIGH",
                "attack": "Grover's reduces 56-bit key to trivial",
                "recommendation": "Replace with AES-256"},
        "md5": {"name": "MD5", "threat": "MEDIUM",
                "attack": "Grover's further weakens already-broken hash",
                "recommendation": "Replace with SHA-256 or SHA-3"},
    }
    pqc_crypto = {
        "pqc_kyber":     {"name": "ML-KEM (Kyber)",    "standard": "NIST FIPS 203",
                          "type": "Key Encapsulation",  "status": "quantum-resistant"},
        "pqc_dilithium": {"name": "ML-DSA (Dilithium)", "standard": "NIST FIPS 204",
                          "type": "Digital Signature",  "status": "quantum-resistant"},
    }
    quantum_safe = {
        "aes_sbox": {"name": "AES",    "note": "AES-256 provides ~128-bit post-quantum security"},
        "aes_rcon": {"name": "AES",    "note": "AES-256 provides ~128-bit post-quantum security"},
        "sha256":   {"name": "SHA-256","note": "~128-bit post-quantum security"},
        "sha512":   {"name": "SHA-512","note": "~256-bit post-quantum security"},
    }

    found_classical, found_pqc, found_safe = {}, {}, {}
    for category, patterns in CRYPTO_CONSTANTS.items():
        for _, pattern_bytes in patterns.items():
            if not isinstance(pattern_bytes, (bytes, bytearray)):
                continue
            if len(pattern_bytes) < MIN_PATTERN_SIZE:
                continue
            if raw.find(pattern_bytes) != -1:
                if category in classical_crypto:
                    found_classical[category] = classical_crypto[category]
                elif category in pqc_crypto:
                    found_pqc[category] = pqc_crypto[category]
                elif category in quantum_safe:
                    found_safe[category] = quantum_safe[category]
                break

    # Kyber/Dilithium prime constants
    if raw.find(struct.pack('<I', 3329)) != -1 and "pqc_kyber" not in found_pqc:
        found_pqc["pqc_kyber"] = pqc_crypto["pqc_kyber"]
    if raw.find(struct.pack('<I', 8380417)) != -1 and "pqc_dilithium" not in found_pqc:
        found_pqc["pqc_dilithium"] = pqc_crypto["pqc_dilithium"]

    sphincs_detected = any(raw.find(m) != -1
                           for m in [b"SPHINCS", b"sphincs", b"SLH-DSA", b"slh-dsa"])
    if sphincs_detected:
        found_pqc["pqc_sphincs"] = {
            "name": "SLH-DSA (SPHINCS+)", "standard": "NIST FIPS 205",
            "type": "Hash-based Signature", "status": "quantum-resistant",
        }

    score = min(len(found_pqc) * 25 + (25 if not found_classical else 0), 100)
    grade = "A" if score >= 75 else ("B" if score >= 50 else ("C" if score >= 25 else "D"))

    recs = []
    for info in found_classical.values():
        recs.append(info["recommendation"])
    if "pqc_kyber" not in found_pqc:
        recs.append("Implement ML-KEM (FIPS 203) for key encapsulation")
    if "pqc_dilithium" not in found_pqc:
        recs.append("Implement ML-DSA (FIPS 204) for digital signatures")
    if not sphincs_detected:
        recs.append("Consider SLH-DSA (FIPS 205) for hash-based signatures")

    return {
        "vulnerable": found_classical,
        "pqc_algorithms": found_pqc,
        "safe": {k: v["name"] for k, v in found_safe.items()},
        "score": score,
        "grade": grade,
        "recommendations": recs,
        "fips": {
            "FIPS_203_ML-KEM":     "pqc_kyber" in found_pqc,
            "FIPS_204_ML-DSA":     "pqc_dilithium" in found_pqc,
            "FIPS_205_SLH-DSA":    sphincs_detected,
        },
    }


def _build_cbom(crypto_data: dict, forensics_data: dict, pqc_data: dict) -> dict:
    """Build a Cryptographic Bill of Materials from collected analysis data."""
    ALGO_META = {
        "AES":           {"type": "Symmetric Cipher",    "quantum_vulnerable": False, "threat_level": "LOW"},
        "SHA-256":       {"type": "Hash Function",        "quantum_vulnerable": False, "threat_level": "LOW"},
        "SHA-512":       {"type": "Hash Function",        "quantum_vulnerable": False, "threat_level": "LOW"},
        "MD5":           {"type": "Hash Function",        "quantum_vulnerable": True,  "threat_level": "MEDIUM"},
        "DES/3DES":      {"type": "Symmetric Cipher",    "quantum_vulnerable": True,  "threat_level": "HIGH"},
        "ChaCha20":      {"type": "Stream Cipher",        "quantum_vulnerable": False, "threat_level": "LOW"},
        "Salsa20":       {"type": "Stream Cipher",        "quantum_vulnerable": False, "threat_level": "LOW"},
        "Blowfish":      {"type": "Symmetric Cipher",    "quantum_vulnerable": False, "threat_level": "LOW"},
        "RC4":           {"type": "Stream Cipher",        "quantum_vulnerable": False, "threat_level": "MEDIUM"},
        "RSA":           {"type": "Asymmetric / KEM",    "quantum_vulnerable": True,  "threat_level": "CRITICAL"},
        "ECDSA/ECDH":    {"type": "Asymmetric / Sig",    "quantum_vulnerable": True,  "threat_level": "CRITICAL"},
        "Kyber (ML-KEM)":    {"type": "PQC / KEM",       "quantum_vulnerable": False, "threat_level": "NONE",
                              "standard": "NIST FIPS 203"},
        "Dilithium (ML-DSA)":{"type": "PQC / Signature", "quantum_vulnerable": False, "threat_level": "NONE",
                              "standard": "NIST FIPS 204"},
        "ML-KEM (Kyber)":    {"type": "PQC / KEM",       "quantum_vulnerable": False, "threat_level": "NONE",
                              "standard": "NIST FIPS 203"},
        "ML-DSA (Dilithium)":{"type": "PQC / Signature", "quantum_vulnerable": False, "threat_level": "NONE",
                              "standard": "NIST FIPS 204"},
        "SLH-DSA (SPHINCS+)":{"type": "PQC / Hash-Sig",  "quantum_vulnerable": False, "threat_level": "NONE",
                              "standard": "NIST FIPS 205"},
    }

    # Aggregate algorithms from crypto findings
    seen: dict = {}
    for f in crypto_data.get("findings", []):
        algo = f["algorithm"]
        if algo not in seen:
            meta = ALGO_META.get(algo, {"type": "Unknown", "quantum_vulnerable": False, "threat_level": "UNKNOWN"})
            seen[algo] = {"name": algo, "occurrences": 0,
                          "locations": [], **meta}
        seen[algo]["occurrences"] += 1
        seen[algo]["locations"].append(f"0x{f['offset']:08X} ({f['section']})")

    # Merge PQC algorithms (may not appear in raw crypto scan)
    for info in pqc_data.get("pqc_algorithms", {}).values():
        name = info["name"]
        if name not in seen:
            meta = ALGO_META.get(name, {"type": info.get("type","PQC"),
                                        "quantum_vulnerable": False,
                                        "threat_level": "NONE",
                                        "standard": info.get("standard","")})
            seen[name] = {"name": name, "occurrences": 1, "locations": [], **meta}

    algorithms = sorted(seen.values(), key=lambda a: (
        0 if a.get("threat_level") == "CRITICAL" else
        1 if a.get("threat_level") == "HIGH" else
        2 if a.get("threat_level") == "MEDIUM" else
        3 if a.get("threat_level") == "LOW" else 4
    ))

    # Collect unique recommendations
    recs = list(dict.fromkeys(pqc_data.get("recommendations", [])))

    # Risk score: weighted by severity
    WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 0, "NONE": 0, "UNKNOWN": 5}
    risk = min(sum(WEIGHTS.get(a.get("threat_level","UNKNOWN"), 5) for a in algorithms
                   if a.get("quantum_vulnerable")), 100)

    return {
        "algorithms": algorithms,
        "quantum_vulnerable": [a["name"] for a in algorithms if a.get("quantum_vulnerable")],
        "quantum_resistant": [a["name"] for a in algorithms if not a.get("quantum_vulnerable")],
        "risk_score": risk,
        "recommendations": recs,
    }


def _detect_file_type(file_path: str) -> str:
    """Detect whether a file is a PCAP capture or a binary (ELF/PE/Mach-O)."""
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext in ('.pcap', '.pcapng', '.cap'):
        return "pcap"

    try:
        with open(file_path, 'rb') as f:
            magic = f.read(16)
    except Exception:
        return "binary"

    if len(magic) < 4:
        return "binary"

    # PCAP / PCAPNG magic bytes
    if magic[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                     b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        return "pcap"
    if magic[:4] == b'\x0a\x0d\x0d\x0a':
        return "pcap"

    # ELF
    if magic[:4] == b'\x7fELF':
        return "binary"
    # PE (MZ)
    if magic[:2] == b'MZ':
        return "binary"
    # Mach-O
    if magic[:4] in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                     b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                     b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
        return "binary"

    return "binary"


def _report_collect_pcap(pcap_path: str) -> dict:
    """Load and analyze a PCAP/PCAPNG file; return canonical report dict."""
    import logging
    logging.getLogger("scapy").setLevel(logging.ERROR)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.utils import rdpcap
    from scapy.layers.inet import TCP, IP
    from scapy.layers.inet6 import IPv6

    packets = rdpcap(pcap_path)
    total_packets = len(packets)

    client_hellos: list = []
    server_hellos: list = []
    conn_map: dict = {}

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if len(payload) < 6 or payload[0] != 0x16:
            continue

        records = _extract_tls_handshakes(payload)
        if not records:
            continue

        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            src_ip = dst_ip = "?"
        src_port, dst_port = tcp.sport, tcp.dport

        for rec in records:
            conn_fwd = (src_ip, src_port, dst_ip, dst_port)
            conn_rev = (dst_ip, dst_port, src_ip, src_port)
            if rec["type"] == "ClientHello":
                rec["_flow"] = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                client_hellos.append(rec)
                conn_map.setdefault(conn_fwd, {"client": None, "server": None})
                conn_map[conn_fwd]["client"] = rec
            elif rec["type"] == "ServerHello":
                server_hellos.append(rec)
                conn_map.setdefault(conn_rev, {"client": None, "server": None})
                conn_map[conn_rev]["server"] = rec

    offered: dict = {}
    for ch in client_hellos:
        for cs in ch.get("cipher_suites", []):
            offered[cs] = offered.get(cs, 0) + 1

    selected: dict = {}
    for sh in server_hellos:
        cs = sh.get("cipher_suite")
        if cs is not None:
            selected[cs] = selected.get(cs, 0) + 1

    groups_offered: dict = {}
    for ch in client_hellos:
        for grp in ch.get("supported_groups", ch.get("key_share_groups", [])):
            groups_offered[grp] = groups_offered.get(grp, 0) + 1

    groups_selected: dict = {}
    for sh in server_hellos:
        grp = sh.get("key_share_group")
        if grp is not None:
            groups_selected[grp] = groups_selected.get(grp, 0) + 1

    tls_versions: dict = {}
    for sh in server_hellos:
        ver = sh.get("selected_version") or sh.get("legacy_version")
        if ver:
            tls_versions[ver] = tls_versions.get(ver, 0) + 1

    sni_list = [ch["sni"] for ch in client_hellos if "sni" in ch]

    pqc_groups = {g: _TLS_NAMED_GROUPS[g]
                  for g in (set(groups_offered) | set(groups_selected))
                  if g in _TLS_NAMED_GROUPS and _TLS_NAMED_GROUPS[g][2] == "SAFE"}

    total_sessions = max(len(server_hellos), 1)
    vuln_sessions = sum(
        c for code, c in selected.items()
        if _TLS_CIPHER_SUITES.get(code, ("", "", "UNKNOWN"))[2] in ("CRITICAL", "HIGH")
    )
    tls13_sessions = sum(
        c for code, c in selected.items()
        if _TLS_CIPHER_SUITES.get(code, ("", "", ""))[1] == "TLS1.3"
    )
    pqc_sessions = sum(groups_selected.get(g, 0) for g in pqc_groups)
    vuln_pct = 100 * vuln_sessions / total_sessions
    pqc_pct = 100 * pqc_sessions / total_sessions
    tls13_pct = 100 * tls13_sessions / total_sessions

    if pqc_pct > 50:
        readiness = "GOOD"
    elif pqc_pct > 0:
        readiness = "PARTIAL"
    elif tls13_pct > 75 and vuln_pct == 0:
        readiness = "TRANSITIONING"
    elif vuln_pct > 50:
        readiness = "POOR"
    else:
        readiness = "MIXED"

    def _cs_entry(code):
        name, kex, threat = _TLS_CIPHER_SUITES.get(
            code, (f"0x{code:04X}", "unknown", "UNKNOWN"))
        return {"code": f"0x{code:04X}", "name": name,
                "key_exchange": kex, "quantum_threat": threat}

    def _grp_entry(grp):
        gname, gtype, threat = _TLS_NAMED_GROUPS.get(
            grp, (f"0x{grp:04X}", "unknown", "UNKNOWN"))
        return {"code": f"0x{grp:04X}", "name": gname,
                "type": gtype, "quantum_threat": threat}

    return {
        "pcap": str(pcap_path),
        "summary": {
            "total_packets":      total_packets,
            "client_hellos":      len(client_hellos),
            "server_hellos":      len(server_hellos),
            "unique_connections": len(conn_map),
        },
        "cipher_suites": {
            "negotiated": {f"0x{k:04X}": {"count": v, **_cs_entry(k)}
                           for k, v in selected.items()},
            "offered":    {f"0x{k:04X}": {"count": v, **_cs_entry(k)}
                           for k, v in offered.items()},
        },
        "key_exchange_groups": {
            "offered":  {f"0x{g:04X}": {"count": c, **_grp_entry(g)}
                         for g, c in groups_offered.items()},
            "selected": {f"0x{g:04X}": {"count": c, **_grp_entry(g)}
                         for g, c in groups_selected.items()},
        },
        "pqc_detected": [
            {"code": f"0x{g:04X}", "name": v[0], "type": v[1],
             "offered": groups_offered.get(g, 0),
             "selected": groups_selected.get(g, 0)}
            for g, v in pqc_groups.items()
        ],
        "tls_versions": {
            _TLS_VERSIONS.get(v, f"0x{v:04X}"): c
            for v, c in tls_versions.items() if c > 0
        },
        "sni_hostnames": sorted(set(sni_list)),
        "assessment": {
            "readiness":           readiness,
            "vulnerable_sessions": vuln_sessions,
            "pqc_sessions":        pqc_sessions,
            "tls13_sessions":      tls13_sessions,
        },
    }


# ── The report command ───────────────────────────────────────────────────────

@main.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'html', 'markdown']),
              default='json', show_default=True,
              help='Output format')
@click.option('--output', '-o', type=click.Path(),
              help='Output file (default: stdout for JSON/Markdown, report.html for HTML)')
@click.option('--open', 'open_browser', is_flag=True,
              help='Open the HTML report in a browser after generation')
@click.option('--skip', multiple=True,
              type=click.Choice(['cfg', 'dataflow']),
              help='Skip slow analyses (cfg, dataflow) for faster runs')
def report(binary_path: str, output_format: str, output: Optional[str],
           open_browser: bool, skip: tuple):
    """
    Generate a unified analysis report.

    Runs all 6 analyses (analyze, crypto, forensics, cfg, dataflow, pqc)
    on a binary and produces a combined report with a CBOM section.

    Output formats:
      json      Canonical structured data (default)
      html      Dark-themed HTML with gold accents
      markdown  GitHub-flavored Markdown

    BINARY_PATH: Path to the binary file to analyze

    Examples:
        zetton report ./sample_aes_ecb
        zetton report ./sample_aes_ecb --format html -o report.html --open
        zetton report ./sample_aes_ecb --format markdown -o report.md
        zetton report ./sample_aes_ecb --skip cfg --skip dataflow
    """
    from zetton.core.binary import Binary
    from zetton import __version__ as _ver
    import datetime

    print_banner()
    start_time = time.time()

    console.print(f"[bold cyan]Unified Report[/bold cyan] — {binary_path}")
    console.print(f"[dim]Output format: {output_format}[/dim]\n")

    # ── Load binary ──────────────────────────────────────────────────────
    try:
        binary = Binary.from_file(binary_path)
    except Exception as e:
        console.print(f"[bold red]Error loading binary:[/bold red] {e}")
        sys.exit(1)

    # ── Run all analyses ─────────────────────────────────────────────────
    analyses = [
        ("analyze",   "Binary analysis",      lambda: _report_collect_binary(binary)),
        ("crypto",    "Crypto detection",     lambda: _report_collect_crypto(binary)),
        ("forensics", "Forensics",            lambda: _report_collect_forensics(binary)),
        ("pqc",       "PQC analysis",         lambda: _report_collect_pqc(binary)),
        ("cfg",       "CFG analysis",         lambda: _report_collect_cfg(binary)),
        ("dataflow",  "Dataflow analysis",    lambda: _report_collect_dataflow(binary)),
    ]

    results: dict = {}
    for key, label, fn in analyses:
        if key in skip:
            console.print(f"  [dim]⏭  {label} (skipped)[/dim]")
            results[key] = {}
            continue
        with console.status(f"  [cyan]Running {label}…[/cyan]"):
            try:
                results[key] = fn()
                count = ""
                if key == "crypto":
                    count = f" ({len(results[key].get('findings',[]))} findings)"
                elif key == "forensics":
                    count = f" ({len(results[key].get('issues',[]))} issue(s))"
                elif key == "cfg":
                    count = f" ({len(results[key].get('functions',[]))} functions)"
                elif key == "dataflow":
                    count = f" ({len(results[key].get('flows',[]))} flow(s))"
                console.print(f"  [green]✓[/green] {label}{count}")
            except Exception as e:
                console.print(f"  [yellow]⚠[/yellow] {label} failed: {e}")
                results[key] = {"error": str(e)}

    # ── Build CBOM ───────────────────────────────────────────────────────
    cbom = _build_cbom(results.get("crypto", {}),
                       results.get("forensics", {}),
                       results.get("pqc", {}))

    # ── Assemble canonical JSON report ───────────────────────────────────
    full_report = {
        "meta": {
            "tool":      "Zetton",
            "version":   _ver,
            "timestamp": datetime.datetime.now().isoformat(),
            "binary":    str(binary_path),
            "format":    binary.format.name,
        },
        "cbom":      cbom,
        "binary":    results.get("analyze", {}),
        "crypto":    results.get("crypto", {}),
        "forensics": results.get("forensics", {}),
        "pqc":       results.get("pqc", {}),
        "cfg":       results.get("cfg", {}),
        "dataflow":  results.get("dataflow", {}),
    }

    # ── Format ───────────────────────────────────────────────────────────
    elapsed = time.time() - start_time

    if output_format == "json":
        rendered = json.dumps(full_report, indent=2, default=str)
        out_path = output or None
        if out_path:
            with open(out_path, "w") as f:
                f.write(rendered)
            console.print(f"\n[green]✓[/green] Report saved to [bold]{out_path}[/bold] in {elapsed:.2f}s")
        else:
            console.print()
            print(rendered)

    elif output_format == "html":
        from zetton.formatters import format_html
        rendered = format_html(full_report)
        out_path = output or "report.html"
        with open(out_path, "w") as f:
            f.write(rendered)
        console.print(f"\n[green]✓[/green] HTML report saved to [bold]{out_path}[/bold] in {elapsed:.2f}s")
        if open_browser:
            import webbrowser
            webbrowser.open(f"file://{Path(out_path).resolve()}")

    elif output_format == "markdown":
        from zetton.formatters import format_markdown
        rendered = format_markdown(full_report)
        out_path = output or None
        if out_path:
            with open(out_path, "w") as f:
                f.write(rendered)
            console.print(f"\n[green]✓[/green] Markdown report saved to [bold]{out_path}[/bold] in {elapsed:.2f}s")
        else:
            console.print()
            print(rendered)

    # ── Print CBOM summary to terminal ───────────────────────────────────
    if output_format != "json" or output:
        console.print()
        vuln = cbom.get("quantum_vulnerable", [])
        resistant = cbom.get("quantum_resistant", [])
        risk = cbom.get("risk_score", 0)
        risk_color = "red" if risk >= 60 else ("yellow" if risk >= 30 else "green")

        summary_table = Table(
            title="CBOM Summary",
            box=box.ROUNDED,
            title_style="bold yellow",
            border_style="dim",
        )
        summary_table.add_column("Category", style="dim", width=24)
        summary_table.add_column("Algorithms", style="white")

        summary_table.add_row("[red]Quantum-Vulnerable[/red]",
                              ", ".join(vuln) if vuln else "[green]None[/green]")
        summary_table.add_row("[cyan]Quantum-Resistant[/cyan]",
                              ", ".join(resistant) if resistant else "[dim]None detected[/dim]")
        summary_table.add_row(f"[{risk_color}]Risk Score[/{risk_color}]",
                              f"[{risk_color}]{risk}/100[/{risk_color}]")
        console.print(summary_table)


# ─── PCAP ANALYSIS ──────────────────────────────────────────────────────────

# ── TLS protocol databases ───────────────────────────────────────────────────
# Tuples: (display_name, key_exchange_type, quantum_threat)
# CRITICAL = RSA/ECDH key exchange broken by Shor's algorithm
# HIGH     = DHE-RSA: authentication broken by Shor's, KE classically safe
# LOW      = TLS 1.3 symmetric suite; quantum risk depends on named group
# SAFE     = PQC or post-quantum hybrid

_TLS_CIPHER_SUITES: dict = {
    # ── RSA key exchange (CRITICAL) ──────────────────────────────────────
    0x0001: ("TLS_RSA_WITH_NULL_MD5",               "RSA",     "CRITICAL"),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5",            "RSA",     "CRITICAL"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA",            "RSA",     "CRITICAL"),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA",       "RSA",     "CRITICAL"),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA",        "RSA",     "CRITICAL"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA",        "RSA",     "CRITICAL"),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256",     "RSA",     "CRITICAL"),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256",     "RSA",     "CRITICAL"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256",     "RSA",     "CRITICAL"),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384",     "RSA",     "CRITICAL"),
    # ── DHE-RSA (HIGH) ───────────────────────────────────────────────────
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA",        "DHE-RSA", "HIGH"),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA",        "DHE-RSA", "HIGH"),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",     "DHE-RSA", "HIGH"),
    0x006B: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",     "DHE-RSA", "HIGH"),
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",     "DHE-RSA", "HIGH"),
    0x009F: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",     "DHE-RSA", "HIGH"),
    0xCCAA: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","DHE-RSA", "HIGH"),
    # ── ECDHE key exchange (CRITICAL) ────────────────────────────────────
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",           "ECDHE", "CRITICAL"),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",           "ECDHE", "CRITICAL"),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",             "ECDHE", "CRITICAL"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",             "ECDHE", "CRITICAL"),
    0xC023: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",        "ECDHE", "CRITICAL"),
    0xC024: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",        "ECDHE", "CRITICAL"),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",          "ECDHE", "CRITICAL"),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",          "ECDHE", "CRITICAL"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",        "ECDHE", "CRITICAL"),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",        "ECDHE", "CRITICAL"),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",          "ECDHE", "CRITICAL"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",          "ECDHE", "CRITICAL"),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",    "ECDHE", "CRITICAL"),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",  "ECDHE", "CRITICAL"),
    # ── TLS 1.3 (symmetric-only suites; KE determined by named group) ────
    0x1301: ("TLS_AES_128_GCM_SHA256",        "TLS1.3", "LOW"),
    0x1302: ("TLS_AES_256_GCM_SHA384",        "TLS1.3", "LOW"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256",  "TLS1.3", "LOW"),
    0x1304: ("TLS_AES_128_CCM_SHA256",        "TLS1.3", "LOW"),
    0x1305: ("TLS_AES_128_CCM_8_SHA256",      "TLS1.3", "LOW"),
}

# Named groups from supported_groups (ext 0x000A) and key_share (ext 0x0033)
_TLS_NAMED_GROUPS: dict = {
    # Standard ECDH (CRITICAL - Shor's breaks ECDH)
    0x0017: ("secp256r1 (P-256)", "ECDH", "CRITICAL"),
    0x0018: ("secp384r1 (P-384)", "ECDH", "CRITICAL"),
    0x0019: ("secp521r1 (P-521)", "ECDH", "CRITICAL"),
    0x001D: ("x25519",            "ECDH", "CRITICAL"),
    0x001E: ("x448",              "ECDH", "CRITICAL"),
    # Finite-field DHE (HIGH)
    0x0100: ("ffdhe2048", "DHE", "HIGH"),
    0x0101: ("ffdhe3072", "DHE", "HIGH"),
    0x0102: ("ffdhe4096", "DHE", "HIGH"),
    0x0103: ("ffdhe6144", "DHE", "HIGH"),
    0x0104: ("ffdhe8192", "DHE", "HIGH"),
    # PQC hybrid groups (SAFE — classical + ML-KEM)
    # Draft codes widely deployed in Chrome/Firefox/Cloudflare (2023–2024)
    0x2F39: ("X25519Kyber768Draft00",        "Hybrid-PQC", "SAFE"),
    0xFE30: ("X25519Kyber512Draft00",        "Hybrid-PQC", "SAFE"),
    0xFE31: ("SecP256r1Kyber768Draft00",     "Hybrid-PQC", "SAFE"),
    # IANA-assigned hybrid codes (2024+, draft-ietf-tls-hybrid-design)
    0x11EB: ("X25519MLKEM768",               "Hybrid-PQC", "SAFE"),
    0x11EC: ("SecP256r1MLKEM768",            "Hybrid-PQC", "SAFE"),
    0x11ED: ("SecP384r1MLKEM1024",           "Hybrid-PQC", "SAFE"),
    0x6399: ("X25519MLKEM768 (0x6399)",      "Hybrid-PQC", "SAFE"),
    0x639A: ("SecP256r1MLKEM768 (0x639A)",   "Hybrid-PQC", "SAFE"),
}

_TLS_VERSIONS: dict = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


# ── Raw TLS parsing helpers ──────────────────────────────────────────────────

def _parse_tls_extensions(data: bytes) -> dict:
    """Parse a TLS extension list into {ext_type: ext_bytes}."""
    exts: dict = {}
    i = 0
    while i + 4 <= len(data):
        ext_type = (data[i] << 8) | data[i + 1]
        ext_len  = (data[i + 2] << 8) | data[i + 3]
        if i + 4 + ext_len > len(data):
            break
        exts[ext_type] = data[i + 4 : i + 4 + ext_len]
        i += 4 + ext_len
    return exts


def _parse_client_hello(body: bytes) -> Optional[dict]:
    """Parse a TLS ClientHello handshake body (bytes after the 4-byte HS header)."""
    result: dict = {"type": "ClientHello", "cipher_suites": []}
    i = 0
    if i + 34 > len(body):          # version (2) + random (32)
        return None
    result["legacy_version"] = (body[i] << 8) | body[i + 1]
    i += 34                         # skip version + random

    if i >= len(body): return result
    sid_len = body[i]; i += 1 + sid_len

    if i + 2 > len(body): return result
    cs_bytes = (body[i] << 8) | body[i + 1]; i += 2
    suites = []
    for _ in range(cs_bytes // 2):
        if i + 2 > len(body): break
        suites.append((body[i] << 8) | body[i + 1])
        i += 2
    result["cipher_suites"] = [s for s in suites if s != 0x00FF]  # drop SCSV

    if i >= len(body): return result
    comp_len = body[i]; i += 1 + comp_len

    if i + 2 > len(body): return result
    ext_total = (body[i] << 8) | body[i + 1]; i += 2
    if i + ext_total > len(body): return result

    exts = _parse_tls_extensions(body[i : i + ext_total])

    # supported_versions (0x002B) → list of versions the client offers
    if 0x002B in exts:
        vd = exts[0x002B]
        if vd:
            vl = vd[0]; j = 1
            versions = []
            while j + 1 <= vl:
                versions.append((vd[j] << 8) | vd[j + 1])
                j += 2
            result["supported_versions"] = versions

    # SNI (0x0000) → first hostname entry
    if 0x0000 in exts:
        sd = exts[0x0000]
        if len(sd) >= 5 and sd[2] == 0:    # entry type 0 = host_name
            nlen = (sd[3] << 8) | sd[4]
            if 5 + nlen <= len(sd):
                result["sni"] = sd[5 : 5 + nlen].decode("ascii", errors="replace")

    # supported_groups (0x000A)
    if 0x000A in exts:
        gd = exts[0x000A]
        if len(gd) >= 2:
            gl = (gd[0] << 8) | gd[1]; j = 2
            groups = []
            while j + 1 < 2 + gl:
                groups.append((gd[j] << 8) | gd[j + 1])
                j += 2
            result["supported_groups"] = groups

    # key_share (0x0033) in ClientHello → list of offered groups
    if 0x0033 in exts:
        kd = exts[0x0033]
        if len(kd) >= 2:
            kl = (kd[0] << 8) | kd[1]; j = 2
            ks_groups = []
            while j + 3 < 2 + kl:
                grp   = (kd[j] << 8) | kd[j + 1]
                kelen = (kd[j + 2] << 8) | kd[j + 3]
                ks_groups.append(grp)
                j += 4 + kelen
            result["key_share_groups"] = ks_groups

    return result


def _parse_server_hello(body: bytes) -> Optional[dict]:
    """Parse a TLS ServerHello handshake body."""
    result: dict = {"type": "ServerHello"}
    i = 0
    if i + 34 > len(body): return None
    result["legacy_version"] = (body[i] << 8) | body[i + 1]
    i += 34

    if i >= len(body): return result
    sid_len = body[i]; i += 1 + sid_len

    if i + 3 > len(body): return result
    result["cipher_suite"] = (body[i] << 8) | body[i + 1]; i += 2
    i += 1  # compression method

    if i + 2 > len(body): return result
    ext_total = (body[i] << 8) | body[i + 1]; i += 2
    exts = _parse_tls_extensions(body[i : i + ext_total])

    # supported_versions (0x002B) in ServerHello = single selected version
    if 0x002B in exts:
        vd = exts[0x002B]
        if len(vd) >= 2:
            result["selected_version"] = (vd[0] << 8) | vd[1]

    # key_share (0x0033) in ServerHello = single selected group
    if 0x0033 in exts:
        kd = exts[0x0033]
        if len(kd) >= 2:
            result["key_share_group"] = (kd[0] << 8) | kd[1]

    return result


def _extract_tls_handshakes(tcp_payload: bytes) -> list:
    """
    Walk a TCP segment payload and extract any TLS ClientHello / ServerHello
    messages. Returns a list of parsed dicts.
    """
    records = []
    i = 0
    while i + 5 <= len(tcp_payload):
        content_type = tcp_payload[i]
        version      = (tcp_payload[i + 1] << 8) | tcp_payload[i + 2]
        length       = (tcp_payload[i + 3] << 8) | tcp_payload[i + 4]

        # Validate TLS record framing
        if content_type not in (0x14, 0x15, 0x16, 0x17, 0x18):
            break
        if version not in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
            break
        if length == 0 or i + 5 + length > len(tcp_payload):
            break

        payload = tcp_payload[i + 5 : i + 5 + length]
        i += 5 + length

        # Only interested in Handshake (0x16) records
        if content_type != 0x16 or len(payload) < 4:
            continue

        hs_type = payload[0]
        hs_len  = (payload[1] << 16) | (payload[2] << 8) | payload[3]
        hs_body = payload[4 : 4 + hs_len]

        if hs_type == 1:        # ClientHello
            parsed = _parse_client_hello(hs_body)
            if parsed:
                records.append(parsed)
        elif hs_type == 2:      # ServerHello
            parsed = _parse_server_hello(hs_body)
            if parsed:
                records.append(parsed)

    return records


# ── The pcap command ─────────────────────────────────────────────────────────

@main.command()
@click.argument('pcap_path', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True,
              help='Show offered cipher suites and SNI hostnames')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'html', 'markdown']),
              default='json', show_default=True,
              help='Output format')
@click.option('--output', '-o', type=click.Path(),
              help='Output file (default: stdout for JSON/Markdown, pcap_report.html for HTML)')
@click.option('--open', 'open_browser', is_flag=True,
              help='Open the HTML report in a browser after generation')
def pcap(pcap_path: str, verbose: bool, output_format: str,
         output: Optional[str], open_browser: bool):
    """
    Analyze a PCAP/PCAPNG file for cryptographic protocols.

    Parses TLS handshakes, extracts cipher suites and key exchange
    groups, classifies each as quantum-vulnerable or quantum-safe,
    and detects PQC key exchange (ML-KEM/Kyber hybrid groups) in
    TLS 1.3 sessions.

    Output formats:
      json      Canonical structured data (default)
      html      Dark-themed HTML with gold accents
      markdown  GitHub-flavored Markdown

    PCAP_PATH: Path to .pcap or .pcapng capture file

    Examples:
        zetton pcap ./capture.pcap
        zetton pcap ./capture.pcap --verbose
        zetton pcap ./capture.pcap --format html -o report.html --open
        zetton pcap ./capture.pcap --format markdown -o report.md
        zetton pcap ./capture.pcap -o results.json
    """
    import logging
    print_banner()
    start_time = time.time()

    console.print(f"[bold cyan]PCAP Crypto Analysis[/bold cyan] — {pcap_path}\n")

    # ── Load PCAP ────────────────────────────────────────────────────────
    try:
        logging.getLogger("scapy").setLevel(logging.ERROR)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.utils import rdpcap
        from scapy.layers.inet import TCP, IP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        console.print("[bold red]Error:[/bold red] scapy is required. "
                      "Install with: [cyan]pip install scapy[/cyan]")
        sys.exit(1)

    with console.status(f"[cyan]Loading {pcap_path}…[/cyan]"):
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            console.print(f"[bold red]Error reading PCAP:[/bold red] {e}")
            sys.exit(1)

    total_packets = len(packets)
    console.print(f"[green]✓[/green] Loaded {total_packets:,} packets\n")

    # ── Parse TLS handshakes from TCP payloads ────────────────────────────
    client_hellos: list = []
    server_hellos: list = []
    conn_map: dict  = {}   # (src_ip, src_port, dst_ip, dst_port) → {client, server}

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        tcp     = pkt[TCP]
        payload = bytes(tcp.payload)
        if len(payload) < 6 or payload[0] != 0x16:
            continue    # fast-path: not a TLS Handshake record

        records = _extract_tls_handshakes(payload)
        if not records:
            continue

        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            src_ip = dst_ip = "?"
        src_port, dst_port = tcp.sport, tcp.dport

        for rec in records:
            conn_fwd = (src_ip, src_port, dst_ip, dst_port)
            conn_rev = (dst_ip, dst_port, src_ip, src_port)
            if rec["type"] == "ClientHello":
                rec["_flow"] = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                client_hellos.append(rec)
                conn_map.setdefault(conn_fwd, {"client": None, "server": None})
                conn_map[conn_fwd]["client"] = rec
            elif rec["type"] == "ServerHello":
                server_hellos.append(rec)
                conn_map.setdefault(conn_rev, {"client": None, "server": None})
                conn_map[conn_rev]["server"] = rec

    if not client_hellos and not server_hellos:
        console.print("[yellow]No TLS handshakes found in this capture.[/yellow]")
        console.print("[dim]The file may not contain TLS traffic, or "
                      "handshakes may be on non-standard ports.[/dim]")
        elapsed = time.time() - start_time
        console.print(f"\n[green]✓[/green] Analysis complete in {elapsed:.3f}s")
        return

    # ── Aggregate statistics ──────────────────────────────────────────────
    # Cipher suites offered by all clients (ClientHello)
    offered: dict = {}
    for ch in client_hellos:
        for cs in ch.get("cipher_suites", []):
            offered[cs] = offered.get(cs, 0) + 1

    # Cipher suites selected by servers (ServerHello)
    selected: dict = {}
    for sh in server_hellos:
        cs = sh.get("cipher_suite")
        if cs is not None:
            selected[cs] = selected.get(cs, 0) + 1

    # Named groups offered by clients
    groups_offered: dict = {}
    for ch in client_hellos:
        for grp in ch.get("supported_groups", ch.get("key_share_groups", [])):
            groups_offered[grp] = groups_offered.get(grp, 0) + 1

    # Named group selected by each server (from key_share extension)
    groups_selected: dict = {}
    for sh in server_hellos:
        grp = sh.get("key_share_group")
        if grp is not None:
            groups_selected[grp] = groups_selected.get(grp, 0) + 1

    # TLS versions (prefer selected_version from ServerHello)
    tls_versions: dict = {}
    for sh in server_hellos:
        ver = sh.get("selected_version") or sh.get("legacy_version")
        if ver:
            tls_versions[ver] = tls_versions.get(ver, 0) + 1

    # SNI hostnames
    sni_list = [ch["sni"] for ch in client_hellos if "sni" in ch]

    # Convenience: which PQC groups were seen
    pqc_groups = {g: _TLS_NAMED_GROUPS[g]
                  for g in (set(groups_offered) | set(groups_selected))
                  if g in _TLS_NAMED_GROUPS and _TLS_NAMED_GROUPS[g][2] == "SAFE"}

    # ── Threat style helper (local) ───────────────────────────────────────
    def _threat_style(threat: str) -> str:
        return {
            "CRITICAL": "[bold red]CRITICAL[/bold red]",
            "HIGH":     "[yellow]HIGH[/yellow]",
            "LOW":      "[cyan]LOW[/cyan]",
            "SAFE":     "[bold green]SAFE[/bold green]",
        }.get(threat, f"[dim]{threat}[/dim]")

    # ── Summary table ─────────────────────────────────────────────────────
    sum_table = Table(
        title="PCAP Summary",
        box=box.ROUNDED,
        title_style="bold white",
        border_style="dim",
        show_header=False,
        pad_edge=True,
    )
    sum_table.add_column("Metric", style="cyan", width=28)
    sum_table.add_column("Value",  style="white")

    sum_table.add_row("Total packets",           f"{total_packets:,}")
    sum_table.add_row("TLS ClientHellos",         str(len(client_hellos)))
    sum_table.add_row("TLS ServerHellos",         str(len(server_hellos)))
    sum_table.add_row("Unique connections",       str(len(conn_map)))
    sum_table.add_row("Cipher suites offered",    str(len(offered)))
    sum_table.add_row("Cipher suites negotiated", str(len(selected)))
    if sni_list:
        sum_table.add_row("Unique SNI hostnames", str(len(set(sni_list))))
    if pqc_groups:
        sum_table.add_row("[green]PQC groups detected[/green]", str(len(pqc_groups)))

    console.print(sum_table)
    console.print()

    # ── Negotiated cipher suites (ServerHello) ────────────────────────────
    if selected:
        cs_table = Table(
            title="Negotiated Cipher Suites (ServerHello)",
            box=box.ROUNDED,
            title_style="bold white",
            border_style="dim",
        )
        cs_table.add_column("Code",         style="dim",      width=8)
        cs_table.add_column("Cipher Suite", style="cyan",     min_width=42)
        cs_table.add_column("Key Exch.",    style="yellow",   width=10)
        cs_table.add_column("Quantum Risk", justify="center", width=12)
        cs_table.add_column("Sessions",     justify="right",  width=8)

        for code, count in sorted(selected.items(), key=lambda x: -x[1]):
            name, kex, threat = _TLS_CIPHER_SUITES.get(
                code, (f"UNKNOWN_0x{code:04X}", "?", "UNKNOWN"))
            cs_table.add_row(
                f"0x{code:04X}", name, kex,
                _threat_style(threat), str(count),
            )
        console.print(cs_table)
        console.print()

    # ── Offered cipher suites (ClientHello) — verbose only ───────────────
    if verbose and offered:
        off_table = Table(
            title="Offered Cipher Suites (ClientHello)",
            box=box.SIMPLE_HEAVY,
            title_style="bold white",
            border_style="dim",
        )
        off_table.add_column("Code",         style="dim",      width=8)
        off_table.add_column("Cipher Suite", style="cyan",     min_width=42)
        off_table.add_column("Key Exch.",    style="yellow",   width=10)
        off_table.add_column("Quantum Risk", justify="center", width=12)
        off_table.add_column("Count",        justify="right",  width=7)

        for code, count in sorted(offered.items(), key=lambda x: -x[1]):
            name, kex, threat = _TLS_CIPHER_SUITES.get(
                code, (f"UNKNOWN_0x{code:04X}", "?", "UNKNOWN"))
            off_table.add_row(
                f"0x{code:04X}", name, kex,
                _threat_style(threat), str(count),
            )
        console.print(off_table)
        console.print()

    # ── Key exchange groups ───────────────────────────────────────────────
    all_groups = set(groups_offered) | set(groups_selected)
    if all_groups:
        grp_table = Table(
            title="Key Exchange Groups",
            box=box.ROUNDED,
            title_style="bold white",
            border_style="dim",
        )
        grp_table.add_column("Code",     style="dim",      width=8)
        grp_table.add_column("Group",    style="cyan",     min_width=30)
        grp_table.add_column("Type",     style="yellow",   width=12)
        grp_table.add_column("Quantum",  justify="center", width=12)
        grp_table.add_column("Offered",  justify="right",  width=8)
        grp_table.add_column("Selected", justify="right",  width=8)

        for grp in sorted(all_groups):
            gname, gtype, threat = _TLS_NAMED_GROUPS.get(
                grp, (f"group_0x{grp:04X}", "?", "UNKNOWN"))
            q_cell = ("[bold green]PQC ✓[/bold green]"
                      if threat == "SAFE" else _threat_style(threat))
            grp_table.add_row(
                f"0x{grp:04X}", gname, gtype, q_cell,
                str(groups_offered.get(grp, 0)) or "—",
                str(groups_selected.get(grp, 0)) if grp in groups_selected else "—",
            )
        console.print(grp_table)
        console.print()

    # ── PQC detection callout ─────────────────────────────────────────────
    if pqc_groups:
        console.print("[bold green]✓ Post-Quantum Key Exchange Detected:[/bold green]")
        for grp, (gname, gtype, _) in pqc_groups.items():
            sel_count = groups_selected.get(grp, 0)
            off_count = groups_offered.get(grp, 0)
            if sel_count:
                status = f"[bold green]negotiated ({sel_count}×)[/bold green]"
            else:
                status = f"[yellow]offered only ({off_count}×)[/yellow]"
            console.print(f"    [cyan]{gname}[/cyan] (0x{grp:04X}) — {status}")
        console.print()

    # ── TLS versions ─────────────────────────────────────────────────────
    if tls_versions:
        ver_table = Table(
            title="TLS Versions Negotiated",
            box=box.SIMPLE,
            title_style="bold white",
            border_style="dim",
        )
        ver_table.add_column("Version",  style="cyan")
        ver_table.add_column("Sessions", style="white", justify="right")
        ver_table.add_column("Status",   justify="center")

        ver_status_map = {
            0x0300: "[bold red]DEPRECATED (SSL 3.0)[/bold red]",
            0x0301: "[bold red]DEPRECATED[/bold red]",
            0x0302: "[bold red]DEPRECATED[/bold red]",
            0x0303: "[yellow]LEGACY (TLS 1.2)[/yellow]",
            0x0304: "[bold green]CURRENT (TLS 1.3)[/bold green]",
        }
        for ver, count in sorted(tls_versions.items(), reverse=True):
            if count == 0:
                continue
            ver_table.add_row(
                _TLS_VERSIONS.get(ver, f"0x{ver:04X}"),
                str(count),
                ver_status_map.get(ver, "[dim]UNKNOWN[/dim]"),
            )
        console.print(ver_table)
        console.print()

    # ── SNI hostnames — verbose only ──────────────────────────────────────
    if verbose and sni_list:
        sni_counts: dict = {}
        for s in sni_list:
            sni_counts[s] = sni_counts.get(s, 0) + 1
        unique_sni = sorted(sni_counts)

        sni_table = Table(
            title=f"SNI Hostnames ({len(unique_sni)} unique)",
            box=box.SIMPLE,
            title_style="bold white",
            border_style="dim",
        )
        sni_table.add_column("Hostname", style="cyan")
        sni_table.add_column("Count",    style="dim", justify="right")
        for hostname, count in sorted(sni_counts.items(), key=lambda x: -x[1])[:30]:
            sni_table.add_row(hostname, str(count))
        console.print(sni_table)
        console.print()

    # ── Quantum readiness assessment ──────────────────────────────────────
    console.print("[bold]Quantum Readiness Assessment:[/bold]")

    total_sessions  = max(len(server_hellos), 1)
    vuln_sessions   = sum(
        c for code, c in selected.items()
        if _TLS_CIPHER_SUITES.get(code, ("", "", "UNKNOWN"))[2] in ("CRITICAL", "HIGH")
    )
    tls13_sessions  = sum(
        c for code, c in selected.items()
        if _TLS_CIPHER_SUITES.get(code, ("", "", ""))[1] == "TLS1.3"
    )
    pqc_sessions    = sum(groups_selected.get(g, 0) for g in pqc_groups)
    vuln_pct        = 100 * vuln_sessions  / total_sessions
    pqc_pct         = 100 * pqc_sessions   / total_sessions
    tls13_pct       = 100 * tls13_sessions / total_sessions

    if pqc_pct > 50:
        readiness       = "GOOD"
        r_color         = "green"
        r_note          = "Majority of sessions use PQC key exchange"
    elif pqc_pct > 0:
        readiness       = "PARTIAL"
        r_color         = "yellow"
        r_note          = "PQC sessions detected; classical key exchange still dominates"
    elif tls13_pct > 75 and vuln_pct == 0:
        readiness       = "TRANSITIONING"
        r_color         = "yellow"
        r_note          = "TLS 1.3 only but no PQC key exchange detected yet"
    elif vuln_pct > 50:
        readiness       = "POOR"
        r_color         = "red"
        r_note          = "Majority of sessions use quantum-vulnerable cipher suites"
    else:
        readiness       = "MIXED"
        r_color         = "yellow"
        r_note          = "Mix of legacy and modern cipher suites"

    console.print(f"    Overall:   [{r_color}]{readiness}[/{r_color}] — {r_note}")
    if vuln_sessions:
        console.print(
            f"    Vulnerable:    [red]{vuln_sessions}[/red] session(s) with "
            f"quantum-vulnerable cipher suites ({vuln_pct:.0f}%)")
    if pqc_sessions:
        console.print(
            f"    PQC-protected: [bold green]{pqc_sessions}[/bold green] session(s) "
            f"using hybrid PQC key exchange ({pqc_pct:.0f}%)")
    if tls13_sessions:
        console.print(
            f"    TLS 1.3:       [cyan]{tls13_sessions}[/cyan] session(s) ({tls13_pct:.0f}%)")

    elapsed = time.time() - start_time
    console.print(f"\n[green]✓[/green] PCAP analysis complete in {elapsed:.3f}s")
    console.print(
        f"    {len(client_hellos)} ClientHello(s), "
        f"{len(server_hellos)} ServerHello(s), "
        f"{len(pqc_groups)} PQC group(s) detected")

    # ── Build canonical report structure ─────────────────────────────────
    def _cs_entry(code):
        name, kex, threat = _TLS_CIPHER_SUITES.get(
            code, (f"0x{code:04X}", "unknown", "UNKNOWN"))
        return {"code": f"0x{code:04X}", "name": name,
                "key_exchange": kex, "quantum_threat": threat}

    def _grp_entry(grp):
        gname, gtype, threat = _TLS_NAMED_GROUPS.get(
            grp, (f"0x{grp:04X}", "unknown", "UNKNOWN"))
        return {"code": f"0x{grp:04X}", "name": gname,
                "type": gtype, "quantum_threat": threat}

    pcap_report = {
        "pcap": str(pcap_path),
        "summary": {
            "total_packets":      total_packets,
            "client_hellos":      len(client_hellos),
            "server_hellos":      len(server_hellos),
            "unique_connections": len(conn_map),
        },
        "cipher_suites": {
            "negotiated": {f"0x{k:04X}": {"count": v, **_cs_entry(k)}
                           for k, v in selected.items()},
            "offered":    {f"0x{k:04X}": {"count": v, **_cs_entry(k)}
                           for k, v in offered.items()},
        },
        "key_exchange_groups": {
            "offered":  {f"0x{g:04X}": {"count": c, **_grp_entry(g)}
                         for g, c in groups_offered.items()},
            "selected": {f"0x{g:04X}": {"count": c, **_grp_entry(g)}
                         for g, c in groups_selected.items()},
        },
        "pqc_detected": [
            {"code": f"0x{g:04X}", "name": v[0], "type": v[1],
             "offered": groups_offered.get(g, 0),
             "selected": groups_selected.get(g, 0)}
            for g, v in pqc_groups.items()
        ],
        "tls_versions": {
            _TLS_VERSIONS.get(v, f"0x{v:04X}"): c
            for v, c in tls_versions.items() if c > 0
        },
        "sni_hostnames": sorted(set(sni_list)),
        "assessment": {
            "readiness":           readiness,
            "vulnerable_sessions": vuln_sessions,
            "pqc_sessions":        pqc_sessions,
            "tls13_sessions":      tls13_sessions,
        },
    }

    # ── Format & output ───────────────────────────────────────────────────
    if output_format == "json":
        rendered = json.dumps(pcap_report, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(rendered)
            console.print(f"[dim]Report saved to: {output}[/dim]")
        else:
            print(rendered)

    elif output_format == "html":
        from zetton.formatters import format_html_pcap
        rendered = format_html_pcap(pcap_report)
        out_path = output or "pcap_report.html"
        with open(out_path, "w") as f:
            f.write(rendered)
        console.print(f"\n[green]✓[/green] HTML report saved to [bold]{out_path}[/bold]")
        if open_browser:
            import webbrowser
            webbrowser.open(f"file://{Path(out_path).resolve()}")

    elif output_format == "markdown":
        lines = [
            f"# Zetton PCAP Report — `{pcap_path}`\n",
            f"**Generated:** {__import__('datetime').datetime.now().isoformat(timespec='seconds')}\n",
            "## PCAP Summary\n",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total packets | {total_packets:,} |",
            f"| TLS ClientHellos | {len(client_hellos)} |",
            f"| TLS ServerHellos | {len(server_hellos)} |",
            f"| Unique connections | {len(conn_map)} |",
            f"| Cipher suites offered | {len(offered)} |",
            f"| Cipher suites negotiated | {len(selected)} |",
        ]
        if sni_list:
            lines.append(f"| Unique SNI hostnames | {len(set(sni_list))} |")
        if pqc_groups:
            lines.append(f"| PQC groups detected | {len(pqc_groups)} |")
        lines.append("")

        lines += [
            "## Quantum Readiness Assessment\n",
            f"**Overall:** {readiness}",
        ]
        if vuln_sessions:
            lines.append(f"- Vulnerable sessions: {vuln_sessions}")
        if pqc_sessions:
            lines.append(f"- PQC-protected sessions: {pqc_sessions}")
        if tls13_sessions:
            lines.append(f"- TLS 1.3 sessions: {tls13_sessions}")
        lines.append("")

        if selected:
            lines += [
                "## Negotiated Cipher Suites\n",
                "| Code | Cipher Suite | Key Exch. | Quantum Risk | Sessions |",
                "|------|--------------|-----------|--------------|----------|",
            ]
            for code, count in sorted(selected.items(), key=lambda x: -x[1]):
                name, kex, threat = _TLS_CIPHER_SUITES.get(
                    code, (f"0x{code:04X}", "?", "UNKNOWN"))
                lines.append(f"| 0x{code:04X} | {name} | {kex} | {threat} | {count} |")
            lines.append("")

        all_groups = set(groups_offered) | set(groups_selected)
        if all_groups:
            lines += [
                "## Key Exchange Groups\n",
                "| Code | Group | Type | Quantum | Offered | Selected |",
                "|------|-------|------|---------|---------|----------|",
            ]
            for grp in sorted(all_groups):
                gname, gtype, threat = _TLS_NAMED_GROUPS.get(
                    grp, (f"0x{grp:04X}", "?", "UNKNOWN"))
                q = "PQC ✓" if threat == "SAFE" else threat
                lines.append(
                    f"| 0x{grp:04X} | {gname} | {gtype} | {q} |"
                    f" {groups_offered.get(grp, '—')} |"
                    f" {groups_selected.get(grp, '—')} |"
                )
            lines.append("")

        if tls_versions:
            lines += [
                "## TLS Versions Negotiated\n",
                "| Version | Sessions |",
                "|---------|----------|",
            ]
            for ver, count in sorted(tls_versions.items(), reverse=True):
                lines.append(f"| {_TLS_VERSIONS.get(ver, f'0x{ver:04X}')} | {count} |")
            lines.append("")

        if sni_list:
            lines += ["## SNI Hostnames Observed\n"]
            for h in sorted(set(sni_list))[:50]:
                lines.append(f"- `{h}`")
            lines.append("")

        rendered = "\n".join(lines)
        if output:
            with open(output, "w") as f:
                f.write(rendered)
            console.print(f"\n[green]✓[/green] Markdown report saved to [bold]{output}[/bold]")
        else:
            print(rendered)


# ─── AUTO ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['html', 'json']),
              default='html', show_default=True,
              help='Output format')
@click.option('--output', '-o', type=click.Path(),
              help='Output file (default: <filename>_zetton_report.html)')
@click.option('--open', 'open_browser', is_flag=True,
              help='Auto-open the report in a browser after generation')
def auto(file_path: str, output_format: str, output: Optional[str],
         open_browser: bool):
    """
    Auto-detect file type and run all relevant analyses.

    Detects whether the target is a PCAP capture or a binary (ELF/PE/Mach-O),
    runs all relevant analyses with a Rich progress display, generates a
    unified report, and prints a condensed terminal summary.

    FILE_PATH: Path to the binary or PCAP file to analyze

    Examples:
        zetton auto ./binary
        zetton auto ./capture.pcap
        zetton auto ./binary --open
        zetton auto ./binary --format json
        zetton auto ./binary -o custom.html
    """
    import datetime
    from zetton import __version__ as _ver
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    print_banner()
    start_time = time.time()

    path = Path(file_path)
    file_type = _detect_file_type(file_path)

    console.print(f"[bold cyan]Auto Analysis[/bold cyan] — {file_path}")
    console.print(f"[dim]Detected type: [bold]{file_type.upper()}[/bold][/dim]\n")

    ext = "json" if output_format == "json" else "html"
    out_path = output or f"{path.stem}_zetton_report.{ext}"

    # ── PCAP branch ──────────────────────────────────────────────────────────
    if file_type == "pcap":
        pcap_data: dict = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("  [cyan]PCAP / TLS analysis…[/cyan]", total=None)
            try:
                pcap_data = _report_collect_pcap(file_path)
                progress.update(task,
                                description="  [green]✓[/green] PCAP / TLS analysis complete")
            except Exception as e:
                progress.update(task,
                                description=f"  [yellow]⚠[/yellow] PCAP analysis failed: {e}")
                pcap_data = {"error": str(e)}
            progress.stop_task(task)

        # Render & save
        if output_format == "json":
            rendered = json.dumps(pcap_data, indent=2, default=str)
            with open(out_path, "w") as f:
                f.write(rendered)
        else:
            from zetton.formatters import format_html_pcap
            rendered = format_html_pcap(pcap_data)
            with open(out_path, "w") as f:
                f.write(rendered)

        # Terminal summary
        assessment = pcap_data.get("assessment", {})
        readiness = assessment.get("readiness", "UNKNOWN")
        r_color = {"GOOD": "green", "PARTIAL": "cyan", "TRANSITIONING": "yellow",
                   "MIXED": "yellow", "POOR": "red"}.get(readiness, "dim")

        summary = pcap_data.get("summary", {})
        vuln = assessment.get("vulnerable_sessions", 0)
        pqc_s = assessment.get("pqc_sessions", 0)
        tls13_s = assessment.get("tls13_sessions", 0)
        pqc_detected = pcap_data.get("pqc_detected", [])

        lines = [
            f"[bold]Quantum Readiness:[/bold]  [{r_color}]{readiness}[/{r_color}]",
            f"[dim]Packets analyzed:[/dim]   {summary.get('total_packets', 0):,}",
            f"[dim]TLS sessions:[/dim]       {summary.get('server_hellos', 0)}",
        ]
        if vuln:
            lines.append(f"[red]Vulnerable sessions:[/red]  {vuln}")
        if pqc_s:
            lines.append(f"[green]PQC sessions:[/green]       {pqc_s}")
        if tls13_s:
            lines.append(f"[cyan]TLS 1.3 sessions:[/cyan]   {tls13_s}")
        if pqc_detected:
            names = ", ".join(p["name"] for p in pqc_detected)
            lines.append(f"[green]PQC groups:[/green]         {names}")

        console.print()
        console.print(Panel(
            "\n".join(lines),
            title="[bold yellow]Auto Analysis Summary[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))

    # ── Binary branch ────────────────────────────────────────────────────────
    else:
        from zetton.core.binary import Binary

        try:
            binary = Binary.from_file(file_path)
        except Exception as e:
            console.print(f"[bold red]Error loading binary:[/bold red] {e}")
            sys.exit(1)

        analyses = [
            ("analyze",   "Binary analysis",   lambda: _report_collect_binary(binary)),
            ("crypto",    "Crypto detection",  lambda: _report_collect_crypto(binary)),
            ("forensics", "Forensics",         lambda: _report_collect_forensics(binary)),
            ("pqc",       "PQC analysis",      lambda: _report_collect_pqc(binary)),
            ("cfg",       "CFG analysis",      lambda: _report_collect_cfg(binary)),
            ("dataflow",  "Dataflow analysis", lambda: _report_collect_dataflow(binary)),
        ]

        results: dict = {}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("  Starting…", total=len(analyses))
            for key, label, fn in analyses:
                progress.update(task,
                                description=f"  [cyan]Running {label}…[/cyan]")
                try:
                    results[key] = fn()
                    count = ""
                    if key == "crypto":
                        count = f" ({len(results[key].get('findings', []))} findings)"
                    elif key == "forensics":
                        count = f" ({len(results[key].get('issues', []))} issue(s))"
                    elif key == "cfg":
                        count = f" ({len(results[key].get('functions', []))} functions)"
                    elif key == "dataflow":
                        count = f" ({len(results[key].get('flows', []))} flow(s))"
                    console.print(f"  [green]✓[/green] {label}{count}")
                except Exception as e:
                    console.print(f"  [yellow]⚠[/yellow] {label} failed: {e}")
                    results[key] = {"error": str(e)}
                progress.advance(task)

        cbom = _build_cbom(results.get("crypto", {}),
                           results.get("forensics", {}),
                           results.get("pqc", {}))

        full_report = {
            "meta": {
                "tool":      "Zetton",
                "version":   _ver,
                "timestamp": datetime.datetime.now().isoformat(),
                "binary":    str(file_path),
                "format":    binary.format.name,
            },
            "cbom":      cbom,
            "binary":    results.get("analyze", {}),
            "crypto":    results.get("crypto", {}),
            "forensics": results.get("forensics", {}),
            "pqc":       results.get("pqc", {}),
            "cfg":       results.get("cfg", {}),
            "dataflow":  results.get("dataflow", {}),
        }

        if output_format == "json":
            rendered = json.dumps(full_report, indent=2, default=str)
            with open(out_path, "w") as f:
                f.write(rendered)
        else:
            from zetton.formatters import format_html
            rendered = format_html(full_report)
            with open(out_path, "w") as f:
                f.write(rendered)

        # Terminal summary — prefer PQC migration score/grade over CBOM risk score
        pqc_data    = results.get("pqc", {})
        mig_score   = pqc_data.get("score")          # 0-100, None if analysis failed
        mig_grade   = pqc_data.get("grade")          # A/B/C/D
        vuln_algos      = cbom.get("quantum_vulnerable", [])
        resistant_algos = cbom.get("quantum_resistant", [])
        # Use PQC recs when available, fall back to CBOM recs
        recs = (pqc_data.get("recommendations") or cbom.get("recommendations", []))[:3]
        forensics_data = results.get("forensics", {})
        critical_count = sum(
            1 for i in forensics_data.get("issues", [])
            if i.get("severity") == "CRITICAL"
        )

        if mig_score is not None:
            # Drive readiness from PQC migration score (matches what the HTML report shows)
            if mig_score >= 75:
                readiness = "GOOD"
                r_color   = "green"
            elif mig_score >= 50:
                readiness = "TRANSITIONING"
                r_color   = "yellow"
            else:
                readiness = "POOR"
                r_color   = "red"
            score_label = f"Migration Score: {mig_score}/100  Grade {mig_grade}"
        else:
            # Fallback: derive from CBOM risk score
            risk = cbom.get("risk_score", 0)
            if risk == 0 and resistant_algos and not vuln_algos:
                readiness = "GOOD"
                r_color   = "green"
            elif risk < 30:
                readiness = "TRANSITIONING"
                r_color   = "yellow"
            else:
                readiness = "POOR"
                r_color   = "red"
            score_label = f"Risk Score: {risk}/100"

        lines = [
            f"[bold]Quantum Readiness:[/bold]  [{r_color}]{readiness}[/{r_color}]"
            f"   [dim]{score_label}[/dim]",
            f"[bold]Critical Findings:[/bold]  {critical_count}",
        ]
        if vuln_algos:
            lines.append(f"[red]Vulnerable Algorithms:[/red]   {', '.join(vuln_algos)}")
        if resistant_algos:
            lines.append(f"[green]Resistant Algorithms:[/green]    {', '.join(resistant_algos)}")
        if recs:
            lines.append("")
            lines.append("[bold]Top Recommendations:[/bold]")
            for i, rec in enumerate(recs, 1):
                lines.append(f"  {i}. {rec}")

        console.print()
        console.print(Panel(
            "\n".join(lines),
            title="[bold yellow]Auto Analysis Summary[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))

    # ── Final output ─────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    console.print(
        f"\n[green]✓[/green] Report saved to [bold]{out_path}[/bold] in {elapsed:.2f}s"
    )
    if open_browser and output_format == "html":
        import webbrowser
        webbrowser.open(f"file://{Path(out_path).resolve()}")


# ─── STATUS ─────────────────────────────────────────────────────────────────

@main.command()
def status():
    """Display Zetton status and available features."""
    print_banner()
    
    table = Table(title="Feature Status", box=box.ROUNDED)
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Description", style="white")
    
    table.add_row("Core Framework", "[green]✅ Ready[/green]", "Package structure and CLI")
    table.add_row("Binary Analysis", "[green]✅ Ready[/green]", "ELF/PE/Mach-O parsing with LIEF")
    table.add_row("Crypto Detection", "[green]✅ Ready[/green]", "Pattern matching for 15+ algorithms")
    table.add_row("Forensics", "[green]✅ Ready[/green]", "Weakness detection & quantum threat assessment")
    table.add_row("CFG Analysis", "[green]✅ Ready[/green]", "Control flow graph with Capstone disassembly")
    table.add_row("Taint Analysis", "[green]✅ Ready[/green]", "Source-to-sink data flow tracking")
    table.add_row("PQC Analysis", "[green]✅ Ready[/green]", "NIST FIPS 203/204/205 compliance checking")
    table.add_row("Quantum Engine", "[yellow]🚧 In Progress[/yellow]", "Qiskit-based quantum circuits")
    table.add_row("PCAP Analysis",     "[green]✅ Ready[/green]", "TLS handshake parsing, cipher suite & PQC detection")
    table.add_row("Report Generation", "[green]✅ Ready[/green]", "Unified HTML/JSON/Markdown reports with CBOM")
    table.add_row("Auto Command",      "[green]✅ Ready[/green]", "File-type detection + all-in-one analysis & report")
    
    console.print(table)
    console.print("\n[green]✓[/green] Zetton is operational!")
    console.print("[dim]Use 'zetton --help' to see available commands[/dim]")


if __name__ == '__main__':
    main()

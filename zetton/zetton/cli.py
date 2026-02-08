"""
Command-line interface for Zetton.

Provides commands for binary analysis, crypto identification,
and forensics reporting.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="Zetton")
def main():
    """
    Zetton - Quantum-Assisted Binary Analysis Framework
    
    A next-generation reverse engineering tool leveraging quantum
    computing for enhanced binary analysis and digital forensics.
    """
    pass


@main.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.option("--quantum/--no-quantum", default=True, help="Enable quantum-assisted analysis")
def analyze(binary_path: str, output: str | None, format: str, quantum: bool):
    """
    Perform comprehensive analysis on a binary.
    
    Analyzes the binary structure, disassembles code sections,
    and identifies cryptographic implementations.
    """
    from zetton import Zetton
    
    console.print(Panel.fit(
        f"[bold blue]Zetton[/bold blue] - Analyzing [green]{binary_path}[/green]",
        border_style="blue"
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading binary...", total=None)
        
        z = Zetton(binary_path)
        
        progress.update(task, description="Analyzing binary structure...")
        info = z.binary.info()
        
        progress.update(task, description="Running analysis...")
        results = z.analyze(quantum_enabled=quantum)
        
        progress.update(task, description="Analysis complete!")
    
    if format == "json":
        output_data = {
            "binary_info": info,
            "crypto_findings": [
                {
                    "algorithm": f.algorithm,
                    "confidence": f.confidence,
                    "offset": f.offset,
                    "section": f.section,
                }
                for f in results.get("crypto", [])
            ],
        }
        
        if output:
            Path(output).write_text(json.dumps(output_data, indent=2))
            console.print(f"Results written to [green]{output}[/green]")
        else:
            console.print_json(data=output_data)
    else:
        # Text output
        _print_binary_info(info)
        _print_crypto_findings(results.get("crypto", []))
        
        if output:
            with open(output, "w") as f:
                f.write(f"Zetton Analysis Report\n")
                f.write(f"Binary: {binary_path}\n\n")
                f.write(json.dumps(info, indent=2))
            console.print(f"Results written to [green]{output}[/green]")


@main.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--quantum/--no-quantum", default=True, help="Use quantum-assisted search")
@click.option("--pattern", "-p", help="Specific pattern type to search for")
def crypto(binary_path: str, quantum: bool, pattern: str | None):
    """
    Identify cryptographic implementations in a binary.
    
    Searches for crypto constants, imports, and high-entropy regions
    to detect encryption algorithms.
    """
    from zetton.core.binary import Binary
    from zetton.crypto.identify import CryptoIdentifier
    from zetton.quantum.engine import QuantumEngine
    
    console.print(Panel.fit(
        "[bold blue]Zetton[/bold blue] - Cryptographic Analysis",
        border_style="blue"
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading binary...", total=None)
        
        binary = Binary.from_file(binary_path)
        identifier = CryptoIdentifier(binary)
        
        engine = None
        if quantum:
            progress.update(task, description="Initializing quantum engine...")
            engine = QuantumEngine()
        
        progress.update(task, description="Scanning for crypto implementations...")
        findings = identifier.identify(quantum_assist=quantum, quantum_engine=engine)
    
    _print_crypto_findings(findings)
    
    # Print summary
    summary = identifier.summary()
    console.print(f"\n[bold]Summary:[/bold] Found {summary['total_findings']} findings "
                  f"across {summary['unique_algorithms']} algorithm types")


@main.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--start", "-s", type=str, help="Start address (hex)")
@click.option("--end", "-e", type=str, help="End address (hex)")
@click.option("--function", "-f", type=str, help="Disassemble function at address")
@click.option("--count", "-n", type=int, default=50, help="Number of instructions")
def disasm(binary_path: str, start: str | None, end: str | None, 
           function: str | None, count: int):
    """
    Disassemble binary code.
    
    Supports linear disassembly or function-based recursive descent.
    """
    from zetton.core.binary import Binary
    from zetton.analyzers.disasm import Disassembler
    
    binary = Binary.from_file(binary_path)
    disassembler = Disassembler(binary)
    
    console.print(Panel.fit(
        f"[bold blue]Zetton[/bold blue] - Disassembly of [green]{binary_path}[/green]",
        border_style="blue"
    ))
    
    if function:
        # Disassemble function
        addr = int(function, 16) if function.startswith("0x") else int(function)
        func = disassembler.disassemble_function(addr)
        
        console.print(f"\n[bold]Function:[/bold] {func.name} at 0x{func.address:x}")
        console.print(f"[bold]Size:[/bold] {func.size} bytes, {func.instruction_count} instructions")
        console.print(f"[bold]Calls:[/bold] {', '.join(hex(c) for c in func.calls) or 'None'}\n")
        
        for insn in func.instructions[:count]:
            _print_instruction(insn)
    elif start:
        # Disassemble range
        start_addr = int(start, 16) if start.startswith("0x") else int(start)
        end_addr = int(end, 16) if end and end.startswith("0x") else (int(end) if end else start_addr + 256)
        
        for insn in disassembler.disassemble_range(start_addr, end_addr):
            _print_instruction(insn)
    else:
        # Linear disassembly from entry point
        console.print(f"\n[bold]Entry point:[/bold] 0x{binary.entry_point:x}\n")
        
        instructions = disassembler.disassemble(max_instructions=count)
        for insn in instructions:
            _print_instruction(insn)


@main.command()
@click.argument("binary_path", type=click.Path(exists=True))
def info(binary_path: str):
    """
    Display binary information.
    
    Shows file format, architecture, sections, and other metadata.
    """
    from zetton.core.binary import Binary
    
    binary = Binary.from_file(binary_path)
    info = binary.info()
    
    console.print(Panel.fit(
        f"[bold blue]Zetton[/bold blue] - Binary Information",
        border_style="blue"
    ))
    
    _print_binary_info(info)
    
    # Sections table
    if binary.sections:
        table = Table(title="Sections")
        table.add_column("Name", style="cyan")
        table.add_column("Virtual Address", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Entropy", style="magenta")
        
        for section in binary.sections:
            table.add_row(
                section.name,
                f"0x{section.virtual_address:x}",
                f"{section.virtual_size:,}",
                f"{section.entropy:.2f}"
            )
        
        console.print(table)
    
    # Imports summary
    if binary.imports:
        console.print(f"\n[bold]Imports:[/bold] {len(binary.imports)} functions")
        libs = set(i.library for i in binary.imports if i.library)
        if libs:
            console.print(f"[bold]Libraries:[/bold] {', '.join(sorted(libs)[:10])}")


@main.command()
def backends():
    """List available quantum backends."""
    from zetton.quantum.engine import QuantumEngine, BackendType
    
    console.print(Panel.fit(
        "[bold blue]Zetton[/bold blue] - Quantum Backends",
        border_style="blue"
    ))
    
    table = Table()
    table.add_column("Backend", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Status", style="yellow")
    
    # Check each backend
    for backend_type in BackendType:
        try:
            engine = QuantumEngine(backend=backend_type)
            status = "[green]Available[/green]" if engine._backend else "[red]Not Available[/red]"
        except Exception as e:
            status = f"[red]Error: {e}[/red]"
        
        backend_category = "Simulator" if "SIMULATOR" in backend_type.name else "Hardware"
        table.add_row(backend_type.name, backend_category, status)
    
    console.print(table)


def _print_binary_info(info: dict) -> None:
    """Print binary information in a formatted table."""
    table = Table(title="Binary Information", show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Path", str(info["path"]))
    table.add_row("Format", info["format"])
    table.add_row("Architecture", info["architecture"])
    table.add_row("Bits", str(info["bits"]))
    table.add_row("Endianness", info["endianness"])
    table.add_row("Entry Point", info["entry_point"])
    table.add_row("Size", f"{info['size']:,} bytes")
    table.add_row("MD5", info["md5"])
    table.add_row("SHA-256", info["sha256"][:32] + "...")
    
    console.print(table)


def _print_crypto_findings(findings: list) -> None:
    """Print crypto findings in a formatted table."""
    if not findings:
        console.print("[yellow]No cryptographic implementations found.[/yellow]")
        return
    
    table = Table(title="Cryptographic Findings")
    table.add_column("Algorithm", style="cyan")
    table.add_column("Confidence", style="green")
    table.add_column("Offset", style="yellow")
    table.add_column("Section", style="magenta")
    table.add_column("Method", style="blue")
    
    for finding in findings[:20]:  # Limit to top 20
        confidence = f"{finding.confidence:.0%}"
        offset = f"0x{finding.offset:x}"
        method = finding.details.get("search_method", "unknown")
        
        # Color confidence based on value
        if finding.confidence >= 0.8:
            confidence = f"[green]{confidence}[/green]"
        elif finding.confidence >= 0.6:
            confidence = f"[yellow]{confidence}[/yellow]"
        else:
            confidence = f"[red]{confidence}[/red]"
        
        table.add_row(
            finding.algorithm,
            confidence,
            offset,
            finding.section,
            method
        )
    
    console.print(table)
    
    if len(findings) > 20:
        console.print(f"[dim]... and {len(findings) - 20} more findings[/dim]")


def _print_instruction(insn) -> None:
    """Print a single instruction."""
    hex_bytes = insn.bytes.hex()
    
    # Color-code by instruction type
    if insn.is_call:
        mnemonic = f"[cyan]{insn.mnemonic}[/cyan]"
    elif insn.is_jump:
        mnemonic = f"[yellow]{insn.mnemonic}[/yellow]"
    elif insn.is_ret:
        mnemonic = f"[red]{insn.mnemonic}[/red]"
    else:
        mnemonic = insn.mnemonic
    
    console.print(f"[dim]0x{insn.address:08x}[/dim]  {hex_bytes:24s}  {mnemonic:8s} {insn.operands}")


if __name__ == "__main__":
    main()

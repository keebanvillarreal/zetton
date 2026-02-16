"""
Forensics report generation for Zetton.

Generates comprehensive forensics reports in HTML, JSON, and text formats
combining analysis results from all Zetton modules.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zetton.core.binary import Binary
    from zetton.crypto.identify import CryptoFinding
    from zetton.forensics.crypto import CryptoForensicsReport
    from zetton.forensics.timeline import Timeline

logger = logging.getLogger(__name__)


class ReportFormat:
    HTML = "html"
    JSON = "json"
    TEXT = "text"


@dataclass
class ReportSection:
    """A section within a forensics report."""
    title: str
    content: str
    subsections: list[ReportSection] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    severity: str = "info"  # info, low, medium, high, critical


@dataclass
class ForensicsReport:
    """
    Complete forensics report combining all analysis modules.

    Collects results from binary analysis, crypto identification,
    timeline reconstruction, and quantum threat assessment into
    a unified report format.
    """
    title: str = "Zetton Forensics Report"
    binary_name: str = ""
    analysis_date: str = ""
    sections: list[ReportSection] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)


class ReportGenerator:
    """
    Generates forensics reports in multiple formats.

    Example:
        >>> generator = ReportGenerator(binary)
        >>> generator.add_binary_info()
        >>> generator.add_crypto_findings(findings)
        >>> generator.add_timeline(timeline)
        >>> generator.generate("report.html", format="html")
    """

    def __init__(self, binary: Binary):
        self.binary = binary
        self.report = ForensicsReport(
            binary_name=str(binary.path),
            analysis_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        self.report.metadata = {
            "zetton_version": "0.1.0",
            "analysis_date": self.report.analysis_date,
            "binary_path": str(binary.path),
            "binary_format": binary.format.name if binary.format else "UNKNOWN",
            "binary_arch": binary.architecture.name if binary.architecture else "UNKNOWN",
            "binary_md5": binary.md5,
            "binary_sha256": binary.sha256,
        }

    def add_binary_info(self) -> None:
        """Add basic binary information section."""
        b = self.binary
        content = (
            f"File: {b.path}\n"
            f"Format: {b.format.name}\n"
            f"Architecture: {b.architecture.name} ({b.bits}-bit)\n"
            f"Endianness: {b.endianness}\n"
            f"Entry Point: 0x{b.entry_point:x}\n"
            f"Sections: {len(b.sections)}\n"
            f"Symbols: {len(b.symbols)}\n"
            f"Imports: {len(b.imports)}\n"
            f"Exports: {len(b.exports)}\n"
            f"MD5: {b.md5}\n"
            f"SHA-256: {b.sha256}\n"
            f"Size: {len(b.raw_data):,} bytes\n"
        )

        section = ReportSection(
            title="Binary Information",
            content=content,
            data={
                "format": b.format.name,
                "architecture": b.architecture.name,
                "bits": b.bits,
                "entry_point": f"0x{b.entry_point:x}",
                "md5": b.md5,
                "sha256": b.sha256,
                "size": len(b.raw_data),
            },
        )

        # Section details subsection
        if b.sections:
            sec_lines = []
            for s in b.sections:
                sec_lines.append(
                    f"  {s.name:20s} VA=0x{s.virtual_address:08x} "
                    f"Size={s.virtual_size:8d} Entropy={s.entropy:.2f}"
                )
            section.subsections.append(ReportSection(
                title="Sections",
                content="\n".join(sec_lines),
            ))

        self.report.sections.append(section)

    def add_crypto_findings(self, findings: list[CryptoFinding]) -> None:
        """Add cryptographic analysis findings."""
        if not findings:
            self.report.sections.append(ReportSection(
                title="Cryptographic Analysis",
                content="No cryptographic implementations detected.",
            ))
            return

        lines = []
        for f in findings:
            lines.append(
                f"  [{f.confidence:.0%}] {f.algorithm} at 0x{f.offset:x} "
                f"({f.section}) - {f.pattern_type}/{f.pattern_name}"
            )

        section = ReportSection(
            title="Cryptographic Analysis",
            content=f"Found {len(findings)} cryptographic implementations:\n" + "\n".join(lines),
            data={
                "total_findings": len(findings),
                "algorithms": list({f.algorithm for f in findings}),
                "findings": [
                    {
                        "algorithm": f.algorithm,
                        "confidence": f.confidence,
                        "offset": f"0x{f.offset:x}",
                        "section": f.section,
                    }
                    for f in findings
                ],
            },
        )
        self.report.sections.append(section)

    def add_crypto_forensics(self, crypto_report: CryptoForensicsReport) -> None:
        """Add detailed crypto forensics report."""
        # Weaknesses
        if crypto_report.weaknesses:
            lines = [str(w) for w in crypto_report.weaknesses]
            severity = "critical" if any(
                w.severity == "critical" for w in crypto_report.weaknesses
            ) else "high"

            self.report.sections.append(ReportSection(
                title="Cryptographic Weaknesses",
                content="\n".join(lines),
                severity=severity,
                data={"weaknesses": [
                    {"type": w.weakness_type.name, "severity": w.severity,
                     "description": w.description, "recommendation": w.recommendation}
                    for w in crypto_report.weaknesses
                ]},
            ))

        # Quantum threats
        if crypto_report.quantum_threats:
            lines = [str(t) for t in crypto_report.quantum_threats]
            self.report.sections.append(ReportSection(
                title="Quantum Threat Assessment",
                content="\n".join(lines),
                data={"threats": [
                    {"algorithm": t.algorithm, "threat_level": t.threat_level.name,
                     "current_bits": t.current_security_bits,
                     "quantum_bits": t.quantum_security_bits,
                     "shor_applicable": t.shor_applicable,
                     "recommendation": t.recommended_action}
                    for t in crypto_report.quantum_threats
                ]},
            ))

    def add_timeline(self, timeline: Timeline) -> None:
        """Add timeline reconstruction."""
        if not timeline.events:
            self.report.sections.append(ReportSection(
                title="Timeline",
                content="No timeline events reconstructed.",
            ))
            return

        lines = [str(e) for e in timeline.events[:50]]
        if len(timeline.events) > 50:
            lines.append(f"... and {len(timeline.events) - 50} more events")

        content = (
            f"Events: {len(timeline.events)}\n"
            f"Earliest: {timeline.earliest}\n"
            f"Latest: {timeline.latest}\n"
            f"Duration: {timeline.duration}\n\n"
            + "\n".join(lines)
        )

        if timeline.analysis_notes:
            content += "\n\nNotes:\n" + "\n".join(
                f"  - {n}" for n in timeline.analysis_notes
            )

        self.report.sections.append(ReportSection(
            title="Timeline Reconstruction",
            content=content,
            data=timeline.to_dict(),
        ))

    def add_custom_section(
        self, title: str, content: str,
        data: dict | None = None, severity: str = "info"
    ) -> None:
        """Add a custom section to the report."""
        self.report.sections.append(ReportSection(
            title=title,
            content=content,
            data=data or {},
            severity=severity,
        ))

    def generate(
        self, output_path: str | Path, format: str = ReportFormat.HTML
    ) -> Path:
        """
        Generate the report file.

        Args:
            output_path: Output file path
            format: Report format (html, json, text)

        Returns:
            Path to generated report
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == ReportFormat.HTML:
            content = self._generate_html()
        elif format == ReportFormat.JSON:
            content = self._generate_json()
        else:
            content = self._generate_text()

        output_path.write_text(content)
        logger.info(f"Report generated: {output_path}")
        return output_path

    def _generate_html(self) -> str:
        """Generate HTML report."""
        sections_html = []
        for section in self.report.sections:
            severity_class = f"severity-{section.severity}" if section.severity != "info" else ""
            subsections = ""
            if section.subsections:
                subsections = "\n".join(
                    f"<h3>{s.title}</h3><pre>{self._escape_html(s.content)}</pre>"
                    for s in section.subsections
                )
            sections_html.append(
                f'<div class="section {severity_class}">'
                f'<h2>{self._escape_html(section.title)}</h2>'
                f'<pre>{self._escape_html(section.content)}</pre>'
                f'{subsections}'
                f'</div>'
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{self._escape_html(self.report.title)}</title>
<style>
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2em; background: #0a0a0a; color: #e0e0e0; }}
    h1 {{ color: #f0c040; border-bottom: 2px solid #f0c040; padding-bottom: 0.5em; }}
    h2 {{ color: #60a0ff; margin-top: 1.5em; }}
    h3 {{ color: #80c0ff; }}
    pre {{ background: #1a1a2e; padding: 1em; border-radius: 4px; overflow-x: auto; font-size: 0.9em; }}
    .section {{ margin: 1.5em 0; padding: 1em; border-left: 3px solid #333; }}
    .severity-critical {{ border-left-color: #ff4444; background: rgba(255,68,68,0.05); }}
    .severity-high {{ border-left-color: #ff8800; background: rgba(255,136,0,0.05); }}
    .severity-medium {{ border-left-color: #ffcc00; }}
    .severity-low {{ border-left-color: #44aaff; }}
    .meta {{ color: #888; font-size: 0.85em; }}
    .header {{ display: flex; align-items: center; gap: 1em; }}
    .logo {{ font-size: 2em; font-weight: bold; color: #f0c040; }}
</style>
</head>
<body>
<div class="header">
    <span class="logo">⚡ ZETTON</span>
    <span>Quantum-Assisted Binary Analysis Framework</span>
</div>
<h1>{self._escape_html(self.report.title)}</h1>
<p class="meta">Binary: {self._escape_html(self.report.binary_name)} | 
   Date: {self.report.analysis_date}</p>
{''.join(sections_html)}
<hr>
<p class="meta">Generated by Zetton v0.1.0</p>
</body>
</html>"""

    def _generate_json(self) -> str:
        """Generate JSON report."""
        data = {
            "title": self.report.title,
            "metadata": self.report.metadata,
            "sections": [
                {
                    "title": s.title,
                    "severity": s.severity,
                    "content": s.content,
                    "data": s.data,
                    "subsections": [
                        {"title": ss.title, "content": ss.content}
                        for ss in s.subsections
                    ],
                }
                for s in self.report.sections
            ],
        }
        return json.dumps(data, indent=2, default=str)

    def _generate_text(self) -> str:
        """Generate plain text report."""
        lines = [
            "=" * 72,
            f"  ZETTON FORENSICS REPORT",
            f"  {self.report.title}",
            "=" * 72,
            f"Binary: {self.report.binary_name}",
            f"Date: {self.report.analysis_date}",
            "",
        ]

        for section in self.report.sections:
            lines.append("-" * 72)
            lines.append(f"  {section.title}")
            if section.severity != "info":
                lines.append(f"  Severity: {section.severity.upper()}")
            lines.append("-" * 72)
            lines.append(section.content)
            for sub in section.subsections:
                lines.append(f"\n  {sub.title}")
                lines.append(sub.content)
            lines.append("")

        lines.append("=" * 72)
        lines.append("Generated by Zetton v0.1.0")
        return "\n".join(lines)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

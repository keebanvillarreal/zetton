"""
Markdown formatter for Zetton reports.

Produces GitHub-flavored Markdown derived from the canonical JSON report.
"""

from __future__ import annotations

from typing import Any


def _badge(level: str) -> str:
    icons = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
        "LOW": "🟢", "NONE": "🟢", "SECURE": "🟢",
        "FULL": "🟢", "PARTIAL": "🟡", "INFO": "🔵",
    }
    return f"{icons.get(level.upper(), '⚪')} **{level}**"


def _flag(label: str, value: Any) -> str:
    if isinstance(value, bool):
        return f"{'✅' if value else '❌'} {label}"
    if isinstance(value, str):
        if value.lower() == "full":
            return f"✅ {label} (Full)"
        if value.lower() == "partial":
            return f"⚠️  {label} (Partial)"
        return f"❌ {label}"
    return f"❓ {label}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None_\n"
    sep = " | ".join("---" for _ in headers)
    head = " | ".join(headers)
    body = "\n".join(" | ".join(str(c) for c in row) for row in rows)
    return f"| {head} |\n| {sep} |\n" + "\n".join(f"| {' | '.join(str(c) for c in r)} |" for r in rows) + "\n"


def format_markdown(report: dict) -> str:
    meta = report.get("meta", {})
    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines.append("# Zetton Analysis Report")
    lines.append("")
    lines.append(f"**Binary:** `{meta.get('binary', 'unknown')}`  ")
    lines.append(f"**Generated:** {meta.get('timestamp', '')}  ")
    lines.append(f"**Version:** {meta.get('version', '')}  ")
    lines.append(f"**Format:** {meta.get('format', '')}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── CBOM ────────────────────────────────────────────────────────────────
    cbom = report.get("cbom", {})
    algorithms = cbom.get("algorithms", [])
    recs = cbom.get("recommendations", [])
    risk = cbom.get("risk_score", 0)

    lines.append("## 📋 CBOM — Cryptographic Bill of Materials")
    lines.append("")
    lines.append(f"**Overall Risk Score:** {risk}/100  ")
    vuln_count = sum(1 for a in algorithms if a.get("quantum_vulnerable"))
    safe_count = len(algorithms) - vuln_count
    lines.append(f"**Quantum-Vulnerable:** {vuln_count}  &nbsp; **Quantum-Safe:** {safe_count}  ")
    lines.append("")

    if algorithms:
        rows = []
        for a in algorithms:
            vuln = "⚠️ YES" if a.get("quantum_vulnerable") else "✅ NO"
            rows.append([
                f"`{a.get('name','')}`",
                a.get("type", ""),
                vuln,
                a.get("threat_level", "—"),
                a.get("standard", "—"),
                str(a.get("occurrences", 1)),
            ])
        lines.append(_table(
            ["Algorithm", "Type", "Quantum-Vulnerable", "Threat", "Standard", "Occurrences"],
            rows,
        ))
    else:
        lines.append("_No cryptographic algorithms detected._")
    lines.append("")

    if recs:
        lines.append("### Recommendations")
        lines.append("")
        for r in recs:
            lines.append(f"- {r}")
        lines.append("")

    lines.append("---")
    lines.append("")

    # ── Binary Analysis ──────────────────────────────────────────────────────
    b = report.get("binary", {})
    sec = b.get("security", {})

    lines.append("## 🔬 Binary Analysis")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"| --- | --- |")
    for k, label in [
        ("format", "Format"), ("architecture", "Architecture"),
        ("bits", "Bits"), ("endianness", "Endianness"),
        ("entry_point", "Entry Point"), ("size", "Size"),
        ("md5", "MD5"), ("sha256", "SHA-256"),
    ]:
        v = b.get(k, "—")
        if k == "size" and isinstance(v, int):
            v = f"{v:,} bytes"
        lines.append(f"| {label} | `{v}` |")
    lines.append("")

    if sec:
        lines.append("**Security Features:**")
        lines.append("")
        flags = [
            _flag("PIE", sec.get("PIE", False)),
            _flag("NX", sec.get("NX", False)),
            _flag("Stack Canary", sec.get("Canary", False)),
            _flag("FORTIFY", sec.get("FORTIFY", False)),
            _flag("RELRO", sec.get("RELRO", "None")),
        ]
        lines.append("  ".join(flags))
        lines.append("")

    sections = b.get("sections", [])
    if sections:
        lines.append("**Sections:**")
        lines.append("")
        rows = []
        for s in sections:
            ent = s.get("entropy", 0)
            ent_flag = " 🔴" if ent > 7.0 else (" 🟡" if ent > 6.0 else "")
            rows.append([
                f"`{s.get('name') or '(empty)'}`",
                f"`{s.get('vaddr','')}`",
                str(s.get("size", "")),
                f"{ent:.4f}{ent_flag}",
            ])
        lines.append(_table(["Section", "VAddr", "Size", "Entropy"], rows))

    lines.append("---")
    lines.append("")

    # ── PQC ─────────────────────────────────────────────────────────────────
    pqc = report.get("pqc", {})
    score = pqc.get("score", 0)
    grade = pqc.get("grade", "D")

    lines.append("## ⚛ Post-Quantum Cryptography Analysis")
    lines.append("")
    bar = "█" * (score // 10) + "░" * (10 - score // 10)
    lines.append(f"**Migration Score:** `[{bar}]` {score}/100 (Grade: **{grade}**)")
    lines.append("")

    vuln = pqc.get("vulnerable", {})
    if vuln:
        lines.append("### ⚠️ Quantum-Vulnerable Algorithms")
        lines.append("")
        rows = [[v.get("name",""), _badge(v.get("threat","HIGH")), v.get("attack",""), v.get("recommendation","")]
                for v in vuln.values()]
        lines.append(_table(["Algorithm", "Threat", "Attack Vector", "Recommendation"], rows))
    else:
        lines.append("✅ No quantum-vulnerable algorithms detected.")
        lines.append("")

    resistant = pqc.get("pqc_algorithms", {})
    if resistant:
        lines.append("### ✅ Post-Quantum Algorithms Detected")
        lines.append("")
        rows = [[v.get("name",""), v.get("standard",""), v.get("type",""), "🟢 SECURE"]
                for v in resistant.values()]
        lines.append(_table(["Algorithm", "Standard", "Type", "Status"], rows))

    lines.append("---")
    lines.append("")

    # ── Crypto Detection ─────────────────────────────────────────────────────
    crypto = report.get("crypto", {})
    findings = crypto.get("findings", [])

    lines.append("## 🔐 Crypto Detection")
    lines.append("")
    if findings:
        rows = []
        for f in findings:
            rows.append([
                f.get("algorithm",""),
                f"`{f.get('pattern','')}`",
                f"`0x{f.get('offset',0):08X}`",
                f.get("section",""),
                f"{f.get('match_size','')} B",
            ])
        lines.append(_table(["Algorithm", "Pattern", "Offset", "Section", "Size"], rows))
    else:
        lines.append("_No cryptographic patterns found._")
        lines.append("")

    lines.append("---")
    lines.append("")

    # ── Forensics ────────────────────────────────────────────────────────────
    forensics = report.get("forensics", {})
    issues = forensics.get("issues", [])

    lines.append("## 🔎 Forensics")
    lines.append("")
    if issues:
        rows = [[_badge(i.get("severity","INFO")), i.get("description",""), f"`{i.get('offset','')}`"]
                for i in issues]
        lines.append(_table(["Severity", "Description", "Offset"], rows))
    else:
        lines.append("✅ No weaknesses detected.")
        lines.append("")

    lines.append("---")
    lines.append("")

    # ── Dataflow ─────────────────────────────────────────────────────────────
    df = report.get("dataflow", {})
    flows = df.get("flows", [])

    lines.append("## 🌊 Dataflow / Taint Analysis")
    lines.append("")

    sources = df.get("sources", {})
    sinks = df.get("sinks", {})
    if sources:
        lines.append(f"**Taint Sources:** {', '.join(f'`{n}`' for n in sources)}")
    if sinks:
        lines.append(f"**Taint Sinks:** {', '.join(f'`{n}`' for n in sinks)}")
    lines.append("")

    if flows:
        rows = [[
            f"`{f.get('source','')}`", "→", f"`{f.get('sink','')}`",
            f"`{f.get('function','')}`", _badge(f.get("severity","LOW")),
        ] for f in flows]
        lines.append(_table(["Source", "", "Sink", "In Function", "Severity"], rows))
    else:
        lines.append("✅ No taint flows detected.")
        lines.append("")

    lines.append("---")
    lines.append("")

    # ── CFG ──────────────────────────────────────────────────────────────────
    cfg = report.get("cfg", {})
    funcs = cfg.get("functions", [])

    lines.append("## 📊 Control Flow Graph")
    lines.append("")
    if funcs:
        rows = []
        for f in funcs:
            cc = f.get("cyclomatic_complexity", 1)
            cc_flag = " 🔴" if cc > 10 else (" 🟡" if cc > 5 else "")
            rows.append([
                f"`{f.get('name','')}`",
                f"`{f.get('address','')}`",
                str(f.get("instructions","")),
                str(f.get("basic_blocks","")),
                f"{cc}{cc_flag}",
                str(f.get("loops","")),
            ])
        lines.append(_table(
            ["Function", "Address", "Instructions", "Blocks", "Complexity", "Loops"],
            rows,
        ))
    else:
        lines.append("_No functions analyzed._")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"_Generated by Zetton v{meta.get('version','')} — UTSA Cyber Jedis Quantum Cybersecurity RIG_")

    return "\n".join(lines)

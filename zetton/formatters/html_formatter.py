# Zetton - Quantum Software Reverse Engineering Framework
# Copyright (c) 2026 Keeban Villarreal
# Licensed under AGPL-3.0. See LICENSE and COPYRIGHT for details.
# Commercial licensing: keeban.villarreal@my.utsa.edu
"""
HTML formatter for Zetton reports.

Dark theme with gold accents matching Zetton branding.
Produces a single self-contained HTML file with no external dependencies.
"""

from __future__ import annotations

import base64
import html
import io
from pathlib import Path
from typing import Any


# ─── Logo: load at import time, recolor white → gold (#FFD700), embed as b64 ──

def _build_logo_data_uri() -> str:
    """
    Load zetton_namelogowht.png, recolor every pixel to gold (#FFD700) while
    preserving the original alpha channel, and return a base64 PNG data URI.
    Falls back to "" if Pillow is unavailable or the file is missing.
    """
    logo_path = Path(__file__).parent.parent / "assets" / "zetton_namelogowht.png"
    try:
        from PIL import Image
        img = Image.open(logo_path).convert("RGBA")
        _, _, _, alpha = img.split()
        # Solid gold for all RGB; alpha channel carries the logo shape unchanged
        gold_r = Image.new("L", img.size, 255)   # R = 0xFF
        gold_g = Image.new("L", img.size, 215)   # G = 0xD7
        gold_b = Image.new("L", img.size, 0)     # B = 0x00
        gold_img = Image.merge("RGBA", (gold_r, gold_g, gold_b, alpha))
        buf = io.BytesIO()
        gold_img.save(buf, format="PNG", optimize=True)
        b64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{b64}"
    except Exception:
        return ""


_LOGO_DATA_URI: str = _build_logo_data_uri()


# ─── Color palette (mirrors CLI: bold yellow banner, cyan highlights) ────────
_CSS = """
:root {
    --bg:        #0d1117;
    --bg-card:   #161b22;
    --bg-code:   #0f1923;
    --border:    #30363d;
    --gold:      #ffd700;
    --gold-dim:  #b8960c;
    --cyan:      #00cfcf;
    --green:     #3fb950;
    --yellow:    #d29922;
    --red:       #f85149;
    --red-dim:   #8b1a1a;
    --orange:    #db6d28;
    --purple:    #bc8cff;
    --text:      #c9d1d9;
    --text-dim:  #6e7681;
    --text-head: #e6edf3;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', 'Consolas', monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
}

/* ── Header ── */
.zetton-header {
    border-bottom: 2px solid var(--gold);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
}
.zetton-logo {
    display: block;
    height: 80px;
    width: auto;
    margin-bottom: .75rem;
    filter: drop-shadow(0 0 8px rgba(255, 215, 0, 0.55));
}
.zetton-subtitle {
    color: var(--text-dim);
    font-size: 13px;
}
.zetton-subtitle span { color: var(--gold-dim); }

.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: .5rem 2rem;
    margin-top: 1rem;
    font-size: 12px;
}
.meta-grid .label { color: var(--text-dim); }
.meta-grid .value { color: var(--cyan); word-break: break-all; }

/* ── Section cards ── */
.section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 1.5rem;
    overflow: hidden;
}
.section-header {
    background: #1c2128;
    border-bottom: 1px solid var(--border);
    padding: .6rem 1rem;
    display: flex;
    align-items: center;
    gap: .5rem;
}
.section-title {
    color: var(--gold);
    font-size: 13px;
    font-weight: bold;
    letter-spacing: .05em;
    text-transform: uppercase;
}
.section-badge {
    margin-left: auto;
    font-size: 11px;
    color: var(--text-dim);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1px 8px;
}
.section-body { padding: 1rem; }

/* ── Tables ── */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin-bottom: .5rem;
}
th {
    text-align: left;
    color: var(--gold-dim);
    border-bottom: 1px solid var(--border);
    padding: .4rem .6rem;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .05em;
}
td {
    padding: .35rem .6rem;
    border-bottom: 1px solid #21262d;
    vertical-align: top;
    word-break: break-word;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: #1c2128; }

/* ── Severity badges ── */
.badge {
    display: inline-block;
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: .04em;
}
.badge-critical { background: #2d0c0c; color: var(--red);    border: 1px solid var(--red-dim); }
.badge-high     { background: #1f1505; color: var(--orange); border: 1px solid #5a3010; }
.badge-medium   { background: #1a1400; color: var(--yellow); border: 1px solid #4a3800; }
.badge-low      { background: #0b1f0b; color: var(--green);  border: 1px solid #1a3f1a; }
.badge-none     { background: #0b1f0b; color: var(--green);  border: 1px solid #1a3f1a; }
.badge-secure   { background: #0b1f0b; color: var(--cyan);   border: 1px solid #0a3030; }
.badge-warning  { background: #1f1505; color: #d29922;        border: 1px solid #5a3010; }
.badge-info     { background: #0d1a2d; color: var(--cyan);   border: 1px solid #0a2040; }

/* ── KV grids (key → value) ── */
.kv-grid {
    display: grid;
    grid-template-columns: 180px 1fr;
    gap: .25rem 1rem;
    font-size: 12px;
}
.kv-key   { color: var(--text-dim); }
.kv-value { color: var(--text); word-break: break-all; }
.kv-value.mono { font-family: monospace; color: var(--cyan); }

/* ── Score bar ── */
.score-row { display: flex; align-items: center; gap: 1rem; margin-bottom: .5rem; }
.score-bar-bg {
    flex: 1; height: 10px; border-radius: 5px;
    background: var(--bg); border: 1px solid var(--border);
}
.score-bar-fill {
    height: 100%; border-radius: 5px;
    transition: width .3s;
}
.score-label { font-size: 20px; font-weight: bold; min-width: 60px; text-align: right; }

/* ── CBOM ── */
.cbom-algo {
    display: flex; align-items: flex-start;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: .5rem .75rem;
    margin-bottom: .5rem;
    gap: .75rem;
    background: var(--bg);
}
.cbom-algo-name { color: var(--text-head); font-weight: bold; flex: 1; }
.cbom-algo-meta { color: var(--text-dim); font-size: 11px; }

/* ── Security flags ── */
.flag { display: inline-flex; align-items: center; gap: .3rem; margin-right: .75rem; }
.flag-on  { color: var(--green); }
.flag-off { color: var(--red); }
.flag-partial { color: var(--yellow); }

/* ── Footer ── */
.footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--text-dim);
    font-size: 11px;
    text-align: center;
}
.footer a { color: var(--gold-dim); text-decoration: none; }
"""


# ─── Helpers ────────────────────────────────────────────────────────────────

def _h(s: Any) -> str:
    """HTML-escape a value."""
    return html.escape(str(s))


def _badge(level: str) -> str:
    lvl = level.upper()
    cls = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "NONE": "none", "SECURE": "secure",
        "FULL": "secure", "PARTIAL": "medium", "WARNING": "warning", "INFO": "info",
    }.get(lvl, "info")
    return f'<span class="badge badge-{cls}">{_h(level)}</span>'


def _flag(label: str, value: Any) -> str:
    if isinstance(value, bool):
        cls = "flag-on" if value else "flag-off"
        sym = "✓" if value else "✗"
    elif isinstance(value, str):
        if value.lower() == "full":
            cls, sym = "flag-on", "✓"
        elif value.lower() in ("partial", "none"):
            cls = "flag-partial" if value.lower() == "partial" else "flag-off"
            sym = "⚠" if value.lower() == "partial" else "✗"
        else:
            cls, sym = "flag-off", "✗"
    else:
        cls, sym = "flag-info", "?"
    return f'<span class="flag"><span class="{cls}">{sym}</span> {_h(label)}</span>'


def _score_bar(score: int, grade: str) -> str:
    pct = max(0, min(100, score))
    if pct >= 75:
        color, label_color = "#3fb950", "#3fb950"
    elif pct >= 50:
        color, label_color = "#d29922", "#d29922"
    else:
        color, label_color = "#f85149", "#f85149"
    return f"""
<div class="score-row">
  <div class="score-bar-bg">
    <div class="score-bar-fill" style="width:{pct}%; background:{color};"></div>
  </div>
  <div class="score-label" style="color:{label_color};">{score}/100 ({_h(grade)})</div>
</div>"""


def _section(title: str, body: str, badge: str = "") -> str:
    badge_html = f'<span class="section-badge">{_h(badge)}</span>' if badge else ""
    return f"""
<div class="section">
  <div class="section-header">
    <span class="section-title">{_h(title)}</span>
    {badge_html}
  </div>
  <div class="section-body">
    {body}
  </div>
</div>"""


# ─── Section renderers ───────────────────────────────────────────────────────

def _render_binary(data: dict) -> str:
    b = data.get("binary", {})
    sec = b.get("security", {})

    kv_rows = ""
    for key, label in [
        ("format", "Format"), ("architecture", "Architecture"),
        ("bits", "Bits"), ("endianness", "Endianness"),
        ("entry_point", "Entry Point"), ("size", "Size"),
        ("md5", "MD5"), ("sha256", "SHA-256"),
    ]:
        val = b.get(key, "—")
        mono = key in ("md5", "sha256", "entry_point")
        mono_cls = ' class="mono"' if mono else ""
        if key == "size" and isinstance(val, int):
            val = f"{val:,} bytes"
        kv_rows += f'<div class="kv-key">{_h(label)}</div><div class="kv-value"{mono_cls}>{_h(val)}</div>\n'

    flags_html = ""
    if sec:
        flags_html = '<div style="margin-top:.75rem;">'
        for k in ("PIE", "NX", "Canary", "FORTIFY"):
            flags_html += _flag(k, sec.get(k, False))
        flags_html += _flag("RELRO", sec.get("RELRO", "None"))
        flags_html += "</div>"

    sections_html = ""
    sections = b.get("sections", [])
    if sections:
        rows = ""
        for s in sections:
            ent = s.get("entropy", 0)
            if isinstance(ent, (int, float)):
                if ent > 7.0:
                    ent_color = "var(--red)"
                elif ent > 6.0:
                    ent_color = "var(--yellow)"
                else:
                    ent_color = "var(--green)"
                ent_cell = f'<span style="color:{ent_color};">{ent:.4f}</span>'
            else:
                ent_cell = _h(ent)
            rows += f"""<tr>
              <td style="color:var(--cyan);">{_h(s.get("name") or "(empty)")}</td>
              <td style="font-family:monospace;">{_h(s.get("vaddr",""))}</td>
              <td>{_h(s.get("size",""))}</td>
              <td>{ent_cell}</td>
            </tr>"""
        sections_html = f"""
<table style="margin-top:1rem;">
  <thead><tr><th>Section</th><th>Vaddr</th><th>Size</th><th>Entropy</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

    body = f'<div class="kv-grid">{kv_rows}</div>{flags_html}{sections_html}'
    count = len(sections)
    return _section("Binary Analysis", body, f"{count} sections")


def _render_crypto(data: dict) -> str:
    findings = data.get("crypto", {}).get("findings", [])
    if not findings:
        return _section("Crypto Detection",
                        "<p style='color:var(--text-dim)'>No cryptographic patterns found.</p>",
                        "0 findings")

    rows = ""
    for f in findings:
        rows += f"""<tr>
          <td style="color:var(--gold); font-weight:bold;">{_h(f.get("algorithm",""))}</td>
          <td style="color:var(--cyan);">{_h(f.get("pattern",""))}</td>
          <td style="font-family:monospace;">0x{f.get("offset",0):08X}</td>
          <td style="color:var(--purple);">{_h(f.get("section",""))}</td>
          <td style="color:var(--text-dim);">{_h(f.get("match_size",""))} B</td>
        </tr>"""

    body = f"""
<table>
  <thead><tr><th>Algorithm</th><th>Pattern</th><th>Offset</th><th>Section</th><th>Size</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    return _section("Crypto Detection", body, f"{len(findings)} findings")


def _render_forensics(data: dict) -> str:
    issues = data.get("forensics", {}).get("issues", [])
    if not issues:
        body = "<p style='color:var(--green)'>✓ No weaknesses detected.</p>"
    else:
        rows = ""
        for iss in issues:
            sev = iss.get("severity", "INFO")
            rows += f"""<tr>
              <td>{_badge(sev)}</td>
              <td>{_h(iss.get("description",""))}</td>
              <td style="font-family:monospace;color:var(--text-dim);">{_h(iss.get("offset",""))}</td>
            </tr>"""
        body = f"""
<table>
  <thead><tr><th>Severity</th><th>Description</th><th>Offset</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    return _section("Forensics", body, f"{len(issues)} issue(s)")


def _render_cfg(data: dict) -> str:
    funcs = data.get("cfg", {}).get("functions", [])
    if not funcs:
        return _section("Control Flow Graph",
                        "<p style='color:var(--text-dim)'>No functions analyzed.</p>",
                        "0 functions")
    rows = ""
    for f in funcs:
        cc = f.get("cyclomatic_complexity", 1)
        cc_color = "var(--red)" if cc > 10 else ("var(--yellow)" if cc > 5 else "var(--green)")
        rows += f"""<tr>
          <td style="color:var(--cyan);">{_h(f.get("name",""))}</td>
          <td style="font-family:monospace;">{_h(f.get("address",""))}</td>
          <td>{_h(f.get("instructions",""))}</td>
          <td>{_h(f.get("basic_blocks",""))}</td>
          <td style="color:{cc_color}; font-weight:bold;">{cc}</td>
          <td>{_h(f.get("loops",""))}</td>
        </tr>"""
    body = f"""
<table>
  <thead><tr><th>Function</th><th>Address</th><th>Instructions</th><th>Blocks</th><th>Complexity</th><th>Loops</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    return _section("Control Flow Graph", body, f"{len(funcs)} functions")


def _render_dataflow(data: dict) -> str:
    df = data.get("dataflow", {})
    sources = df.get("sources", {})
    sinks = df.get("sinks", {})
    flows = df.get("flows", [])

    src_rows = "".join(
        f'<tr><td style="color:var(--cyan);">{_h(n)}</td><td>{_h(v.get("description",""))}</td></tr>'
        for n, v in sources.items()
    ) or "<tr><td colspan='2' style='color:var(--text-dim)'>None found</td></tr>"

    sink_rows = "".join(
        f'<tr><td style="color:var(--red);">{_h(n)}</td><td>{_h(v.get("description",""))}</td><td>{_badge(v.get("severity","LOW"))}</td></tr>'
        for n, v in sinks.items()
    ) or "<tr><td colspan='3' style='color:var(--text-dim)'>None found</td></tr>"

    flow_rows = "".join(
        f"""<tr>
          <td style="color:var(--cyan);">{_h(f.get("source",""))}</td>
          <td style="color:var(--text-dim);">→</td>
          <td style="color:var(--red);">{_h(f.get("sink",""))}</td>
          <td style="color:var(--yellow);">{_h(f.get("function",""))}</td>
          <td>{_badge(f.get("severity","LOW"))}</td>
        </tr>"""
        for f in flows
    ) or "<tr><td colspan='5' style='color:var(--green)'>No taint flows detected</td></tr>"

    body = f"""
<div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
  <div>
    <div style="color:var(--text-dim); font-size:11px; text-transform:uppercase; margin-bottom:.4rem;">Taint Sources</div>
    <table>
      <thead><tr><th>Function</th><th>Type</th></tr></thead>
      <tbody>{src_rows}</tbody>
    </table>
  </div>
  <div>
    <div style="color:var(--text-dim); font-size:11px; text-transform:uppercase; margin-bottom:.4rem;">Taint Sinks</div>
    <table>
      <thead><tr><th>Function</th><th>Risk</th><th>Severity</th></tr></thead>
      <tbody>{sink_rows}</tbody>
    </table>
  </div>
</div>
<div style="color:var(--text-dim); font-size:11px; text-transform:uppercase; margin-bottom:.4rem;">Detected Taint Flows</div>
<table>
  <thead><tr><th>Source</th><th></th><th>Sink</th><th>In Function</th><th>Severity</th></tr></thead>
  <tbody>{flow_rows}</tbody>
</table>"""
    return _section("Dataflow / Taint Analysis", body, f"{len(flows)} flow(s)")


def _render_pqc(data: dict) -> str:
    pqc = data.get("pqc", {})
    vuln = pqc.get("vulnerable", {})
    resistant = pqc.get("pqc_algorithms", {})
    score = pqc.get("score", 0)
    grade = pqc.get("grade", "D")

    vuln_rows = "".join(
        f"""<tr>
          <td style="color:var(--gold); font-weight:bold;">{_h(v.get("name",""))}</td>
          <td>{_badge(v.get("threat","HIGH"))}</td>
          <td style="color:var(--text-dim);">{_h(v.get("attack",""))}</td>
        </tr>"""
        for v in vuln.values()
    ) or "<tr><td colspan='3' style='color:var(--green)'>✓ No quantum-vulnerable algorithms detected</td></tr>"

    pqc_rows = "".join(
        f"""<tr>
          <td style="color:var(--cyan); font-weight:bold;">{_h(v.get("name",""))}</td>
          <td style="color:var(--gold-dim);">{_h(v.get("standard",""))}</td>
          <td>{_h(v.get("type",""))}</td>
          <td>{_badge("SECURE")}</td>
        </tr>"""
        for v in resistant.values()
    ) or "<tr><td colspan='4' style='color:var(--red)'>No PQC algorithms detected</td></tr>"

    body = f"""
{_score_bar(score, grade)}
<div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-top:1rem;">
  <div>
    <div style="color:var(--red); font-size:11px; text-transform:uppercase; margin-bottom:.4rem;">⚠ Quantum-Vulnerable</div>
    <table>
      <thead><tr><th>Algorithm</th><th>Threat</th><th>Attack</th></tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>
  </div>
  <div>
    <div style="color:var(--green); font-size:11px; text-transform:uppercase; margin-bottom:.4rem;">✓ Post-Quantum Secure</div>
    <table>
      <thead><tr><th>Algorithm</th><th>Standard</th><th>Type</th><th>Status</th></tr></thead>
      <tbody>{pqc_rows}</tbody>
    </table>
  </div>
</div>"""
    return _section("PQC Analysis", body, f"Score: {score}/100 ({grade})")


def _render_cbom(data: dict) -> str:
    cbom = data.get("cbom", {})
    algorithms = cbom.get("algorithms", [])
    recommendations = cbom.get("recommendations", [])
    risk_score = cbom.get("risk_score", 0)

    if not algorithms:
        body = "<p style='color:var(--text-dim)'>No cryptographic algorithms detected.</p>"
    else:
        algo_html = ""
        for a in algorithms:
            quantum_badge = (
                _badge("CRITICAL") if a.get("quantum_vulnerable") and a.get("threat_level") == "CRITICAL"
                else _badge("HIGH") if a.get("quantum_vulnerable")
                else _badge("SECURE")
            )
            algo_html += f"""
<div class="cbom-algo">
  <div>
    <div class="cbom-algo-name">{_h(a.get("name",""))}</div>
    <div class="cbom-algo-meta">
      Type: {_h(a.get("type",""))} &nbsp;|&nbsp;
      Occurrences: {_h(a.get("occurrences", 1))}
      {f"&nbsp;|&nbsp; Standard: {_h(a.get('standard',''))}" if a.get("standard") else ""}
    </div>
  </div>
  <div style="text-align:right;">
    {quantum_badge}
    <div class="cbom-algo-meta" style="margin-top:.3rem;">{_h(a.get("threat_level",""))}</div>
  </div>
</div>"""

        recs_html = ""
        if recommendations:
            recs_html = '<div style="margin-top:1rem; color:var(--text-dim); font-size:11px; text-transform:uppercase;">Recommendations</div><ul style="margin-top:.5rem; padding-left:1.2rem;">'
            for r in recommendations:
                recs_html += f'<li style="color:var(--yellow); margin-bottom:.3rem;">{_h(r)}</li>'
            recs_html += "</ul>"

        body = f"""
<div style="margin-bottom:.5rem; color:var(--text-dim); font-size:12px;">
  Overall Risk Score: <span style="color:var(--gold);">{risk_score}/100</span>
  &nbsp;|&nbsp; {len([a for a in algorithms if a.get("quantum_vulnerable")])} quantum-vulnerable,
  {len([a for a in algorithms if not a.get("quantum_vulnerable")])} quantum-safe
</div>
{algo_html}
{recs_html}"""

    return _section("CBOM — Cryptographic Bill of Materials", body,
                    f"{len(algorithms)} algorithm(s)")


# ─── PCAP section renderers ──────────────────────────────────────────────────

def _render_pcap_summary(data: dict) -> str:
    summary = data.get("summary", {})
    rows = [
        ("Total packets",           f"{summary.get('total_packets', 0):,}"),
        ("TLS ClientHellos",         str(summary.get("client_hellos", 0))),
        ("TLS ServerHellos",         str(summary.get("server_hellos", 0))),
        ("Unique connections",       str(summary.get("unique_connections", 0))),
        ("Cipher suites offered",    str(len(data.get("cipher_suites", {}).get("offered", {})))),
        ("Cipher suites negotiated", str(len(data.get("cipher_suites", {}).get("negotiated", {})))),
    ]
    sni = data.get("sni_hostnames", [])
    if sni:
        rows.append(("Unique SNI hostnames", str(len(set(sni)))))
    pqc = data.get("pqc_detected", [])
    if pqc:
        rows.append(("PQC groups detected", str(len(pqc))))

    kv = "".join(
        f'<div class="kv-key">{_h(label)}</div><div class="kv-value">{_h(val)}</div>\n'
        for label, val in rows
    )
    return _section("PCAP Summary", f'<div class="kv-grid">{kv}</div>')


def _render_pcap_cipher_suites(data: dict) -> str:
    negotiated = data.get("cipher_suites", {}).get("negotiated", {})
    if not negotiated:
        return _section("Negotiated Cipher Suites",
                        "<p style='color:var(--text-dim)'>No negotiated cipher suites found.</p>",
                        "0 suites")

    # Sort by session count descending
    items = sorted(negotiated.values(), key=lambda x: -x.get("count", 0))
    rows = ""
    for cs in items:
        threat = cs.get("quantum_threat", "UNKNOWN")
        badge_cls = {
            "CRITICAL": "critical", "HIGH": "high", "LOW": "low", "SAFE": "secure",
        }.get(threat, "warning")
        rows += f"""<tr>
          <td style="font-family:monospace;color:var(--text-dim);">{_h(cs.get("code",""))}</td>
          <td style="color:var(--cyan);">{_h(cs.get("name",""))}</td>
          <td style="color:var(--yellow);">{_h(cs.get("key_exchange",""))}</td>
          <td><span class="badge badge-{badge_cls}">{_h(threat)}</span></td>
          <td style="text-align:right;">{_h(cs.get("count", 0))}</td>
        </tr>"""

    body = f"""
<table>
  <thead><tr><th>Code</th><th>Cipher Suite</th><th>Key Exch.</th><th>Quantum Risk</th><th style="text-align:right;">Sessions</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    return _section("Negotiated Cipher Suites", body, f"{len(items)} suite(s)")


def _render_pcap_key_groups(data: dict) -> str:
    offered_map   = data.get("key_exchange_groups", {}).get("offered", {})
    selected_map  = data.get("key_exchange_groups", {}).get("selected", {})
    pqc_codes     = {p["code"] for p in data.get("pqc_detected", [])}
    all_codes     = set(offered_map) | set(selected_map)

    if not all_codes:
        return _section("Key Exchange Groups",
                        "<p style='color:var(--text-dim)'>No key exchange groups found.</p>",
                        "0 groups")

    rows = ""
    for code in sorted(all_codes):
        entry = offered_map.get(code) or selected_map.get(code) or {}
        threat  = entry.get("quantum_threat", "UNKNOWN")
        is_pqc  = (code in pqc_codes) or threat == "SAFE"
        if is_pqc:
            q_cell = '<span class="badge badge-secure">PQC ✓</span>'
            row_style = ' style="background:rgba(0,207,207,0.04);"'
        else:
            badge_cls = {"CRITICAL": "critical", "HIGH": "high",
                         "LOW": "low"}.get(threat, "warning")
            q_cell = f'<span class="badge badge-{badge_cls}">{_h(threat)}</span>'
            row_style = ""
        offered_count  = offered_map.get(code,  {}).get("count", "—")
        selected_count = selected_map.get(code, {}).get("count", "—")
        rows += f"""<tr{row_style}>
          <td style="font-family:monospace;color:var(--text-dim);">{_h(code)}</td>
          <td style="color:var(--cyan);">{_h(entry.get("name",""))}</td>
          <td style="color:var(--yellow);">{_h(entry.get("type",""))}</td>
          <td>{q_cell}</td>
          <td style="text-align:right;">{_h(offered_count)}</td>
          <td style="text-align:right;">{_h(selected_count)}</td>
        </tr>"""

    body = f"""
<table>
  <thead><tr><th>Code</th><th>Group</th><th>Type</th><th>Quantum</th><th style="text-align:right;">Offered</th><th style="text-align:right;">Selected</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    return _section("Key Exchange Groups", body, f"{len(all_codes)} group(s)")


def _render_pcap_tls_versions(data: dict) -> str:
    tls_versions = data.get("tls_versions", {})
    if not tls_versions:
        return _section("TLS Versions",
                        "<p style='color:var(--text-dim)'>No TLS version data found.</p>", "0")

    ver_status = {
        "SSL 3.0":  ("DEPRECATED", "critical"),
        "TLS 1.0":  ("DEPRECATED", "critical"),
        "TLS 1.1":  ("DEPRECATED", "high"),
        "TLS 1.2":  ("LEGACY",     "warning"),
        "TLS 1.3":  ("CURRENT",    "secure"),
    }
    rows = ""
    for ver, count in sorted(tls_versions.items(),
                             key=lambda x: -x[1]):
        label, cls = ver_status.get(ver, ("UNKNOWN", "info"))
        rows += f"""<tr>
          <td style="color:var(--cyan);">{_h(ver)}</td>
          <td style="text-align:right;">{_h(count)}</td>
          <td><span class="badge badge-{cls}">{_h(label)}</span></td>
        </tr>"""

    body = f"""
<table>
  <thead><tr><th>Version</th><th style="text-align:right;">Sessions</th><th>Status</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    return _section("TLS Versions Negotiated", body, f"{len(tls_versions)} version(s)")


def _render_pcap_assessment(data: dict) -> str:
    assessment = data.get("assessment", {})
    readiness  = assessment.get("readiness", "UNKNOWN")
    vuln       = assessment.get("vulnerable_sessions", 0)
    pqc_sess   = assessment.get("pqc_sessions", 0)
    tls13_sess = assessment.get("tls13_sessions", 0)
    total      = max(data.get("summary", {}).get("server_hellos", 1), 1)

    # Map readiness to score/grade for the score bar
    score_map = {
        "GOOD":         (85, "A"),
        "PARTIAL":      (55, "C"),
        "TRANSITIONING":(45, "C"),
        "MIXED":        (35, "D"),
        "POOR":         (15, "F"),
        "UNKNOWN":      (0,  "F"),
    }
    score, grade = score_map.get(readiness, (0, "F"))

    readiness_badge = {
        "GOOD":          "secure",
        "PARTIAL":       "warning",
        "TRANSITIONING": "warning",
        "MIXED":         "high",
        "POOR":          "critical",
    }.get(readiness, "info")

    def pct(n): return f"{100*n//total}%" if total else "0%"

    detail_rows = ""
    if vuln:
        detail_rows += f"""<tr>
          <td style="color:var(--text-dim);">Vulnerable sessions</td>
          <td style="color:var(--red);">{vuln} ({pct(vuln)} of sessions)</td>
        </tr>"""
    if pqc_sess:
        detail_rows += f"""<tr>
          <td style="color:var(--text-dim);">PQC-protected sessions</td>
          <td style="color:var(--cyan);">{pqc_sess} ({pct(pqc_sess)} of sessions)</td>
        </tr>"""
    if tls13_sess:
        detail_rows += f"""<tr>
          <td style="color:var(--text-dim);">TLS 1.3 sessions</td>
          <td style="color:var(--green);">{tls13_sess} ({pct(tls13_sess)} of sessions)</td>
        </tr>"""

    detail_table = f"""
<table style="margin-top:.75rem;">
  <tbody>{detail_rows}</tbody>
</table>""" if detail_rows else ""

    body = f"""
<div style="margin-bottom:.5rem;">
  <span class="badge badge-{readiness_badge}" style="font-size:13px; padding:3px 12px;">
    {_h(readiness)}
  </span>
</div>
{_score_bar(score, grade)}
{detail_table}"""
    return _section("Quantum Readiness Assessment", body, readiness)


def _render_pcap_sni(data: dict) -> str:
    sni_list = data.get("sni_hostnames", [])
    if not sni_list:
        return _section("SNI Hostnames",
                        "<p style='color:var(--text-dim)'>No SNI hostnames observed.</p>", "0")

    unique = sorted(set(sni_list))
    rows = "".join(
        f'<tr><td style="color:var(--cyan);">{_h(h)}</td></tr>'
        for h in unique[:50]
    )
    note = (f'<p style="color:var(--text-dim);font-size:11px;margin-top:.5rem;">'
            f'Showing 50 of {len(unique)} hostnames.</p>'
            if len(unique) > 50 else "")

    body = f"""
<table>
  <thead><tr><th>Hostname</th></tr></thead>
  <tbody>{rows}</tbody>
</table>{note}"""
    return _section("SNI Hostnames Observed", body, f"{len(unique)} unique")


# ─── Main entry point ────────────────────────────────────────────────────────

def format_html_pcap(report: dict) -> str:
    """Render a Zetton PCAP analysis report dict as a self-contained HTML document."""
    import datetime

    pcap_path = report.get("pcap", "unknown")
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")

    if _LOGO_DATA_URI:
        logo_html = f'<img class="zetton-logo" src="{_LOGO_DATA_URI}" alt="Zetton">'
    else:
        logo_html = '<div style="color:var(--gold);font-size:22px;font-weight:bold;margin-bottom:.75rem;">ZETTON</div>'

    meta_html = f"""
<div class="meta-grid">
  <div><span class="label">PCAP file</span></div>
  <div><span class="value">{_h(pcap_path)}</span></div>
  <div><span class="label">Generated</span></div>
  <div><span class="value">{_h(timestamp)}</span></div>
  <div><span class="label">Report type</span></div>
  <div><span class="value">PCAP Crypto &amp; PQC Analysis</span></div>
</div>"""

    sections = "".join([
        _render_pcap_summary(report),
        _render_pcap_assessment(report),
        _render_pcap_cipher_suites(report),
        _render_pcap_key_groups(report),
        _render_pcap_tls_versions(report),
        _render_pcap_sni(report),
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zetton PCAP Report — {_h(pcap_path)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="zetton-header">
    {logo_html}
    <div class="zetton-subtitle">
      <span>Quantum Software Reverse Engineering Framework</span>
      &nbsp;·&nbsp; UTSA Cyber Jedis Quantum Cybersecurity RIG
    </div>
    {meta_html}
  </div>
  {sections}
  <div class="footer">
    Generated by <a href="https://github.com/keebanvillarreal/zetton">Zetton</a>
    &nbsp;·&nbsp; UTSA Cyber Jedis Quantum Cybersecurity RIG
  </div>
</body>
</html>"""


def format_html(report: dict) -> str:
    """Render a Zetton report dict as a self-contained HTML document."""
    meta = report.get("meta", {})
    binary_path = meta.get("binary", "unknown")
    timestamp = meta.get("timestamp", "")
    version = meta.get("version", "")

    if _LOGO_DATA_URI:
        logo_html = (
            f'<img class="zetton-logo" src="{_LOGO_DATA_URI}" alt="Zetton">'
        )
    else:
        logo_html = '<div style="color:var(--gold);font-size:22px;font-weight:bold;margin-bottom:.75rem;">ZETTON</div>'

    meta_html = f"""
<div class="meta-grid">
  <div><span class="label">Binary</span></div>
  <div><span class="value">{_h(binary_path)}</span></div>
  <div><span class="label">Generated</span></div>
  <div><span class="value">{_h(timestamp)}</span></div>
  <div><span class="label">Zetton Version</span></div>
  <div><span class="value">{_h(version)}</span></div>
  <div><span class="label">Format</span></div>
  <div><span class="value">{_h(meta.get("format", ""))}</span></div>
</div>"""

    sections = "".join([
        _render_cbom(report),
        _render_binary(report),
        _render_pqc(report),
        _render_crypto(report),
        _render_forensics(report),
        _render_dataflow(report),
        _render_cfg(report),
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zetton Report — {_h(binary_path)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="zetton-header">
    {logo_html}
    <div class="zetton-subtitle">
      <span>Quantum Software Reverse Engineering Framework</span>
      &nbsp;·&nbsp; UTSA Cyber Jedis Quantum Cybersecurity RIG
    </div>
    {meta_html}
  </div>
  {sections}
  <div class="footer">
    Generated by <a href="https://github.com/keebanvillarreal/zetton">Zetton v{_h(version)}</a>
    &nbsp;·&nbsp; UTSA Cyber Jedis Quantum Cybersecurity RIG
  </div>
</body>
</html>"""

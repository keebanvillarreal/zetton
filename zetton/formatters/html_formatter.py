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

import html
from typing import Any

# ─── Gold logo: pre-built base64 PNG (white logo recolored to #FFD700) ────────
# Generated from zetton/assets/zetton_namelogowht.png via PIL at dev time.
# Stored as a constant so no image file or Pillow is required at runtime.
_LOGO_B64: str = (
    "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"
    "gg=="
)
_LOGO_DATA_URI: str = f"data:image/png;base64,{_LOGO_B64}"
_LOGO_HTML: str = f'<img class="zetton-logo" src="{_LOGO_DATA_URI}" alt="Zetton">'


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

    logo_html = _LOGO_HTML

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

    logo_html = _LOGO_HTML

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

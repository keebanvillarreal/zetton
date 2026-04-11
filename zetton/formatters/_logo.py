"""
Shared Zetton logo asset for HTML formatters.

Loads zetton_namelogowht.png at import time, recolors every pixel to gold
(#FFD700) while preserving alpha, and exposes the result as a base64 PNG
data URI.  Both the binary and PCAP HTML formatters import from here so the
logo is built once and never duplicated.
"""

from __future__ import annotations

import base64
import io
from pathlib import Path


def _build_logo_data_uri() -> str:
    """
    Return a base64 PNG data URI of the Zetton logo recolored to gold (#FFD700).
    Falls back to "" if Pillow is unavailable or the asset file is missing.
    """
    logo_path = Path(__file__).parent.parent / "assets" / "zetton_namelogowht.png"
    try:
        from PIL import Image
        img = Image.open(logo_path).convert("RGBA")
        _, _, _, alpha = img.split()
        # Solid gold RGB; alpha carries the logo shape unchanged
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


#: Gold logo data URI, built once at import time and shared by all formatters.
LOGO_DATA_URI: str = _build_logo_data_uri()

#: Ready-to-embed HTML snippet: ``<img>`` when the logo loaded, fallback text otherwise.
LOGO_HTML: str = (
    f'<img class="zetton-logo" src="{LOGO_DATA_URI}" alt="Zetton">'
    if LOGO_DATA_URI
    else '<div style="color:var(--gold);font-size:22px;font-weight:bold;'
         'margin-bottom:.75rem;">ZETTON</div>'
)

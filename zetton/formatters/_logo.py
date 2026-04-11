"""
Re-exports the pre-built logo constants from html_formatter so any future
formatter module can import them from a single shared location.
"""

from .html_formatter import _LOGO_DATA_URI as LOGO_DATA_URI, _LOGO_HTML as LOGO_HTML

__all__ = ["LOGO_DATA_URI", "LOGO_HTML"]

"""
Zetton Report Formatters

Converts the canonical JSON report structure into HTML, Markdown, or JSON output.
JSON is the canonical format; HTML and Markdown derive from it.
"""

from .html_formatter import format_html, format_html_pcap
from .markdown_formatter import format_markdown

__all__ = ["format_html", "format_html_pcap", "format_markdown"]

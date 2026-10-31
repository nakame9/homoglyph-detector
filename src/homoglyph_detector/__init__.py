"""Detect homoglyph / IDN homograph look-alikes in domains, emails, URLs and names."""
from .analyzer import Finding, Report, analyze
from .unicode_data import script_of, skeleton

__all__ = ["analyze", "Report", "Finding", "skeleton", "script_of"]
__version__ = "0.1.0"

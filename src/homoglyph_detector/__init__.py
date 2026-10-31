"""Detect homoglyph / IDN homograph look-alikes in domains, emails, URLs and names."""
from .analyzer import Finding, Report, analyze
from .unicode_data import confusable_type, restriction_level, script_of, skeleton

__all__ = ["analyze", "Report", "Finding", "skeleton", "script_of", "confusable_type", "restriction_level"]
__version__ = "0.3.0"

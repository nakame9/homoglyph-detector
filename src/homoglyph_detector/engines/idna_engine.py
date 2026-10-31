"""idna engine: IDNA2008 / UTS #46 validity, browser mapping, A-label <-> U-label round-trip."""
from __future__ import annotations

import unicodedata

import idna

from ..context import Context
from .base import EngineResult


def _idna_error(error: idna.IDNAError) -> tuple[str, str]:
    if isinstance(error, idna.IDNABidiError):
        return "idna_bidi", "breaks the IDNA bidi rule (RFC 5893)"
    if isinstance(error, idna.InvalidCodepointContext):
        return "idna_context", "breaks an IDNA contextual rule (RFC 5892 CONTEXTJ/CONTEXTO)"
    if isinstance(error, idna.InvalidCodepoint):
        return "idna_disallowed", "contains a code point IDNA2008 does not allow"
    if "too long" in str(error):
        return "idna_length", "exceeds DNS length limits (63 octets per label, 253 per domain)"
    return "idna_invalid", "is not a valid IDNA2008 domain name"


def idna_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("idna")
    if unicodedata.normalize("NFC", ctx.raw.strip()) != ctx.raw.strip():
        result.add("not_nfc", "low", "Input was not in Unicode NFC; normalised to NFC (same meaning)")
    if not ctx.host:
        return result.noisy_or()
    for label in ctx.host.split("."):
        if label.startswith("xn--"):
            try:
                result.add("punycode", "info", f"A-label '{label}' is the U-label '{idna.decode(label)}'")
            except idna.IDNAError:
                pass  # reported below through the lookup error
    if ctx.lookup_error:
        kind, why = _idna_error(ctx.lookup_error)
        result.add(kind, "medium", f"'{ctx.host}' {why}: {ctx.lookup_error}")
    elif ctx.strict_error:
        result.add("idna_mapped", "low", f"Not valid IDNA2008 as written ({ctx.strict_error}); browsers map it "
                   f"to '{ctx.resolved}'", mapped=ctx.resolved)
    if ctx.a_label and idna.encode(idna.decode(ctx.a_label)).decode("ascii") != ctx.a_label:
        result.add("idna_roundtrip", "medium",
                   f"'{ctx.a_label}' does not round-trip through its U-label '{idna.decode(ctx.a_label)}'")
    return result.noisy_or()

"""unicode engine: UTS #39 scripts, restriction levels, confusable / bidi / invisible characters."""
from __future__ import annotations

import unicodedata

from ..context import Context
from ..unicode_data import (LEVELS, confusable_type, is_allowed, is_bidi_control, is_default_ignorable,
                            is_single_script, numbering_systems, repeated_marks, restriction_level, script_of,
                            scripts_in, skeleton)
from .base import EngineResult, typed


def _check_characters(text: str, result: EngineResult, tld_scripts: set[str] = frozenset()) -> None:
    if unicodedata.normalize("NFKC", text) != text:
        result.add("compatibility", "medium",
                   "Contains compatibility characters (e.g. fullwidth) that normalise to other text",
                   nfkc=unicodedata.normalize("NFKC", text))

    for part in text.replace("@", ".").replace(" ", ".").split("."):
        level = restriction_level(part)
        if LEVELS.index(level) > LEVELS.index(result.facts["restriction_level"]):
            result.facts["restriction_level"] = level
        # Highly Restrictive (Latin + Han/Kana/Hangul, e.g. 'sonyストア') is normal CJK writing, not mixing
        if level in ("Moderately Restrictive", "Minimally Restrictive") or (
                level == "Unrestricted" and not is_single_script(part)):
            severity = "low" if level == "Moderately Restrictive" else "medium"
            result.add("mixed_script", severity,
                       f"'{part}' mixes scripts: {', '.join(sorted(scripts_in(part)))} (level: {level})",
                       scripts=sorted(scripts_in(part)), restriction_level=level)
        skel = skeleton(part)
        if not part.isascii() and skel.isascii() and skel != part:
            kind = confusable_type(part, skel)
            # Chromium's IDN policy: a Cyrillic word that happens to look Latin ('орех') is ordinary under a
            # Cyrillic TLD (.рф) and suspicious elsewhere; brand look-alikes are still caught by the brand engine
            expected = bool(tld_scripts) and scripts_in(part) <= tld_scripts
            # Latin letters with diacritics or ligatures ('mæglerhuset', 'borsaekranı') are ordinary words of
            # Danish, Turkish, ...; a Latin label that copies a brand ('ɑpple') is still caught by the brand engine
            latin = scripts_in(part) <= {"Latin"} and unicodedata.normalize("NFKC", part) == part
            result.add("whole_lookalike", "info" if expected or latin else "medium",
                       f"'{part}' renders like ASCII '{skel}'{typed(kind)}"
                       + (" (normal under a same-script TLD)" if expected else "")
                       + (" (ordinary Latin letters)" if latin and not expected else ""),
                       looks_like=skel, confusable_type=kind)
        if len(numbering_systems(part)) > 1:
            result.add("mixed_numbers", "medium", f"'{part}' mixes digits from different number systems")
        for mark in repeated_marks(part):
            result.add("hidden_overlay", "medium",
                       f"'{part}' stacks the same mark U+{ord(mark):04X} twice (can hide a character)")

    for pos, ch in enumerate(text):
        info = dict(position=pos, char=ch, codepoint=f"U+{ord(ch):04X}", script=script_of(ch))
        if is_bidi_control(ch):
            result.add("bidi_control", "high",
                       f"Position {pos}: bidi control U+{ord(ch):04X} {unicodedata.name(ch, '')} "
                       "can reorder how the text is displayed", **info)
        elif is_default_ignorable(ch):
            result.add("default_ignorable", "medium",
                       f"Position {pos}: invisible U+{ord(ch):04X} {unicodedata.name(ch, '')}", **info)
        elif ch.isascii():
            continue
        elif skeleton(ch).isascii() and skeleton(ch) != ch:
            # info: a Cyrillic 'а' inside a Russian word is just Russian; the evidence is at label level
            result.add("confusable_char", "info",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} ({script_of(ch)}) looks like '{skeleton(ch)}'",
                       **info, looks_like=skeleton(ch))
        elif not is_allowed(ch) and ch != " ":
            result.add("restricted_char", "low",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} is outside the UTS #39 identifier profile",
                       **info)


def unicode_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("unicode", facts={"restriction_level": "ASCII-Only"})
    tld = ctx.text.rsplit(".", 1)[-1] if ctx.host and "." in ctx.text else ""
    _check_characters(ctx.text, result, scripts_in(tld) if not tld.isascii() else set())
    if ctx.local:
        _check_characters(ctx.local, result)
    return result.noisy_or()

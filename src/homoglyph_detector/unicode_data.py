"""Unicode UTS #39 building blocks: scripts, skeleton, restriction levels, confusable types.

Section numbers refer to https://www.unicode.org/reports/tr39/
"""
from __future__ import annotations

import bisect
import re
import unicodedata
from functools import cache
from typing import Iterable

from .integrity import DATA, read_verified  # noqa: F401  (DATA re-exported)

IGNORED_SCRIPTS = {"Common", "Inherited"}  # digits, '-', '.', combining marks: fit any script

# §5.1 augmented script sets: CJK writing systems combine several scripts.
AUGMENT = {
    "Han": {"Han_with_Bopomofo", "Japanese", "Korean"},
    "Hiragana": {"Japanese"}, "Katakana": {"Japanese"},
    "Hangul": {"Korean"}, "Bopomofo": {"Han_with_Bopomofo"},
}
CJK_SETS = {"Japanese", "Korean", "Han_with_Bopomofo"}
# UAX #31 Table 7, Recommended scripts (used by the Moderately Restrictive level).
RECOMMENDED = {
    "Arabic", "Armenian", "Bengali", "Bopomofo", "Cyrillic", "Devanagari", "Ethiopic", "Georgian",
    "Greek", "Gujarati", "Gurmukhi", "Han", "Hangul", "Hebrew", "Hiragana", "Kannada", "Katakana",
    "Khmer", "Lao", "Latin", "Malayalam", "Myanmar", "Oriya", "Sinhala", "Tamil", "Telugu",
    "Thaana", "Thai", "Tibetan",
}
LEVELS = ["ASCII-Only", "Single Script", "Highly Restrictive", "Moderately Restrictive",
          "Minimally Restrictive", "Unrestricted"]  # §5.2, most to least restrictive


def _data_lines(name: str):
    for line in read_verified(name).splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield [field.strip() for field in line.split(";")]


@cache
def _ranges(name: str) -> tuple[list[int], list[int], list[str]]:
    rows = sorted((int(lo, 16), int(hi or lo, 16), value)
                  for rng, value, *_ in _data_lines(name) for lo, _, hi in [rng.partition("..")])
    return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]


def _lookup(name: str, ch: str, default: str | None = None) -> str | None:
    starts, ends, values = _ranges(name)
    i = bisect.bisect_right(starts, ord(ch)) - 1
    return values[i] if i >= 0 and ord(ch) <= ends[i] else default


@cache
def _confusables() -> dict[str, str]:
    return {chr(int(src, 16)): "".join(chr(int(cp, 16)) for cp in target.split())
            for src, target, *_ in _data_lines("confusables.txt")}


@cache
def _script_names() -> dict[str, str]:
    return {short: long for _, short, long, *_ in _data_lines("ScriptAliases.txt")}


def script_of(ch: str) -> str:
    return _lookup("Scripts.txt", ch, "Unknown")


def script_extensions(ch: str) -> set[str]:
    scx = _lookup("ScriptExtensions.txt", ch)
    return {_script_names()[code] for code in scx.split()} if scx else {script_of(ch)}


def scripts_in(text: str) -> set[str]:
    return {script_of(ch) for ch in text} - IGNORED_SCRIPTS


def is_allowed(ch: str) -> bool:
    """§3.1 General Security Profile (IdentifierStatus.txt)."""
    return _lookup("IdentifierStatus.txt", ch) == "Allowed"


def is_default_ignorable(ch: str) -> bool:
    """Default_Ignorable_Code_Point: renders as nothing (zero-width space, soft hyphen, ...)."""
    return _lookup("DefaultIgnorable.txt", ch) is not None


def is_bidi_control(ch: str) -> bool:
    """Bidi_Control: reorders how surrounding text is displayed (e.g. U+202E RLO)."""
    return _lookup("BidiControl.txt", ch) is not None


def data_versions() -> dict[str, str | None]:
    """Unicode version each bundled data file declares in its header."""
    versions = {}
    for name in sorted(p.name for p in DATA.iterdir() if p.name.endswith(".txt")):
        match = re.search(r"Version: (\d+\.\d+\.\d+)|-(\d+\.\d+\.\d+)\.txt", read_verified(name)[:1000])
        versions[name] = match and (match[1] or match[2])
    return versions


def skeleton(text: str) -> str:
    """§4 skeleton: NFD -> drop default-ignorables -> map each char to its prototype -> NFD.

    Lower-cased at the end because domains are case-insensitive; this makes
    '0' (-> 'O') collide with 'o' as a human reader would expect.
    """
    table = _confusables()
    mapped = "".join(table.get(ch, ch) for ch in unicodedata.normalize("NFD", text) if not is_default_ignorable(ch))
    return unicodedata.normalize("NFD", mapped).lower()


def resolved_script_set(text: Iterable[str]) -> set[str] | None:
    """§5.1 intersection of every character's augmented Script_Extensions.

    None means ALL (only Common/Inherited characters); an empty set means mixed-script.
    """
    result = None
    for ch in text:
        scx = script_extensions(ch)
        if scx & IGNORED_SCRIPTS:
            continue
        augmented = scx.union(*(AUGMENT.get(s, set()) for s in scx))
        result = augmented if result is None else result & augmented
    return result


def is_single_script(text: Iterable[str]) -> bool:
    resolved = resolved_script_set(text)
    return resolved is None or bool(resolved)


def restriction_level(text: str) -> str:
    """§5.2 Restriction Level of an identifier (one domain label, one word)."""
    if not all(is_allowed(ch) for ch in text):
        return "Unrestricted"
    if text.isascii():
        return "ASCII-Only"
    if is_single_script(text):
        return "Single Script"
    # What is left after removing Latin must be one script (Highly / Moderately Restrictive).
    rest = resolved_script_set(ch for ch in text if "Latin" not in script_extensions(ch)) or set()
    if rest & CJK_SETS:
        return "Highly Restrictive"
    if rest & (RECOMMENDED - {"Cyrillic", "Greek"}):
        return "Moderately Restrictive"
    return "Minimally Restrictive"


def confusable_type(x: str, y: str) -> str | None:
    """§4 classification of two confusable strings, or None if they are not confusable."""
    if x == y or skeleton(x) != skeleton(y):
        return None
    if is_single_script(x + y):
        return "single-script"
    return "whole-script" if is_single_script(x) and is_single_script(y) else "mixed-script"


def numbering_systems(text: str) -> set[int]:
    """§5.3 mixed numbers: the zero code point of every decimal digit used."""
    return {ord(ch) - unicodedata.decimal(ch) for ch in text if unicodedata.category(ch) == "Nd"}


def repeated_marks(text: str) -> list[str]:
    """§5.4 hidden overlays: the same nonspacing mark twice on one base character."""
    run, found = [], []
    for ch in unicodedata.normalize("NFD", text):
        if unicodedata.category(ch) == "Mn":
            if ch in run:
                found.append(ch)
            run.append(ch)
        else:
            run = []
    return found

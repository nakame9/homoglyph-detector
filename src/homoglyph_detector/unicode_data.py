"""Unicode data: UTS #39 skeleton and per-character script lookup."""
from __future__ import annotations

import bisect
import unicodedata
from functools import cache
from importlib.resources import files

DATA = files("homoglyph_detector") / "data"
IGNORED_SCRIPTS = {"Common", "Inherited"}  # digits, '-', '.', combining marks


def _data_lines(name: str):
    for line in (DATA / name).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield [field.strip() for field in line.split(";")]


@cache
def _confusables() -> dict[str, str]:
    table = {}
    for src, target, *_ in _data_lines("confusables.txt"):
        table[chr(int(src, 16))] = "".join(chr(int(cp, 16)) for cp in target.split())
    return table


@cache
def _script_ranges() -> tuple[list[int], list[int], list[str]]:
    rows = []
    for rng, script in _data_lines("Scripts.txt"):
        lo, _, hi = rng.partition("..")
        rows.append((int(lo, 16), int(hi or lo, 16), script))
    rows.sort()
    return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]


def script_of(ch: str) -> str:
    starts, ends, names = _script_ranges()
    i = bisect.bisect_right(starts, ord(ch)) - 1
    return names[i] if i >= 0 and ord(ch) <= ends[i] else "Unknown"


def skeleton(text: str) -> str:
    """UTS #39 skeleton: NFD -> map every char to its prototype -> NFD.

    Lower-cased at the end because domains are case-insensitive; this makes
    '0' (-> 'O') collide with 'o' as a human reader would expect.
    """
    table = _confusables()
    mapped = "".join(table.get(ch, ch) for ch in unicodedata.normalize("NFD", text))
    return unicodedata.normalize("NFD", mapped).lower()


def scripts_in(text: str) -> set[str]:
    return {script_of(ch) for ch in text} - IGNORED_SCRIPTS

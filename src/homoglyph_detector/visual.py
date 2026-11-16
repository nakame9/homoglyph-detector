"""ASCII visual confusable detection: look-alikes made only of domain characters (a-z 0-9 -).

A. character substitution        5hopee   ~ shopee    (5 -> s), gmăįl ~ gmail (accents dropped)
B. multi-character substitution  vvhatsapp ~ whatsapp (vv -> w), clropbox ~ dropbox (cl -> d)
C. visual similarity scoring     weighted edit distance where a look-alike substitution
                                 costs (1 - similarity) and any other edit costs 1.

Pairs UTS #39 calls identical (0/o, 1/l, m/rn) come from confusables.txt and cost 0.
NEAR only lists pairs Unicode does not cover because they are similar, not identical;
tests/test_visual.py checks it never overlaps the official data.
"""
from __future__ import annotations

import string
import unicodedata
from functools import cache
from typing import NamedTuple

from .unicode_data import _confusables, skeleton

DOMAIN_CHARS = set(string.ascii_lowercase + string.digits + "-")
MAX_VISUAL_DISTANCE = 0.5  # at most "half a character" of visible difference
ACCENT_COST = 0.2          # an accent on a familiar letter (ž, ă, ľ) is easy to miss, like the i/l pair

# similarity in (0, 1): 1 would mean identical, so cost = 1 - similarity
NEAR = {
    # A. one character for another
    ("i", "l"): 0.8, ("i", "1"): 0.8, ("i", "j"): 0.7,
    ("s", "5"): 0.7, ("z", "2"): 0.6, ("b", "6"): 0.6, ("g", "9"): 0.6, ("q", "9"): 0.6,
    ("g", "q"): 0.7, ("e", "c"): 0.6, ("u", "v"): 0.7, ("b", "d"): 0.5, ("n", "m"): 0.4,
    # B. several characters for one
    ("vv", "w"): 0.9, ("cl", "d"): 0.9, ("nn", "m"): 0.7, ("ii", "u"): 0.6,
}


class VisualMatch(NamedTuple):
    score: float        # 1 - distance / longest length; 1.0 = renders the same
    distance: float     # weighted edit distance
    edits: list[str]    # e.g. ["5->s", "vv->w"]; identical pairs included, plain typos as "+x" / "-x" / "x->y"


@cache
def _costs() -> dict[tuple[str, str], float]:
    costs = {}
    for (x, y), similarity in NEAR.items():
        costs[x, y] = costs[y, x] = round(1 - similarity, 3)
    for src, target in _confusables().items():   # official identical pairs: 0/o, 1/l, m/rn
        x, y = src, target.lower()
        if src.islower() or src.isdigit():       # 'I' -> 'l' only holds in upper case
            if x != y and set(x + y) <= DOMAIN_CHARS:
                costs[x, y] = costs[y, x] = 0.0
    return costs


@cache
def _cheap_pairs() -> dict[str, list[tuple[str, str, int]]]:
    by_first: dict[str, list[tuple[str, str, int]]] = {}
    for (source, target), cost in _costs().items():
        if cost < 1:
            by_first.setdefault(source[0], []).append((source, target, round(cost * 1000)))
    return by_first


def _visual_text(value: str) -> tuple[str, int]:
    if value.isascii():
        return value, 0
    skel = skeleton(value)
    plain = "".join(ch for ch in skel if unicodedata.category(ch) != "Mn")
    return plain, len(skel) - len(plain)


def can_score_visually(a: str, b: str) -> bool:
    """Test whether the alignment can cost less than one edit before computing its details."""
    a, accents = _visual_text(a)
    # An insertion, deletion or ordinary substitution costs 1 and cannot give a positive engine score.
    # ponytail: search the cheap alignments only; compute the exact match only for candidates worth scoring.
    pending = [(0, 0, 1000 - round(1000 * ACCENT_COST * accents))]
    visited: dict[tuple[int, int], int] = {}
    pairs = _cheap_pairs()
    while pending:
        i, j, budget = pending.pop()
        if budget <= visited.get((i, j), 0):
            continue
        visited[i, j] = budget
        if i == len(a) or j == len(b):
            if i == len(a) and j == len(b):
                return True
            continue
        if a[i] == b[j]:
            pending.append((i + 1, j + 1, budget))
        for source, target, cost in pairs.get(a[i], ()):
            if cost < budget and a.startswith(source, i) and b.startswith(target, j):
                pending.append((i + len(source), j + len(target), budget - cost))
    return False


def visual_similarity(a: str, b: str) -> VisualMatch:
    """How alike text `a` looks to the lower-case ASCII reference `b` (weighted Levenshtein with
    multi-character pairs). Non-ASCII `a` is read as a hurried reader would: its UTS #39 skeleton
    without accents, each dropped accent costing ACCENT_COST."""
    a, accents = _visual_text(a)
    costs = _costs()
    multi = [(x, y, c) for (x, y), c in costs.items() if len(x) > 1 or len(y) > 1]
    inf = float("inf")
    dist = [[inf] * (len(b) + 1) for _ in range(len(a) + 1)]
    back: list[list[tuple[int, int, str] | None]] = [[None] * (len(b) + 1) for _ in range(len(a) + 1)]
    dist[0][0] = 0.0
    for i in range(len(a) + 1):
        for j in range(len(b) + 1):
            options = []
            if i:
                options.append((dist[i - 1][j] + 1, (i - 1, j, f"-{a[i - 1]}")))
            if j:
                options.append((dist[i][j - 1] + 1, (i, j - 1, f"+{b[j - 1]}")))
            if i and j:
                x, y = a[i - 1], b[j - 1]
                cost = 0.0 if x == y else costs.get((x, y), 1.0)
                options.append((dist[i - 1][j - 1] + cost, (i - 1, j - 1, "" if x == y else f"{x}->{y}")))
            for x, y, cost in multi:
                if i >= len(x) and j >= len(y) and a[i - len(x):i] == x and b[j - len(y):j] == y:
                    options.append((dist[i - len(x)][j - len(y)] + cost, (i - len(x), j - len(y), f"{x}->{y}")))
            if options:
                dist[i][j], back[i][j] = min(options, key=lambda option: option[0])

    edits, i, j = [], len(a), len(b)
    while back[i][j]:
        i, j, edit = back[i][j]
        if edit:
            edits.append(edit)
    distance = round(dist[len(a)][len(b)] + ACCENT_COST * accents, 3)
    edits = [f"{accents} accent(s)"] * bool(accents) + edits[::-1]
    return VisualMatch(round(max(0.0, 1 - distance / max(len(a), len(b), 1)), 3), distance, edits)

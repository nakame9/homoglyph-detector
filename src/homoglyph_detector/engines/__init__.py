"""Independent detection engines: one file per engine, all with the same signature

    engine(ctx: Context, brands: list[dict]) -> EngineResult   (score 0..1 + findings)

    unicode     unicode_engine.py     UTS #39 scripts, restriction levels, bidi / invisible characters
    idna        idna_engine.py        IDNA2008 / UTS #46 validity, mapping, round-trip
    brand       brand_engine.py       skeleton homographs and one-edit typosquats of protected brands
    combosquat  combosquat_engine.py  a brand name on an unofficial domain
    visual      visual_engine.py      ASCII / accent visual look-alikes, continuous similarity

No engine reads another engine's output; scoring.py fuses their scores with calibrated weights.
Adding or changing an engine changes the scores: re-run benchmark/calibrate.py (see docs/bao-tri.md).
"""
from .base import SEVERITY_WEIGHT, EngineResult, Finding, is_official
from .brand_engine import brand_engine
from .combosquat_engine import combosquat_engine
from .idna_engine import idna_engine
from .unicode_engine import unicode_engine
from .visual_engine import visual_engine

ENGINES = {"unicode": unicode_engine, "idna": idna_engine, "brand": brand_engine,
           "combosquat": combosquat_engine, "visual": visual_engine}

__all__ = ["ENGINES", "SEVERITY_WEIGHT", "EngineResult", "Finding", "is_official"]

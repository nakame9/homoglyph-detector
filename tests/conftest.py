"""Hypothesis profiles, chosen with HYPOTHESIS_PROFILE:

    dev   (default) 150 random examples per property, different every run
    ci    400 examples, deterministic so a CI failure reproduces
    deep  2000 examples, for bug hunting before a release
"""
import os

from hypothesis import HealthCheck, settings

COMMON = dict(deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("dev", max_examples=150, **COMMON)
settings.register_profile("ci", max_examples=400, derandomize=True, print_blob=True, **COMMON)
settings.register_profile("deep", max_examples=2000, **COMMON)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))

"""Compatibility checks for the bundled Unicode data.

Run after scripts/update_unicode_data.py: they fail if a new Unicode release changes a
file format, renames a script, or leaves the data files on different versions.
"""
from homoglyph_detector.unicode_data import (AUGMENT, IGNORED_SCRIPTS, RECOMMENDED, _confusables, _ranges,
                                             _script_names, data_versions, is_bidi_control,
                                             is_default_ignorable, skeleton)


def test_all_files_are_one_unicode_version():
    versions = data_versions()
    assert len(versions) == 7 and None not in versions.values(), versions
    assert len(set(versions.values())) == 1, versions


def test_confusable_prototypes_map_to_themselves():
    # UTS #39 builds the mapping so a prototype is never remapped; skeleton relies on it.
    table = _confusables()
    assert len(table) > 6000
    assert not [src for src, target in table.items() if any(table.get(ch, ch) != ch for ch in target)]


def test_every_script_code_has_a_name():
    codes = {code for value in _ranges("ScriptExtensions.txt")[2] for code in value.split()}
    assert codes <= set(_script_names())


def test_script_names_used_by_the_spec_exist():
    assert set(AUGMENT) | RECOMMENDED | IGNORED_SCRIPTS <= set(_ranges("Scripts.txt")[2])


def test_identifier_profile_parsed():
    statuses = set(_ranges("IdentifierStatus.txt")[2])
    assert statuses == {"Allowed"}


def test_property_files():
    for ch in "\u200b\u00ad\ufe0f\u115f\u2060":   # ZWSP, soft hyphen, VS16, Hangul filler, word joiner
        assert is_default_ignorable(ch)
    assert not is_default_ignorable("a") and not is_bidi_control("a")
    bidi = [chr(cp) for cp in range(0x110000) if is_bidi_control(chr(cp))]
    assert "\u202e" in bidi and "\u2066" in bidi
    assert all(is_default_ignorable(ch) for ch in bidi)   # bidi controls are invisible too


def test_known_skeletons():
    # Well-known confusables that must survive any data update.
    assert skeleton("p\u0430ypal") == skeleton("paypal")
    assert skeleton("\u0441\u0440\u0430") == skeleton("cpa")   # Cyrillic сра vs Latin cpa
    assert skeleton("rn") == skeleton("m")

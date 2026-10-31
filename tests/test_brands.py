import copy
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from homoglyph_detector import analyze, integrity
from homoglyph_detector.brands import BrandDBError, bundled, load, resolve, validate
from homoglyph_detector.cli import DATA_ERROR, main
from homoglyph_detector.integrity import DataIntegrityError, read_verified, sha256, verify_all
from homoglyph_detector.scoring import calibration

ROOT = Path(__file__).resolve().parents[1]
ACME = {"schema": 1, "name": "ACME Bank brands", "version": "1.2.0", "updated": "2026-10-31",
        "brands": [{"id": "acmebank", "name": "ACME Bank", "category": "banking", "country": "VN",
                    "domains": ["acmebank.vn", "acme-bank.com.vn"], "keywords": ["acmebank"]}]}


def write_db(tmp_path, db, name="brands.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(db), "utf-8")
    return str(path)


# --- bundled database: versioned and pinned ---------------------------------------

def test_bundled_database_is_versioned_and_verified():
    db = bundled()
    assert db.verification == "manifest" and db.source == "bundled"
    assert db.version.count(".") == 2 and len(db.sha256) == 64 and len(db.brands) >= 10
    assert integrity.manifest()["files"]["brands.json"]["version"] == db.version


def test_every_bundled_file_is_pinned_and_intact():
    assert set(verify_all().values()) == {"ok"}
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "seal_data.py"), "--check"], capture_output=True)
    assert result.returncode == 0, result.stderr


def test_calibration_was_fitted_on_the_bundled_brands():
    assert calibration()["brands"]["sha256"] == bundled().sha256


@pytest.fixture
def tampered_data(tmp_path, monkeypatch):
    for item in integrity.DATA.iterdir():
        shutil.copy(str(item), tmp_path / item.name)
    monkeypatch.setattr(integrity, "DATA", tmp_path)
    integrity.manifest.cache_clear()
    yield tmp_path
    integrity.manifest.cache_clear()


def test_tampered_allow_list_is_refused(tampered_data):
    path = tampered_data / "brands.json"
    path.write_text(path.read_text("utf-8").replace('["paypal.com"]', '["paypal.com", "paypal-secure-login.com"]'), "utf-8")
    with pytest.raises(DataIntegrityError, match="does not match its SHA-256"):
        read_verified("brands.json")
    assert verify_all()["brands.json"] != "ok"


def test_unlisted_data_file_is_refused(tampered_data):
    (tampered_data / "extra.txt").write_text("x", "utf-8")
    with pytest.raises(DataIntegrityError, match="not listed"):
        read_verified("extra.txt")


def test_seal_refuses_a_change_without_a_version_bump(tampered_data):
    spec = importlib.util.spec_from_file_location("seal_data", ROOT / "scripts" / "seal_data.py")
    seal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seal)
    seal.DATA, seal.MANIFEST = tampered_data, tampered_data / "MANIFEST.json"
    db = json.loads((tampered_data / "brands.json").read_text("utf-8"))
    db["brands"][0]["keywords"].append("appleid")
    (tampered_data / "brands.json").write_text(json.dumps(db), "utf-8")
    assert seal.main([]) == 1                      # same version: refused
    db["version"] = "1.0.1"
    (tampered_data / "brands.json").write_text(json.dumps(db), "utf-8")
    assert seal.main([]) == 0 and seal.main(["--check"]) == 0


# --- external databases: pinning, merging, overriding -----------------------------

def test_organisation_database_is_merged_and_detected(tmp_path):
    path = write_db(tmp_path, ACME)
    report = analyze("acrnebank.vn", (path,))
    assert report.verdict == "MALICIOUS"
    assert [db["name"] for db in report.brand_db] == ["homoglyph-detector default brands", "ACME Bank brands"]
    assert report.brand_db[1]["verification"] == "unpinned"
    assert analyze("acmebank.vn", (path,)).verdict == "SAFE"


def test_pinning(tmp_path):
    path = write_db(tmp_path, ACME)
    digest = sha256(Path(path).read_bytes())
    assert load((f"{path}#sha256={digest}",))[1][1].verification == "pinned"
    with pytest.raises(DataIntegrityError, match="expected"):
        load((f"{path}#sha256={'0' * 64}",))


def test_later_database_overrides_by_id(tmp_path):
    db = copy.deepcopy(ACME)
    db["brands"] = [{"id": "paypal", "name": "PayPal", "domains": ["paypal.com", "paypal-business.example"],
                     "keywords": ["paypal"]}]
    brands, _ = load((write_db(tmp_path, db),))
    assert next(b for b in brands if b["id"] == "paypal")["domains"] == ["paypal.com", "paypal-business.example"]


def test_a_domain_cannot_belong_to_two_brands(tmp_path):
    db = copy.deepcopy(ACME)
    db["brands"][0]["domains"].append("paypal.com")   # an org database claiming someone else's domain
    with pytest.raises(BrandDBError, match="claimed by both"):
        load((write_db(tmp_path, db),))


def test_environment_variable_and_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMOGLYPH_BRANDS", "env.json")
    assert resolve(("cli.json",)) == ("env.json", "cli.json")   # command line comes last and wins


def test_cli_exit_codes_for_data_problems(tmp_path, capsys):
    path = write_db(tmp_path, ACME)
    assert main(["paypal.com", "--brands", f"{path}#sha256=bad"]) == DATA_ERROR
    assert main(["paypal.com", "--brands", str(tmp_path / "missing.json")]) == DATA_ERROR
    assert main(["--verify", "--brands", path]) == 0
    assert "[unpinned]" in capsys.readouterr().out


# --- validation -------------------------------------------------------------------

@pytest.mark.parametrize("change, message", [
    (lambda db: db["brands"][0]["domains"].append("github.io"), "public suffix"),   # would allow-list all of github.io
    (lambda db: db["brands"][0]["domains"].append("com.vn"), "public suffix"),
    (lambda db: db["brands"][0]["domains"].append("Acme.vn"), "lower-case"),
    (lambda db: db["brands"][0]["domains"].append("-acme.vn"), "not a valid IDNA2008"),
    (lambda db: db["brands"][0]["keywords"].append("ab"), "keyword"),
    (lambda db: db["brands"][0]["keywords"].append("\u0430cme"), "keyword"),        # Cyrillic a
    (lambda db: db["brands"].append(copy.deepcopy(db["brands"][0])), "duplicate id"),
    (lambda db: db["brands"].append({**copy.deepcopy(db["brands"][0]), "id": "other"}), "already claimed"),
    (lambda db: db.update(version="1.2"), "version"),
    (lambda db: db.update(updated="31/10/2026"), "updated"),
    (lambda db: db.update(schema=2), "schema"),
    (lambda db: db.update(brands=[]), "non-empty"),
])
def test_validation_rejects(change, message):
    db = copy.deepcopy(ACME)
    change(db)
    with pytest.raises(BrandDBError, match=message):
        validate(db, "test")


def test_validation_accepts_the_example():
    validate(copy.deepcopy(ACME), "test")

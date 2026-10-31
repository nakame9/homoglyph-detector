import json

import pytest

from homoglyph_detector import analyze
from homoglyph_detector.cli import main
from homoglyph_detector.scoring import (calibration, custom_profile, operating_curve, profile,
                                         threshold_for_fpr, verdict)

LABELS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1]
PROBS = [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.5, 0.9, 0.5, 0.9, 0.9, 0.95]


def test_operating_curve_and_threshold_selection():
    curve = operating_curve(LABELS, PROBS)
    # thresholds sit halfway between distinct scores
    assert [pt["threshold"] for pt in curve] == [0.0, 0.3, 0.7, 0.925, 1.0]
    assert threshold_for_fpr(1.0, curve) == 0.3      # 2 false alerts out of 8 is fine: catch everything
    assert threshold_for_fpr(0.125, curve) == 0.7    # one false alert allowed
    assert threshold_for_fpr(0.0, curve) == 0.925    # no false alert at all
    budgets = [0.0, 0.125, 0.25, 1.0]                # a smaller budget never lowers the threshold
    thresholds = [threshold_for_fpr(b, curve) for b in budgets]
    assert thresholds == sorted(thresholds, reverse=True)


def test_builtin_profiles_meet_their_targets_on_the_train_split():
    model = calibration()
    curve = {pt["threshold"]: pt for pt in model["operating_curve"]}
    assert set(model["profiles"]) >= {"default", "banking", "browser"}
    for name, pr in model["profiles"].items():
        assert 0 <= pr["suspicious"] <= pr["malicious"] <= 1, name
        for level in ("suspicious", "malicious"):
            target = pr["targets"][level]
            if "max_fpr" in target:
                assert curve[pr[level]]["fpr"] <= target["max_fpr"], (name, level)
            else:
                assert pr[level] == target["probability"]


def test_profiles_order_environments_by_strictness():
    banking, default, browser = (profile(n) for n in ("banking", "default", "browser"))
    assert banking["suspicious"] <= default["suspicious"] <= browser["suspicious"]
    assert banking["test"]["suspicious"]["recall"] >= browser["test"]["suspicious"]["recall"]
    assert browser["test"]["suspicious"]["false_alerts_per_10k"] < banking["test"]["suspicious"]["false_alerts_per_10k"]


def test_same_domain_different_environments():
    """A combosquat is a review item by default, blocked in banking, and not worth a browser warning."""
    verdicts = {name: analyze("paypal-login.com", policy=name).verdict for name in ("default", "banking", "browser")}
    assert verdicts == {"default": "SUSPICIOUS", "banking": "MALICIOUS", "browser": "SAFE"}
    for name in ("default", "banking", "browser"):     # a real homograph is caught everywhere
        assert analyze("p\u0430ypal.com", policy=name).verdict == "MALICIOUS"


def test_report_records_the_policy():
    report = analyze("paypal-login.com", policy="browser")
    assert report.profile == "browser"
    assert report.thresholds == {"suspicious": profile("browser")["suspicious"],
                                 "malicious": profile("browser")["malicious"]}
    assert verdict(report.probability, profile("browser")) == report.verdict


def test_custom_alert_budget():
    policy = custom_profile(0.01, 0.001)
    assert policy["suspicious"] == threshold_for_fpr(0.01) and policy["malicious"] == threshold_for_fpr(0.001)
    assert analyze("paypal-login.com", policy=policy).profile.startswith("custom")
    with pytest.raises(ValueError):
        custom_profile(0.001, 0.01)        # MALICIOUS may not tolerate more false alerts than SUSPICIOUS
    with pytest.raises(ValueError):
        custom_profile(2.0, 0.1)


def test_profile_from_environment(monkeypatch):
    monkeypatch.setenv("HOMOGLYPH_PROFILE", "banking")
    assert profile()["name"] == "banking" and analyze("paypal-login.com").profile == "banking"
    monkeypatch.setenv("HOMOGLYPH_PROFILE", "nope")
    with pytest.raises(ValueError, match="unknown risk profile"):
        profile()


def test_cli_policies(capsys):
    assert main(["paypal-login.com", "--profile", "banking"]) == 2
    assert main(["paypal-login.com", "--profile", "browser"]) == 0
    assert main(["paypal-login.com", "--max-fpr", "0.05,0.02"]) == 2
    assert main(["--profiles"]) == 0
    capsys.readouterr()
    main(["paypal-login.com", "--profile", "browser", "--json"])
    assert json.loads(capsys.readouterr().out)[0]["profile"] == "browser"
    for bad in (["x.com", "--profile", "nope"], ["x.com", "--max-fpr", "abc"],
                ["x.com", "--profile", "banking", "--max-fpr", "0.1,0.01"]):
        with pytest.raises(SystemExit):
            main(bad)

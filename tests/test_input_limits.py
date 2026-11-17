import io
import json
import sys

import pytest

from homoglyph_detector import analyze
from homoglyph_detector import cli
from homoglyph_detector.analyzer import ENGINES
from homoglyph_detector.cli import main
from homoglyph_detector.context import MAX_INPUT_LENGTH
from homoglyph_detector.visual import can_score_visually, visual_similarity


def test_api_checks_raw_length_before_running_engines(monkeypatch):
    prefix = "https://example.org/"
    url = prefix + "\u00e9" * (MAX_INPUT_LENGTH - len(prefix))
    assert len(url) == MAX_INPUT_LENGTH
    assert analyze(url).parse_status == "ok"

    def fail(*args):
        raise AssertionError("oversized inputs must not reach an engine")

    monkeypatch.setitem(ENGINES, "visual", fail)
    report = analyze(url + " ", base_rate=0.001)
    assert (report.parse_status, report.parse_reason, report.verdict) == ("unsupported", "too_long", "SUSPICIOUS")
    assert report.input == report.target == report.skeleton == ""
    assert report.risk_score == 0 and report.probability_at_base_rate is None


def test_cli_drains_an_oversized_line_and_keeps_following_lines(tmp_path, monkeypatch, capsys):
    class BoundedStdin(io.StringIO):
        def readline(self, size=-1):
            assert 0 < size <= MAX_INPUT_LENGTH + 2
            return super().readline(size)

    oversized = "https://example.org/" + "a" * (MAX_INPUT_LENGTH * 40)
    prefix = "https://example.org/"
    at_limit = prefix + "a" * (MAX_INPUT_LENGTH - len(prefix))
    lines = "#" + "a" * (MAX_INPUT_LENGTH * 3) + "\r\n" + at_limit + "\r\n" + oversized + "\r\nhttps://example.org/"
    path = tmp_path / "inputs.txt"
    path.write_bytes(lines.encode("utf-8"))
    for source in (str(path), "-"):
        monkeypatch.setattr(sys, "stdin", BoundedStdin(lines))
        assert main(["--json", "-f", source]) == 1
        rows = json.loads(capsys.readouterr().out)
        assert [row["parse_status"] for row in rows] == ["ok", "unsupported", "ok"]
        assert rows[0]["input"] == at_limit and rows[2]["input"] == "https://example.org/"
        assert rows[1]["parse_reason"] == "too_long" and rows[1]["input"] == ""

    assert main([oversized, "https://payp\u0430l.com/"]) == 2
    shown = capsys.readouterr().out
    assert "unsupported (too_long)" in shown and oversized not in shown


def test_batch_input_limit_applies_to_arguments_and_file_together(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "MAX_BATCH_INPUTS", 2)
    path = tmp_path / "inputs.txt"
    path.write_text("xn--pypal-4ve.com\n", encoding="utf-8")
    args = ["--json", "-f", str(path), "example.org"]
    assert main(args) == 2
    assert len(json.loads(capsys.readouterr().out)) == 2
    assert main(args + ["paypal.com"]) == cli.DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == "" and "batch exceeds 2 inputs" in captured.err


@pytest.mark.parametrize("prefix", ["", "#", " "])
def test_batch_character_limit_counts_drained_and_skipped_lines(monkeypatch, capsys, prefix):
    monkeypatch.setattr(cli, "MAX_BATCH_CHARACTERS", 2 * MAX_INPUT_LENGTH)
    monkeypatch.setattr(sys, "stdin", io.StringIO("example.org\n" + prefix + " " * (3 * MAX_INPUT_LENGTH)))
    assert main(["-f", "-"]) == cli.DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == "" and "batch exceeds" in captured.err


def test_batch_accepts_the_exact_character_limit(monkeypatch, capsys):
    text = "# comment\nexample.org\n"
    monkeypatch.setattr(cli, "MAX_BATCH_CHARACTERS", len(text) + len("apple.com"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    assert main(["--json", "-f", "-", "apple.com"]) == 0
    assert [row["input"] for row in json.loads(capsys.readouterr().out)] == ["apple.com", "example.org"]


@pytest.mark.parametrize("text,keyword", [
    ("rnicrosoft", "microsoft"),
    ("5hopee", "shopee"),
    ("vvhatsapp", "whatsapp"),
    ("gm\u0103\u012fl", "gmail"),
    ("paypa", "paypal"),
    ("x" * MAX_INPUT_LENGTH, "paypal"),
])
def test_visual_candidate_preserves_matches_below_one_edit(text, keyword):
    assert can_score_visually(text, keyword) == (visual_similarity(text, keyword).distance < 1)

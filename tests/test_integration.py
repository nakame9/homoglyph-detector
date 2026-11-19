import json

import pytest

from homoglyph_detector import analyze
from homoglyph_detector.cli import main
from homoglyph_detector.context import MAX_RAW_LENGTH


def test_integration_redacts_secrets_and_preserves_userinfo_evidence(capsys):
    raw = "https://paypal.com:USER_SECRET@apple.com:8443/PATH_SECRET?v=QUERY_SECRET#FRAGMENT_SECRET"
    assert main(["--integration-json", raw]) == 1
    output = capsys.readouterr().out
    assert "_SECRET" not in output
    record, = json.loads(output)
    assert record == analyze(raw).to_integration_dict()
    assert (record["schema_version"], record["input"], record["scheme"], record["host"], record["port"]) == (
        1, "https://apple.com:8443", "https", "apple.com", 8443)
    assert record["has_query"] and record["has_userinfo"]
    assert record["verdict"] == "SUSPICIOUS" and record["parse_status"] == "ok"
    assert {"kind": "brand_in_userinfo", "brand_id": "paypal"} in record["findings"]
    assert all(set(f) <= {"kind", "brand_id"} for f in record["findings"])


@pytest.mark.parametrize("raw", [
    "https://LOGIN_SECRET@HOST_SECRET:bad/PATH_SECRET?v=QUERY_SECRET#FRAGMENT_SECRET",
    "https://LOGIN_SECRET@apple.com%40HOST_SECRET/?v=QUERY_SECRET",
    "https://LOGIN_SECRET@\u202eapple.com/?v=QUERY_SECRET",
    "HOST_SECRET\x1b[2J.com",
    "LOCAL_SECRET@HOST_SECRET\x01.com",
    "https://example.org/" + "OVERSIZE_SECRET" * (MAX_RAW_LENGTH // 15 + 1),
])
def test_unscored_inputs_never_echo_secrets_or_change_verdict(raw, capsys):
    report = analyze(raw)
    assert main(["--integration-json", raw]) == (2 if report.verdict == "MALICIOUS" else 1)
    output = capsys.readouterr().out
    assert "_SECRET" not in output
    record, = json.loads(output)
    assert record["input"] is None and record["host"] is None and record["port"] is None
    assert (record["parse_status"], record["parse_reason"], record["verdict"]) == (
        report.parse_status, report.parse_reason, report.verdict)
    if report.parse_reason == "too_long":
        assert record["has_query"] is None and record["has_userinfo"] is None


@pytest.mark.parametrize("raw,destination,host,port,userinfo,query", [
    ("https://[::1]:8443/?q=QUERY_SECRET", "https://[::1]:8443", "::1", 8443, False, True),
    (r"https:\\example.org\@PATH_SECRET?custom=QUERY_SECRET", "https://example.org", "example.org", None, False, True),
    ("paypal.com%2FUSER_SECRET@apple.com/a", "http://apple.com", "apple.com", None, True, False),
    ("LOCAL_SECRET@example.org", "example.org", "example.org", None, False, False),
    ("DISPLAY_SECRET Example Name", None, None, None, False, False),
    ("https://@example.org:0/?#QUERY_SECRET", "https://example.org:0", "example.org", 0, True, True),
    ("https://0x7f.1/", "https://127.0.0.1", "127.0.0.1", None, False, False),
])
def test_destination_and_presence_flags_follow_the_analyzed_url(raw, destination, host, port, userinfo, query):
    record = analyze(raw).to_integration_dict()
    assert (record["input"], record["host"], record["port"]) == (destination, host, port)
    assert record["has_userinfo"] is userinfo and record["has_query"] is query
    assert "_SECRET" not in json.dumps(record)


def test_long_urls_keep_their_verdicts_and_batch_limits(capsys):
    benign = "https://www.paypal.com/?returnUri=" + "QUERY_SECRET" * 100
    attack = "https://payp\u0430l.com/" + "PATH_SECRET" * 180
    assert main(["--integration-json", benign, attack]) == 2
    rows = json.loads(capsys.readouterr().out)
    assert [r["verdict"] for r in rows] == ["SAFE", "MALICIOUS"]
    assert all(r["parse_status"] == "ok" for r in rows)
    assert "_SECRET" not in json.dumps(rows)
    assert main(["--integration-json", *(["example.org"] * 257)]) == 3
    captured = capsys.readouterr()
    assert captured.out == "" and "batch exceeds" in captured.err


def test_integration_file_reader_keeps_following_lines_and_mixed_exit_code(tmp_path, capsys):
    path = tmp_path / "inputs.txt"
    path.write_text("OVERSIZE_SECRET" * 600 + "\nhttps://example.org/\nhttps://\u202eapple.com/", encoding="utf-8")
    assert main(["--integration-json", "-f", str(path)]) == 2
    output = capsys.readouterr().out
    assert "_SECRET" not in output
    rows = json.loads(output)
    assert [r["parse_status"] for r in rows] == ["unsupported", "ok", "rejected"]
    assert [r["verdict"] for r in rows] == ["SUSPICIOUS", "SAFE", "MALICIOUS"]


def test_full_json_remains_available_and_output_flags_are_exclusive(capsys):
    raw = "https://paypal.com:USER_SECRET@apple.com/?custom=QUERY_SECRET"
    assert main(["--json", raw]) == 1
    report, = json.loads(capsys.readouterr().out)
    assert report["input"] == raw and "schema_version" not in report
    with pytest.raises(SystemExit) as error:
        main(["--json", "--integration-json", raw])
    assert error.value.code == 2

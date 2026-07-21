import json

from logsentinel_lite.cli import main


def test_json_output_and_never_fail_mode(tmp_path, capsys):
    log = tmp_path / "sample.log"
    log.write_text("ERROR operation failed\n", encoding="utf-8")

    code = main(
        ["scan", str(log), "--format", "json", "--fail-on", "never"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["status"] == "error"
    assert payload["summary"]["issues_found"] == 1


def test_default_error_threshold_returns_one(tmp_path):
    log = tmp_path / "sample.log"
    log.write_text("ERROR operation failed\n", encoding="utf-8")
    assert main(["scan", str(log)]) == 1


def test_critical_status_returns_two(tmp_path):
    log = tmp_path / "sample.log"
    log.write_text("CRITICAL service panic\n", encoding="utf-8")
    assert main(["scan", str(log)]) == 2


def test_warning_does_not_fail_default_error_threshold(tmp_path):
    log = tmp_path / "sample.log"
    log.write_text("WARNING service degraded\n", encoding="utf-8")
    assert main(["scan", str(log)]) == 0


def test_warning_threshold_returns_one(tmp_path):
    log = tmp_path / "sample.log"
    log.write_text("WARNING service degraded\n", encoding="utf-8")
    assert main(["scan", str(log), "--fail-on", "warning"]) == 1


def test_missing_file_returns_three(tmp_path, capsys):
    missing = tmp_path / "missing.log"
    code = main(["scan", str(missing)])
    error = capsys.readouterr().err

    assert code == 3
    assert "No such file" in error


def test_text_output_contains_summary(tmp_path, capsys):
    log = tmp_path / "sample.log"
    log.write_text("INFO service started\n", encoding="utf-8")
    code = main(["scan", str(log), "--fail-on", "never"])
    output = capsys.readouterr().out

    assert code == 0
    assert "Status: OK" in output
    assert "1 lines scanned" in output

import json

import pytest

from logsentinel_lite.analyzer import analyze_lines, load_patterns


def test_default_patterns_find_multiple_severities():
    report = analyze_lines(
        [
            "INFO startup complete\n",
            "WARNING disk degraded\n",
            "ERROR operation failed\n",
            "CRITICAL backup panic\n",
        ],
        source="sample.log",
        patterns=load_patterns(),
        checked_at="2026-01-01T00:00:00Z",
    )

    assert report["status"] == "critical"
    assert report["summary"]["items_checked"] == 4
    assert report["summary"]["issues_found"] == 3
    assert report["summary"]["by_severity"] == {
        "warning": 1,
        "error": 1,
        "critical": 1,
    }


def test_only_highest_severity_is_recorded_per_line():
    report = analyze_lines(
        ["CRITICAL error warning\n"],
        source="sample.log",
        patterns=load_patterns(),
    )

    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "critical"


def test_sensitive_values_are_redacted():
    report = analyze_lines(
        [
            "ERROR login failed for user@example.test "
            "from 192.0.2.10 token=demo-secret\n"
        ],
        source="sample.log",
        patterns=load_patterns(),
    )

    message = report["findings"][0]["message"]
    assert "user@example.test" not in message
    assert "192.0.2.10" not in message
    assert "demo-secret" not in message
    assert "<redacted-email>" in message
    assert "<redacted-ip>" in message
    assert "<redacted-secret>" in message


def test_redaction_can_be_disabled():
    line = "ERROR login failed for user@example.test from 192.0.2.10\n"
    report = analyze_lines(
        [line],
        source="sample.log",
        patterns=load_patterns(),
        redact=False,
    )

    assert "user@example.test" in report["findings"][0]["message"]
    assert "192.0.2.10" in report["findings"][0]["message"]


def test_empty_input_is_ok():
    report = analyze_lines([], source="empty.log", patterns=load_patterns())

    assert report["status"] == "ok"
    assert report["summary"]["items_checked"] == 0
    assert report["findings"] == []


def test_custom_patterns_can_replace_defaults(tmp_path):
    config = tmp_path / "patterns.json"
    config.write_text(
        json.dumps(
            {
                "include_defaults": False,
                "patterns": [
                    {
                        "name": "database-lock",
                        "severity": "warning",
                        "regex": "database locked",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = analyze_lines(
        [
            "ERROR ignored because defaults are disabled\n",
            "database locked\n",
        ],
        source="sample.log",
        patterns=load_patterns(config),
    )

    assert report["summary"]["issues_found"] == 1
    assert report["findings"][0]["category"] == "database-lock"


def test_invalid_pattern_severity_is_rejected(tmp_path):
    config = tmp_path / "patterns.json"
    config.write_text(
        json.dumps(
            {
                "patterns": [
                    {"name": "bad-rule", "severity": "emergency", "regex": "problem"}
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid severity"):
        load_patterns(config)


def test_invalid_regular_expression_is_rejected(tmp_path):
    config = tmp_path / "patterns.json"
    config.write_text(
        json.dumps(
            {
                "patterns": [
                    {"name": "bad-regex", "severity": "error", "regex": "["}
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid regex"):
        load_patterns(config)

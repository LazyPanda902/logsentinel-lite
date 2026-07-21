"""Core log analysis and redaction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Sequence

SEVERITY_RANK = {"ok": 0, "warning": 1, "error": 2, "critical": 3}

DEFAULT_PATTERN_DATA = (
    {
        "name": "critical-condition",
        "severity": "critical",
        "regex": r"\b(?:critical|fatal|panic)\b",
    },
    {
        "name": "authentication-failure",
        "severity": "error",
        "regex": (
            r"\b(?:authentication failed|login failed|invalid password|"
            r"invalid credentials)\b"
        ),
    },
    {
        "name": "access-denied",
        "severity": "error",
        "regex": r"\b(?:access denied|permission denied|unauthorized)\b",
    },
    {
        "name": "application-error",
        "severity": "error",
        "regex": r"\b(?:error|failed|failure|exception|traceback)\b",
    },
    {
        "name": "warning-condition",
        "severity": "warning",
        "regex": r"\b(?:warn(?:ing)?|degraded|retrying|timeout)\b",
    },
)

BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(token|api[_-]?key|password|passwd|secret)(\s*[:=]\s*)([^\s,;]+)"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class PatternRule:
    """A compiled detection rule."""

    name: str
    severity: str
    regex: re.Pattern[str]


def _compile_rule(item: object) -> PatternRule:
    if not isinstance(item, dict):
        raise ValueError("Each pattern must be a JSON object.")

    name = item.get("name")
    severity = item.get("severity")
    expression = item.get("regex")

    if not isinstance(name, str) or not name.strip():
        raise ValueError("Each pattern requires a non-empty name.")
    if severity not in {"warning", "error", "critical"}:
        raise ValueError(f"Pattern {name!r} has invalid severity {severity!r}.")
    if not isinstance(expression, str) or not expression:
        raise ValueError(f"Pattern {name!r} requires a regular expression.")

    try:
        compiled = re.compile(expression, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"Pattern {name!r} contains invalid regex: {exc}") from exc

    return PatternRule(name=name.strip(), severity=severity, regex=compiled)


def load_patterns(config_path: Path | None = None) -> tuple[PatternRule, ...]:
    """Load built-in patterns and optional custom JSON rules."""

    include_defaults = True
    custom_items: list[object] = []

    if config_path is not None:
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON configuration: {exc}") from exc

        if not isinstance(payload, dict):
            raise ValueError("Configuration root must be a JSON object.")

        include_defaults = payload.get("include_defaults", True)
        if not isinstance(include_defaults, bool):
            raise ValueError("include_defaults must be true or false.")

        custom_items = payload.get("patterns", [])
        if not isinstance(custom_items, list):
            raise ValueError("patterns must be a JSON array.")

    items: list[object] = []
    if include_defaults:
        items.extend(DEFAULT_PATTERN_DATA)
    items.extend(custom_items)

    if not items:
        raise ValueError("At least one detection pattern is required.")

    return tuple(_compile_rule(item) for item in items)


def redact_text(text: str) -> str:
    """Redact common sensitive values from report output."""

    result = BEARER_RE.sub("Bearer <redacted-secret>", text)
    result = SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted-secret>",
        result,
    )
    result = EMAIL_RE.sub("<redacted-email>", result)
    return IPV4_RE.sub("<redacted-ip>", result)


def _status_from_counts(counts: dict[str, int]) -> str:
    for severity in ("critical", "error", "warning"):
        if counts[severity]:
            return severity
    return "ok"


def analyze_lines(
    lines: Iterable[str],
    *,
    source: str,
    patterns: Sequence[PatternRule],
    redact: bool = True,
    checked_at: str | None = None,
) -> dict[str, object]:
    """Analyze log lines and return a serializable report."""

    findings: list[dict[str, object]] = []
    lines_scanned = 0
    counts = {"warning": 0, "error": 0, "critical": 0}

    for line_number, raw_line in enumerate(lines, start=1):
        lines_scanned += 1
        line = raw_line.rstrip("\r\n")
        matches = [rule for rule in patterns if rule.regex.search(line)]
        if not matches:
            continue

        selected = max(matches, key=lambda rule: SEVERITY_RANK[rule.severity])
        findings.append(
            {
                "line": line_number,
                "severity": selected.severity,
                "category": selected.name,
                "message": redact_text(line) if redact else line,
            }
        )
        counts[selected.severity] += 1

    timestamp = checked_at or (
        datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )

    return {
        "status": _status_from_counts(counts),
        "checked_at": timestamp,
        "source": source,
        "summary": {
            "items_checked": lines_scanned,
            "issues_found": len(findings),
            "by_severity": counts,
        },
        "findings": findings,
    }


def analyze_file(
    path: Path,
    *,
    patterns: Sequence[PatternRule],
    redact: bool = True,
) -> dict[str, object]:
    """Analyze one local text file."""

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return analyze_lines(
            handle,
            source=path.name,
            patterns=patterns,
            redact=redact,
        )

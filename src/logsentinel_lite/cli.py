"""Command-line interface for LogSentinel Lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .analyzer import SEVERITY_RANK, analyze_file, load_patterns


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="Review a local text log for operational and security signals.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Analyze one local text log")
    scan.add_argument("path", type=Path, help="Path to the local text log")
    scan.add_argument("--config", type=Path, help="Optional JSON pattern configuration")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--no-redact", action="store_true", help="Disable output redaction")
    scan.add_argument(
        "--fail-on",
        choices=("never", "warning", "error", "critical"),
        default="error",
        help="Return nonzero when this severity or higher is found",
    )
    return parser


def render_text(report: dict[str, object]) -> str:
    summary = report["summary"]
    findings = report["findings"]
    assert isinstance(summary, dict)
    assert isinstance(findings, list)

    lines = [
        f"Status: {str(report['status']).upper()}",
        f"Source: {report['source']}",
        f"Checked: {report['checked_at']}",
        (
            "Summary: "
            f"{summary['items_checked']} lines scanned, "
            f"{summary['issues_found']} findings"
        ),
    ]

    if findings:
        lines.extend(["", "Findings:"])
        for finding in findings:
            assert isinstance(finding, dict)
            lines.append(
                "  "
                f"line {finding['line']} "
                f"[{str(finding['severity']).upper()}] "
                f"{finding['category']}: {finding['message']}"
            )
    else:
        lines.append("No matching warning, error, or critical signals.")

    return "\n".join(lines)


def result_exit_code(status: str, fail_on: str) -> int:
    if fail_on == "never" or status == "ok":
        return 0
    if SEVERITY_RANK[status] < SEVERITY_RANK[fail_on]:
        return 0
    return 2 if status == "critical" else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = analyze_file(
            args.path,
            patterns=load_patterns(args.config),
            redact=not args.no_redact,
        )
    except (OSError, ValueError) as exc:
        print(f"logsentinel: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return result_exit_code(str(report["status"]), args.fail_on)

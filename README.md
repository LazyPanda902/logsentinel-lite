# LogSentinel Lite

[![CI](https://github.com/LazyPanda902/logsentinel-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/LazyPanda902/logsentinel-lite/actions/workflows/ci.yml)

LogSentinel Lite is a small, privacy-conscious command-line tool for reviewing local
text logs. It detects common operational and security signals, creates text or JSON
reports, and redacts common sensitive values before displaying findings.

## Capabilities

- Warning, error, and critical detection
- Authentication-failure and access-denied detection
- Custom JSON regular-expression rules
- Text and JSON reports
- Redaction of IPv4 addresses, email addresses, bearer tokens, passwords, tokens,
  API keys, and secret assignments
- Monitoring-friendly exit codes
- Python 3.11 and 3.12 CI
- Fake sample data and automated tests

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
logsentinel scan samples/example.log --fail-on never
```

Generate JSON:

```bash
logsentinel scan samples/example.log --format json --fail-on never
```

Use custom patterns:

```bash
logsentinel scan samples/example.log \
  --config config/patterns.example.json \
  --fail-on never
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | No finding met the configured failure threshold |
| `1` | Warning or error met the threshold |
| `2` | Critical finding met the threshold |
| `3` | Input, configuration, or file-reading error |

The default failure threshold is `error`.

## Privacy

LogSentinel Lite reads only the local file supplied on the command line. It does
not upload logs or call external services. Redaction is enabled by default.

Only fake sample data belongs in this public repository.

## Development checks

```bash
python -m ruff check .
python -m compileall -q src tests
python -m pytest
```

## Scope

The current version analyzes complete local text files. It does not provide live
tailing, remote collection, SIEM integration, or guaranteed detection of every
secret or incident.

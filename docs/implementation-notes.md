# Implementation Notes

## Architecture

- `analyzer.py`: pattern validation, file analysis, severity classification, redaction
- `cli.py`: arguments, text/JSON rendering, exit codes
- `tests/`: analyzer behavior, configuration validation, CLI behavior

## Design rules

- Standard-library runtime dependencies only
- No network calls or log uploads
- Redaction enabled by default
- One highest-severity finding per line
- Fake sample data only
- No claims for unimplemented features

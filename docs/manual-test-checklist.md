# Manual Test Checklist

- [ ] Fresh virtual-environment installation succeeds
- [ ] `logsentinel --help` works
- [ ] Text and JSON output work with the fake sample
- [ ] Sensitive values are redacted
- [ ] Custom patterns load
- [ ] Missing files return exit code 3
- [ ] Ruff, compilation, and pytest pass
- [ ] No private logs or real secrets are committed

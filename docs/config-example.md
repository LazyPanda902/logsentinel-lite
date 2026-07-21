# Configuration Example

LogSentinel Lite uses optional JSON pattern configuration.

See `config/patterns.example.json`.

Each rule requires:

- `name`
- `severity`: `warning`, `error`, or `critical`
- `regex`: a Python-compatible regular expression

Do not place passwords, tokens, private hostnames, customer data, or real
production logs in configuration examples.

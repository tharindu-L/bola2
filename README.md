# bola2

Automated, black-box, cross-session BOLA (Broken Object Level Authorization)
identification and exploitation framework for REST and GraphQL APIs.

Companion implementation for the dissertation *"Automated Identification and
Exploitation Framework for BOLA Vulnerability in Modern APIs"* (University of
Kelaniya, 2026). The core methodology (discover operations, authenticate two
principals, generate cross-user test cases, compare responses with a
deterministic oracle, produce evidence) follows Chapter 3 of the dissertation.
Automatic API discovery is an additive extension beyond the dissertation's
original OpenAPI/GraphQL-introspection scope, feeding the same unified
operation model and the same detection pipeline.

## Architecture

```
Discovery Layer (OpenAPI | GraphQL introspection | Automatic discovery)
                    |
        Unified Operation Model
                    |
   Authentication Manager -- Request Engine -- Identifier / Ownership Analysis
                    |
              BOLA Analyzer (deterministic oracle)
                    |
              Evidence / Report
```

- `bola_framework/models/` -- the unified `Operation`, `GraphQLSelection`, and
  `Finding` representations every other module reads and writes.
- `bola_framework/discovery/` -- `OpenApiDiscoverer`, `GraphQLIntrospectionDiscoverer`,
  `AutoDiscoverer`. Each produces `Operation` objects; none contains
  target-specific rules.
- `bola_framework/auth/` -- `AuthenticationManager` / `Principal`: parallel
  authenticated sessions (bearer token, cookie, basic, API-key header).
- `bola_framework/engine/` -- `RequestEngine` (REST + GraphQL execution),
  `identifier_detector` (generic ID heuristics), `ownership` (multi-signal
  ownership correlation), `graphql_builder` (AST -> query string).
- `bola_framework/analysis/` -- `response_diff` (field-level comparison) and
  `bola_analyzer` (the deterministic classification oracle).
- `bola_framework/reporting/` -- redacted JSON/Markdown report generation.
- `bola_framework/scanner.py` -- orchestrates the full pipeline.
- `bola_framework/cli.py` -- `bola-scan` entry point.

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

### Quick one-off scan (no config file)

For a fast run against an authorized test target, pass credentials directly
on the command line -- no YAML file needed:

```bash
python cli.py scan --target http://192.168.8.142:3000 \
    --user-a "usera@test.com" --pass-a "Password1!" \
    --user-b "userb@test.com" --pass-b "Password2!" \
    --id-a 1 --id-b 2 \
    --output ./juiceshop-spec-report.json -v
```

This authenticates both users against `<target>/rest/user/login` (OWASP
Juice Shop's login endpoint and response shape by default), then runs
auto-discovery against `<target>` since `--mode` was left at its default
(`auto`). Override the login shape and discovery mode for other targets:

```bash
python cli.py scan --target http://192.168.8.142:8888 \
    --mode openapi --spec-source http://192.168.8.142:8888/openapi.json \
    --login-path /api/auth/login --login-user-field email \
    --login-pass-field password --token-json-path token \
    --user-a "usera@test.com" --pass-a "Password1!" \
    --user-b "userb@test.com" --pass-b "Password2!" \
    --id-a 1 --id-b 2 \
    --output ./report.json -v
```

Run `python cli.py scan --help` for the full flag reference (GraphQL mode,
cookie/API-key auth schemes, timeout, write-verification toggle, etc).

### Repeatable scans (config file)

1. Copy `examples/scan_config.example.yaml`, point it at your authorized test
   target, and fill in credentials for two test principals ("User A",
   "User B").
2. Run:

```bash
bola-scan scan --config scan_config.yaml --mode openapi --spec-source ./openapi.json
bola-scan scan --config scan_config.yaml --mode graphql --spec-source http://target/graphql
bola-scan scan --config scan_config.yaml --mode auto --spec-source http://target/
```

`python cli.py scan --config scan_config.yaml` works identically to
`bola-scan scan --config ...` -- both call the same entry point.

Reports are written as `bola_report.json` and `bola_report.md`. The process
exits with status `1` if any `confirmed_bola` findings were produced, `0`
otherwise, so it can be wired into CI.

## Scope and ethics

Only use this against systems you are explicitly authorized to test. It does
not brute-force credentials, does not persist raw secrets (headers/bodies are
redacted before being written to disk), and does not perform any destructive
action beyond the minimal request needed to demonstrate and, where safe,
verify a finding.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

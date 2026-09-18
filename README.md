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

1. Copy `examples/scan_config.example.yaml`, point it at your authorized test
   target, and fill in credentials for two test principals ("User A",
   "User B").
2. Run:

```bash
bola-scan --config scan_config.yaml --mode openapi --source ./openapi.json
bola-scan --config scan_config.yaml --mode graphql --source http://target/graphql
bola-scan --config scan_config.yaml --mode auto --source http://target/
```

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

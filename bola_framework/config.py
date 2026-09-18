"""Scan configuration loading.

A scan config is a YAML/JSON file describing: discovery mode and its source,
the two (or more) principals and how to authenticate them, and run-level
options. Nothing here is application-specific -- it is filled in per target
by the operator at scan time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from bola_framework.auth.session_manager import AuthScheme, LoginSpec, Principal


@dataclass
class DiscoveryConfig:
    mode: str  # "openapi" | "graphql" | "auto"
    source: Optional[str] = None          # OpenAPI file/URL, or auto-discovery start URL
    graphql_endpoint: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: int = 60
    max_depth: int = 3
    min_confidence: float = 0.35


@dataclass
class ScanConfig:
    discovery: DiscoveryConfig
    principals: list[Principal]
    timeout: float = 15.0
    output_json: str = "bola_report.json"
    output_markdown: str = "bola_report.md"
    verify_writes: bool = True


def _principal_from_dict(label: str, data: dict) -> Principal:
    scheme = AuthScheme(data.get("scheme", "bearer_token"))
    login_spec = LoginSpec(
        scheme=scheme,
        login_url=data.get("login_url"),
        login_method=data.get("login_method", "POST"),
        login_payload=data.get("login_payload", {}),
        token_json_path=data.get("token_json_path"),
        static_token=data.get("static_token"),
        username=data.get("username"),
        password=data.get("password"),
        api_key_header_name=data.get("api_key_header_name", "X-API-Key"),
    )
    return Principal(
        label=label,
        login_spec=login_spec,
        user_id_hint=data.get("user_id_hint"),
    )


def load_scan_config(path: str) -> ScanConfig:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text) if text.lstrip().startswith("{") else yaml.safe_load(text)

    discovery_data = data.get("discovery", {})
    discovery = DiscoveryConfig(
        mode=discovery_data["mode"],
        source=discovery_data.get("source"),
        graphql_endpoint=discovery_data.get("graphql_endpoint"),
        base_url=discovery_data.get("base_url"),
        max_pages=discovery_data.get("max_pages", 60),
        max_depth=discovery_data.get("max_depth", 3),
        min_confidence=discovery_data.get("min_confidence", 0.35),
    )

    principals = [
        _principal_from_dict(label, pdata)
        for label, pdata in data.get("principals", {}).items()
    ]

    return ScanConfig(
        discovery=discovery,
        principals=principals,
        timeout=data.get("timeout", 15.0),
        output_json=data.get("output_json", "bola_report.json"),
        output_markdown=data.get("output_markdown", "bola_report.md"),
        verify_writes=data.get("verify_writes", True),
    )

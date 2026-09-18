"""Automatic API discovery backend.

Used when no OpenAPI document is available and GraphQL introspection is
disabled or not applicable. Crawls the externally observable surface of a
target (HTML links, forms, inline JavaScript, common well-known probe paths)
and classifies discovered URLs as likely API operations with a confidence
score, rather than assuming every page or link is an API endpoint.

This module contains no target-specific rules. It never special-cases a
particular application, path, or field name -- it only reasons about generic
structural signals (content-type of responses, path shape, presence of
placeholders, HTTP verbs implied by forms/JS, JSON-looking payloads).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from bola_framework.discovery.base import Discoverer
from bola_framework.models import (
    ApiType,
    DiscoverySource,
    HttpMethod,
    Operation,
    OperationType,
    Parameter,
    ParameterLocation,
    REST_METHOD_TO_OPERATION_TYPE,
)

logger = logging.getLogger(__name__)

# Generic, structural probe paths -- not tied to any specific application.
# These are conventional REST/GraphQL discovery locations recognized across
# the industry (OpenAPI hosting conventions, common GraphQL mount points),
# not assumptions about any one target's resource model.
_WELL_KNOWN_SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
)
_WELL_KNOWN_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphql/console")

# A path segment shaped like an identifier: digits, UUID, or a long opaque token.
_ID_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_-]{16,})$"
)

_JSON_CONTENT_TYPES = ("application/json", "application/vnd.api+json", "application/hal+json")

_API_PATH_HINTS_RE = re.compile(r"/(api|v[0-9]+|graphql|rest|service)(/|$)", re.IGNORECASE)


@dataclass
class _DiscoveredCandidate:
    method: str
    url: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    form_fields: list[str] = field(default_factory=list)


class AutoDiscoverer(Discoverer):
    """Crawl-based discovery of likely API operations from the externally
    observable surface of a running application."""

    def __init__(
        self,
        start_url: str,
        session: Optional[requests.Session] = None,
        max_pages: int = 60,
        max_depth: int = 3,
        min_confidence: float = 0.35,
        headers: Optional[dict] = None,
        timeout: float = 10.0,
        max_js_bundles: int = 20,
        max_js_bundle_bytes: int = 3_000_000,
    ):
        self.start_url = start_url.rstrip("/")
        self.session = session or requests.Session()
        if headers:
            self.session.headers.update(headers)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.min_confidence = min_confidence
        self.timeout = timeout
        self.max_js_bundles = max_js_bundles
        self.max_js_bundle_bytes = max_js_bundle_bytes

        self._origin = self._origin_of(self.start_url)
        self._visited_pages: set[str] = set()
        self._visited_js_bundles: set[str] = set()
        self._candidates: dict[tuple[str, str], _DiscoveredCandidate] = {}

    @staticmethod
    def _origin_of(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def discover(self) -> list[Operation]:
        self._probe_well_known_paths()
        self._crawl(self.start_url, depth=0)

        operations: list[Operation] = []
        for (method, url), candidate in self._candidates.items():
            if candidate.confidence < self.min_confidence:
                continue
            operations.append(self._candidate_to_operation(candidate))

        logger.info(
            "Automatic discovery visited %d pages, produced %d candidate operations "
            "(%d above confidence threshold)",
            len(self._visited_pages),
            len(self._candidates),
            len(operations),
        )
        return operations

    # -- probing -----------------------------------------------------------

    def _probe_well_known_paths(self) -> None:
        for spec_path in _WELL_KNOWN_SPEC_PATHS:
            url = urljoin(self._origin, spec_path)
            self._register_if_json(url)
        for gql_path in _WELL_KNOWN_GRAPHQL_PATHS:
            url = urljoin(self._origin, gql_path)
            self._probe_graphql_endpoint(url)

    def _probe_graphql_endpoint(self, url: str) -> None:
        try:
            resp = self.session.post(
                url, json={"query": "{__typename}"}, timeout=self.timeout
            )
        except requests.RequestException:
            return
        if resp.status_code < 500 and "application/json" in resp.headers.get(
            "content-type", ""
        ):
            try:
                data = resp.json()
            except ValueError:
                return
            if "data" in data or "errors" in data:
                self._add_candidate(
                    "POST",
                    url,
                    confidence=0.9,
                    signals=["graphql-endpoint-responds"],
                )

    def _register_if_json(self, url: str) -> None:
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException:
            return
        content_type = resp.headers.get("content-type", "")
        if resp.status_code == 200 and "json" in content_type:
            self._add_candidate(
                "GET", url, confidence=0.95, signals=["well-known-spec-path"]
            )

    # -- crawling ------------------------------------------------------------

    def _crawl(self, url: str, depth: int) -> None:
        if depth > self.max_depth or len(self._visited_pages) >= self.max_pages:
            return
        if url in self._visited_pages:
            return
        if self._origin_of(url) != self._origin:
            return  # never crawl off-origin; out of scope and could be unauthorized

        self._visited_pages.add(url)

        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException:
            return

        content_type = resp.headers.get("content-type", "")

        if any(ct in content_type for ct in _JSON_CONTENT_TYPES):
            self._classify_json_response(url, resp)
            return  # a JSON endpoint has no HTML links to follow

        if "text/html" not in content_type:
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        self._extract_links(soup, url, depth)
        self._extract_forms(soup, url)
        self._extract_js_references(soup, url)

    def _extract_links(self, soup: BeautifulSoup, base: str, depth: int) -> None:
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            absolute = urljoin(base, href)
            if absolute.startswith("mailto:") or absolute.startswith("javascript:"):
                continue
            if self._looks_like_api_path(absolute):
                self._add_candidate(
                    "GET", absolute, confidence=0.4, signals=["linked-api-shaped-path"]
                )
            self._crawl(absolute, depth + 1)

    def _extract_forms(self, soup: BeautifulSoup, base: str) -> None:
        for form in soup.find_all("form"):
            action = form.get("action") or base
            absolute = urljoin(base, action)
            method = (form.get("method") or "GET").upper()
            fields = [
                inp.get("name")
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            self._add_candidate(
                method,
                absolute,
                confidence=0.55,
                signals=["html-form"],
                form_fields=fields,
            )

    # String-literal path references inside JS source, e.g. fetch("/rest/x").
    _JS_PATH_LITERAL_RE = re.compile(r"""["'`](/[a-zA-Z0-9/_\-{}.]+)["'`]""")

    # Template-literal paths with interpolation, e.g. `/rest/basket/${id}` or
    # `/api/users/${userId}/profile`. This is the dominant way modern SPA
    # frameworks (Angular, React, Vue) build per-object API URLs, and it is
    # exactly the shape of the endpoints that matter most for BOLA testing --
    # the plain literal regex above cannot match these at all because of the
    # `$` and expression characters inside `${...}`. Each `${...}` segment is
    # replaced with a numeric sentinel so the normal path-templatizing logic
    # downstream turns it into a proper {paramN} placeholder.
    _JS_TEMPLATE_LITERAL_RE = re.compile(r"`(/[^`]*?\$\{[^`]*?)`")
    _TEMPLATE_INTERPOLATION_RE = re.compile(r"\$\{[^}]*\}")

    # Simple string concatenation, e.g. '/rest/basket/' + id or
    # "/api/users/" + userId + "/profile". Covers older/non-template-literal
    # JS that still builds per-object URLs dynamically.
    _JS_CONCAT_PREFIX_RE = re.compile(
        r"""["'](/[a-zA-Z0-9/_\-]*/)["']\s*\+\s*[a-zA-Z_$][\w$]*"""
    )

    def _extract_js_references(self, soup: BeautifulSoup, base: str) -> None:
        """Scan both inline <script> blocks and same-origin external JS bundles
        for API-shaped path string literals. Single-page applications (Angular,
        React, Vue, ...) typically render almost no server-side HTML and issue
        their real API calls from bundled JS, so external bundles are the
        primary discovery surface for those apps, not the initial HTML page.
        """
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                self._scan_external_js_bundle(urljoin(base, src))
            else:
                self._scan_js_text(script.string or "", base)

    def _scan_external_js_bundle(self, bundle_url: str) -> None:
        if bundle_url in self._visited_js_bundles:
            return
        if len(self._visited_js_bundles) >= self.max_js_bundles:
            return
        if self._origin_of(bundle_url) != self._origin:
            return  # never fetch third-party/CDN scripts; out of scope
        self._visited_js_bundles.add(bundle_url)

        try:
            resp = self.session.get(
                bundle_url, timeout=self.timeout, stream=True
            )
        except requests.RequestException:
            return
        if resp.status_code != 200:
            return

        content_type = resp.headers.get("content-type", "")
        if "javascript" not in content_type and not bundle_url.endswith(".js"):
            return

        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536, decode_unicode=False):
            total += len(chunk)
            if total > self.max_js_bundle_bytes:
                break
            chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="ignore")

        self._scan_js_text(text, bundle_url, signal="external-js-bundle-reference")

    def _scan_js_text(
        self, text: str, base: str, signal: str = "inline-js-reference"
    ) -> None:
        confidence = 0.3 if signal == "inline-js-reference" else 0.35

        for match in set(self._JS_PATH_LITERAL_RE.findall(text)):
            if self._looks_like_api_path(match):
                absolute = urljoin(base, match)
                self._add_candidate("GET", absolute, confidence=confidence, signals=[signal])

        # Template-literal paths carry a stronger signal than plain literals:
        # interpolation is itself evidence the path addresses a specific
        # object, which is exactly what BOLA testing needs.
        template_confidence = min(1.0, confidence + 0.15)
        for match in set(self._JS_TEMPLATE_LITERAL_RE.findall(text)):
            normalized = self._TEMPLATE_INTERPOLATION_RE.sub("1", match)
            if self._looks_like_api_path(normalized) or "1" in normalized:
                absolute = urljoin(base, normalized)
                self._add_candidate(
                    "GET",
                    absolute,
                    confidence=template_confidence,
                    signals=[f"{signal}-template-literal"],
                )

        for prefix in set(self._JS_CONCAT_PREFIX_RE.findall(text)):
            normalized = prefix + "1"
            absolute = urljoin(base, normalized)
            self._add_candidate(
                "GET",
                absolute,
                confidence=template_confidence,
                signals=[f"{signal}-string-concat"],
            )

    def _classify_json_response(self, url: str, resp: requests.Response) -> None:
        try:
            resp.json()
        except ValueError:
            return
        self._add_candidate(
            "GET", url, confidence=0.85, signals=["json-response-observed"]
        )

    # -- classification -------------------------------------------------------

    @staticmethod
    def _looks_like_api_path(url: str) -> bool:
        path = urlparse(url).path
        if not path or path in ("/", ""):
            return False
        if _API_PATH_HINTS_RE.search(path):
            return True
        segments = [s for s in path.split("/") if s]
        return any(_ID_SEGMENT_RE.match(seg) for seg in segments)

    def _add_candidate(
        self,
        method: str,
        url: str,
        confidence: float,
        signals: list[str],
        form_fields: Optional[list[str]] = None,
    ) -> None:
        key = (method.upper(), url)
        existing = self._candidates.get(key)
        if existing:
            existing.confidence = min(1.0, max(existing.confidence, confidence) + 0.05)
            existing.signals.extend(s for s in signals if s not in existing.signals)
            if form_fields:
                existing.form_fields = list(set(existing.form_fields) | set(form_fields))
        else:
            self._candidates[key] = _DiscoveredCandidate(
                method=method.upper(),
                url=url,
                confidence=confidence,
                signals=list(signals),
                form_fields=list(form_fields or []),
            )

    def _candidate_to_operation(self, candidate: _DiscoveredCandidate) -> Operation:
        parsed = urlparse(candidate.url)
        path_template, path_params = self._templatize_path(parsed.path)

        parameters = list(path_params)
        for field_name in candidate.form_fields:
            parameters.append(
                Parameter(
                    name=field_name,
                    location=ParameterLocation.BODY,
                    json_path=field_name,
                )
            )

        try:
            method_enum = HttpMethod(candidate.method)
        except ValueError:
            method_enum = HttpMethod.GET

        return Operation(
            operation_id=f"auto.{candidate.method}.{path_template}",
            api_type=ApiType.REST,
            operation_type=REST_METHOD_TO_OPERATION_TYPE.get(
                method_enum, OperationType.UNKNOWN
            ),
            source=DiscoverySource.AUTO_DISCOVERY,
            http_method=method_enum,
            path_template=path_template,
            base_url=self._origin,
            parameters=parameters,
            discovery_confidence=candidate.confidence,
            raw_metadata={"signals": candidate.signals, "observed_url": candidate.url},
        )

    @staticmethod
    def _templatize_path(path: str) -> tuple[str, list[Parameter]]:
        """Replace identifier-shaped segments with {paramN} placeholders so that
        e.g. /api/orders/482 and /api/orders/981 collapse into the same
        Operation template, with the varying segment exposed as a path Parameter
        for the identifier detector to evaluate.
        """
        segments = path.split("/")
        params: list[Parameter] = []
        templated = []
        counter = 0
        for seg in segments:
            if seg and _ID_SEGMENT_RE.match(seg):
                counter += 1
                name = f"param{counter}"
                templated.append("{" + name + "}")
                params.append(
                    Parameter(
                        name=name,
                        location=ParameterLocation.PATH,
                        example=seg,
                    )
                )
            else:
                templated.append(seg)
        return "/".join(templated), params

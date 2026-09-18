"""Authentication Manager.

Maintains parallel authenticated sessions for two or more principals (User A,
User B, ...) so the Request Engine can issue the same operation as different
identities. Supports bearer token, cookie-based, and HTTP basic authentication,
matching the mechanisms described in Chapter 3 of the dissertation. Login
flows themselves are configuration-driven (a login operation + credentials),
never hard-coded to a specific application.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)


class AuthScheme(str, Enum):
    BEARER_TOKEN = "bearer_token"
    COOKIE = "cookie"
    BASIC = "basic"
    API_KEY_HEADER = "api_key_header"
    NONE = "none"


@dataclass
class LoginSpec:
    """How to obtain credentials for a principal.

    Either `static_token` / `static_credentials` can be supplied directly, or
    a `login_url` + `login_payload` describing a login request whose response
    yields the token/cookie. `token_json_path` is a dotted path into the login
    response JSON body (e.g. "data.access_token").
    """

    scheme: AuthScheme
    login_url: Optional[str] = None
    login_method: str = "POST"
    login_payload: dict = field(default_factory=dict)
    token_json_path: Optional[str] = None
    static_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key_header_name: str = "X-API-Key"


@dataclass
class Principal:
    """An authenticated identity (e.g. "User A") plus everything the Request
    Engine needs to attach that identity's credentials to a request."""

    label: str
    login_spec: LoginSpec
    user_id_hint: Optional[str] = None  # optional known ID for ownership correlation
    session: requests.Session = field(default_factory=requests.Session)
    _token: Optional[str] = None
    _authenticated: bool = False

    def apply_auth(self, request_kwargs: dict) -> dict:
        """Mutate a `requests`-style kwargs dict to carry this principal's auth."""
        headers = dict(request_kwargs.get("headers") or {})
        scheme = self.login_spec.scheme

        if scheme == AuthScheme.BEARER_TOKEN and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        elif scheme == AuthScheme.API_KEY_HEADER and self._token:
            headers[self.login_spec.api_key_header_name] = self._token
        elif scheme == AuthScheme.BASIC:
            request_kwargs["auth"] = (
                self.login_spec.username,
                self.login_spec.password,
            )
        # COOKIE scheme relies on the principal's `requests.Session` cookie jar,
        # which is attached automatically when the caller uses `self.session`.

        request_kwargs["headers"] = headers
        return request_kwargs


def _dig(obj: dict, dotted_path: str):
    node = obj
    for part in dotted_path.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return None
    return node


class AuthenticationManager:
    """Owns and authenticates all principals used in a scan run."""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.principals: dict[str, Principal] = {}

    def register(self, principal: Principal) -> None:
        self.principals[principal.label] = principal

    def get(self, label: str) -> Principal:
        return self.principals[label]

    def authenticate_all(self) -> None:
        for principal in self.principals.values():
            self.authenticate(principal)

    def authenticate(self, principal: Principal) -> None:
        spec = principal.login_spec

        if spec.scheme == AuthScheme.NONE:
            principal._authenticated = True
            return

        if spec.static_token:
            principal._token = spec.static_token
            principal._authenticated = True
            return

        if spec.scheme == AuthScheme.BASIC:
            principal._authenticated = bool(spec.username and spec.password)
            return

        if not spec.login_url:
            raise ValueError(
                f"Principal '{principal.label}' has no static_token and no "
                "login_url; cannot authenticate."
            )

        resp = principal.session.request(
            spec.login_method,
            spec.login_url,
            json=spec.login_payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()

        if spec.scheme == AuthScheme.COOKIE:
            # Cookies land in principal.session.cookies automatically.
            principal._authenticated = len(principal.session.cookies) > 0
            return

        body = {}
        try:
            body = resp.json()
        except ValueError:
            pass

        token = None
        if spec.token_json_path:
            token = _dig(body, spec.token_json_path)
        if token is None:
            for candidate_path in ("access_token", "token", "data.token", "jwt"):
                token = _dig(body, candidate_path)
                if token:
                    break

        if not token:
            raise RuntimeError(
                f"Could not locate an auth token in login response for "
                f"principal '{principal.label}'. Set token_json_path explicitly."
            )

        principal._token = token
        principal._authenticated = True
        logger.info("Authenticated principal '%s'", principal.label)

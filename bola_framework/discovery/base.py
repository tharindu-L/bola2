"""Shared interface for discovery backends.

Every discovery backend (OpenAPI, GraphQL introspection, automatic discovery)
implements `Discoverer.discover()` and returns a list of `Operation` objects.
Nothing downstream of discovery is allowed to know which backend produced an
operation, other than through the `source` provenance tag on the Operation
itself, which is used only for reporting.
"""

from __future__ import annotations

import abc
import logging

from bola_framework.models import Operation

logger = logging.getLogger(__name__)


class Discoverer(abc.ABC):
    """Base class for all discovery backends."""

    @abc.abstractmethod
    def discover(self) -> list[Operation]:
        """Return the list of operations this backend was able to identify."""
        raise NotImplementedError

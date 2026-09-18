"""Ownership correlation.

BOLA is not "can another user access an ID" -- it is "can another
authenticated user access or manipulate an object that belongs to a
different user without authorization". This module builds up ownership
evidence for a (principal, object_identifier) pair from multiple weak
signals rather than trusting any single one (e.g. a field literally named
"user_id") as proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from bola_framework.engine.identifier_detector import is_owner_signal
from bola_framework.models.finding import RequestRecord


@dataclass
class OwnershipRecord:
    """Accumulated ownership evidence for one (principal, object_id) pair."""

    principal_label: str
    object_identifier: Any
    signals: list[str] = field(default_factory=list)
    established_via_creation: bool = False
    established_via_response_field: bool = False
    score: float = 0.0

    def add_signal(self, description: str, weight: float) -> None:
        self.signals.append(description)
        self.score = min(1.0, self.score + weight)

    @property
    def is_established(self) -> bool:
        """Conservative threshold: require either a creation-based link (the
        strongest possible evidence -- the principal made the request that
        created the object) or a combination of weaker signals crossing a bar.
        """
        return self.established_via_creation or self.score >= 0.6


class OwnershipTracker:
    """Tracks ownership across a scan run so cross-session tests can be built
    on top of a `User A -> owns -> Object A` baseline established earlier in
    the run (e.g. via a create operation or an authenticated listing).
    """

    def __init__(self):
        self._records: dict[tuple[str, str], OwnershipRecord] = {}

    def _key(self, principal_label: str, object_identifier: Any) -> tuple[str, str]:
        return (principal_label, str(object_identifier))

    def record_creation(self, principal_label: str, object_identifier: Any) -> OwnershipRecord:
        """Strongest possible signal: this principal's own request created the
        object and the identifier was extracted directly from that response.
        """
        record = self._get_or_create(principal_label, object_identifier)
        record.established_via_creation = True
        record.add_signal("object created by this principal's own authenticated request", 1.0)
        return record

    def record_authenticated_listing(
        self, principal_label: str, object_identifier: Any
    ) -> OwnershipRecord:
        """The object appeared in a listing/response returned specifically to
        this principal's own authenticated session (e.g. GET /me/orders)."""
        record = self._get_or_create(principal_label, object_identifier)
        record.established_via_response_field = True
        record.add_signal(
            "object identifier observed in a response returned to this principal's "
            "own authenticated session",
            0.5,
        )
        return record

    def record_field_correlation(
        self,
        principal_label: str,
        object_identifier: Any,
        field_name: str,
        field_value: Any,
        principal_user_id_hint: Optional[str],
    ) -> Optional[OwnershipRecord]:
        """A response field name looks like an owner/user reference and its
        value matches the principal's known user id. Weak on its own -- field
        names are not proof -- but useful in combination with other signals.
        """
        if not is_owner_signal(field_name):
            return None
        if principal_user_id_hint is None or str(field_value) != str(principal_user_id_hint):
            return None
        record = self._get_or_create(principal_label, object_identifier)
        record.add_signal(
            f"response field '{field_name}' matches principal's known user id", 0.35
        )
        return record

    def get(self, principal_label: str, object_identifier: Any) -> Optional[OwnershipRecord]:
        return self._records.get(self._key(principal_label, object_identifier))

    def _get_or_create(self, principal_label: str, object_identifier: Any) -> OwnershipRecord:
        key = self._key(principal_label, object_identifier)
        if key not in self._records:
            self._records[key] = OwnershipRecord(
                principal_label=principal_label, object_identifier=object_identifier
            )
        return self._records[key]

    def scan_response_for_correlations(
        self,
        principal_label: str,
        object_identifier: Any,
        response_body: Any,
        principal_user_id_hint: Optional[str],
    ) -> None:
        """Walk a JSON response body looking for owner-shaped fields that
        correlate with the principal's known identity."""
        for field_name, field_value in _walk_json_fields(response_body):
            self.record_field_correlation(
                principal_label, object_identifier, field_name, field_value, principal_user_id_hint
            )


def _walk_json_fields(node: Any, prefix: str = ""):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                yield from _walk_json_fields(value, f"{prefix}.{key}" if prefix else key)
            else:
                yield (key, value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_json_fields(item, prefix)

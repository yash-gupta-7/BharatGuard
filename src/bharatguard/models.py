"""Core data types. Session is a security boundary: it must never log,
serialize, or expose raw PII values through repr/debug output."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PIIEntity:
    entity_type: str
    start: int
    end: int
    confidence: float
    source: str


class Session:
    """In-memory token->original-value map for one protect()/restore() cycle.
    Deliberately has no to_dict/to_json/__getstate__: the mapping must never
    be persisted, so the capability to serialize it does not exist."""

    def __init__(self) -> None:
        self._mapping: dict[str, str] = {}

    def remember(self, token: str, original_value: str) -> None:
        self._mapping[token] = original_value

    def lookup(self, token: str) -> str | None:
        return self._mapping.get(token)

    def __repr__(self) -> str:
        return f"Session(entities={len(self._mapping)})"

    __str__ = __repr__

    @property
    def __getstate__(self) -> None:
        raise AttributeError("Session instances cannot be pickled")


@dataclass
class ProtectedMessages:
    messages: list[dict]
    session: Session

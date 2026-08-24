"""Policy: maps PII entity types to an action (mask/tokenize/ignore).

Plain dict-backed config -- no config framework, no YAML, no external schema
library. Kept deliberately minimal.
"""
from __future__ import annotations

_VALID_ACTIONS = {"mask", "tokenize", "ignore"}

DEFAULT_POLICY: dict[str, str] = {
    "AADHAAR": "mask",
    "PAN": "mask",
    "IFSC": "mask",
    "PHONE": "tokenize",
    "EMAIL": "tokenize",
    "UPI": "tokenize",
    "PERSON": "tokenize",
    "ADDRESS": "mask",
    "API_KEY": "mask",
    "CARD_NUMBER": "mask",
}


class PolicyConfig:
    """Entity-type -> action policy. Starts from DEFAULT_POLICY and lets a
    caller override individual entity types while leaving the rest at
    their defaults."""

    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        merged = dict(DEFAULT_POLICY)
        if overrides:
            for entity_type, action in overrides.items():
                if action not in _VALID_ACTIONS:
                    raise ValueError(
                        f"Invalid policy action {action!r} for entity type "
                        f"{entity_type!r}; must be one of {sorted(_VALID_ACTIONS)}"
                    )
                merged[entity_type] = action
        self._actions = merged

    def action_for(self, entity_type: str) -> str:
        """Returns the configured action for entity_type. Raises KeyError
        for an entity type with no known policy entry (fail closed --
        never silently default an unrecognized type to a permissive
        action)."""
        return self._actions[entity_type]

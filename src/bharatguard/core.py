"""PIIGuard: the top-level protect()/restore() pipeline.

Pipeline for protect(): normalize -> deterministic detectors -> contextual
detectors -> merge_entities() -> translate offsets back to original-text
space -> policy decision -> mask/tokenize/ignore -> ProtectedMessages.

Never log or print a matched/raw value anywhere in this module.
"""
from __future__ import annotations

import re

from bharatguard.detectors.contextual import IndianAddressDetector, SpacyPersonDetector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.merge import merge_entities
from bharatguard.masking.mask import apply_masking
from bharatguard.models import PIIEntity, ProtectedMessages, Session
from bharatguard.normalization.normalize import normalize
from bharatguard.policy.policy import PolicyConfig

_CONTEXTUAL_DETECTORS = [SpacyPersonDetector(), IndianAddressDetector()]

_TOKEN_RE = re.compile(r"<([A-Z_]+_\d+)>")


def _translate_entity(entity: PIIEntity, offset_map: list[int]) -> PIIEntity:
    """Translates an entity's start/end from normalized-text space to
    original-text space using `offset_map` (offset_map[i] is the original
    index for normalized_text[i]). For span (start, end) on normalized
    text, the original span is (offset_map[start], offset_map[end - 1] + 1)
    per normalize()'s documented contract."""
    if entity.end <= entity.start:
        # Degenerate/empty span -- should not occur from real detectors,
        # but translate conservatively rather than indexing offset_map[-1].
        orig_start = offset_map[entity.start] if entity.start < len(offset_map) else entity.start
        return PIIEntity(entity.entity_type, orig_start, orig_start, entity.confidence, entity.source)
    orig_start = offset_map[entity.start]
    orig_end = offset_map[entity.end - 1] + 1
    return PIIEntity(entity.entity_type, orig_start, orig_end, entity.confidence, entity.source)


class PIIGuard:
    """Detects and masks/tokenizes Indian PII in chat-style messages.

    Message structure assumption (deliberate scope limit): `protect()`
    supports exactly `list[dict]` where each dict has at least a
    `"content"` key whose value is a plain `str`, e.g.
    `[{"role": "user", "content": "text"}, ...]`. Only `"content"` is
    protected; every other key on each dict (e.g. `"role"`) passes through
    unchanged. Nested/structured/multimodal content (e.g. a list of content
    blocks, as some chat APIs use) is explicitly out of scope and is not
    handled -- passing such a message shape will fail loudly (content is
    expected to support string slicing/masking) rather than being silently
    mishandled.
    """

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self._policy = policy if policy is not None else PolicyConfig()

    def protect(self, messages: list[dict]) -> ProtectedMessages:
        """Detects and masks/tokenizes PII across all messages in one call.

        A single Session is created for this call and shared across all
        messages, so the same original value mentioned in two different
        messages within this call reuses the same token. Each PIIGuard.
        protect() call gets its own fresh Session -- token mappings never
        leak between separate protect() calls.

        Does not mutate the caller's original message dicts or the list
        containing them; new dict objects are built for the returned
        ProtectedMessages.messages.
        """
        session = Session()
        token_registry: dict[tuple[str, str], str] = {}
        protected_messages: list[dict] = []

        for message in messages:
            content = message["content"]
            normalized_text, offset_map = normalize(content)

            entities: list[PIIEntity] = []
            for detector in DETERMINISTIC_DETECTORS:
                entities.extend(detector.detect(normalized_text))
            for detector in _CONTEXTUAL_DETECTORS:
                entities.extend(detector.detect(normalized_text))

            # Translate BEFORE merge: merge_entities' overlap resolution
            # must operate on the same coordinate space it will ultimately
            # be applied in, and translating first also means downstream
            # code never has to remember which space a given entity is in.
            translated = [_translate_entity(e, offset_map) for e in entities]
            merged = merge_entities(translated)

            masked_content = apply_masking(
                content, merged, self._policy, session, token_registry
            )
            protected_messages.append({**message, "content": masked_content})

        return ProtectedMessages(messages=protected_messages, session=session)

    def restore(self, response: str, session: Session) -> str:
        """Replaces known tokens (pattern `<[A-Z_]+_\\d+>`) in `response`
        with their original values from `session`. `response` must be a
        plain string -- not a dict, list, or other structured object; no
        recursive serializer for arbitrary response shapes is implemented,
        that is out of scope.

        If a token is not found in `session` (unknown/foreign token), it is
        left exactly as-is in the output: this function never guesses,
        never substitutes a placeholder, and never raises for that case.
        """
        def _replace(match: re.Match) -> str:
            token = match.group(1)
            original = session.lookup(token)
            return match.group(0) if original is None else original

        return _TOKEN_RE.sub(_replace, response)

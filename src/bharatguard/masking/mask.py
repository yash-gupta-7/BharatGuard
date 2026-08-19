"""Masking/tokenization: replaces PII spans in text per policy.

Operates on ORIGINAL-text offsets only -- callers (PIIGuard.protect()) are
responsible for translating detector offsets from normalized-text space
into original-text space via the normalizer's offset map before calling
apply_masking(). This module never re-runs detection and never mutates the
input string in place (Python strings are immutable; a new string is built
via slicing).

Never log or print a matched/raw value anywhere in this module.
"""
from __future__ import annotations

from bharatguard.models import PIIEntity, Session
from bharatguard.policy.policy import PolicyConfig

REDACTED_MARKER = "[REDACTED]"


def apply_masking(
    text: str,
    entities: list[PIIEntity],
    policy: PolicyConfig,
    session: Session,
    token_registry: dict[tuple[str, str], str] | None = None,
) -> str:
    """Replaces each entity's span in `text` per its policy action.

    - "mask": replace the span with REDACTED_MARKER.
    - "tokenize": replace the span with "<{ENTITY_TYPE}_{N}>", where N
      increments per entity type. If the exact original substring for a
      given entity type has already been tokenized earlier (tracked in
      `token_registry`, NOT on Session), the existing token is reused
      instead of minting a new one. The mapping is recorded via
      session.remember(token, original_value).
    - "ignore": the span is left untouched.

    `token_registry` is masking-scoped bookkeeping (never stored on
    Session, which stays token -> value only, no reverse lookup, no bulk
    export). It maps (entity_type, raw_value) -> token name. When omitted,
    a fresh registry is used for this single call. A caller that needs
    token reuse to span multiple apply_masking() calls (e.g. PIIGuard's
    per-message loop within one protect() call, for cross-message reuse of
    the same value) creates one registry and threads it through every call
    for that protect() invocation. This state is ordinary local Python
    state, entirely separate from Session's minimal remember()/lookup()
    surface.

    Entities are expected to be non-overlapping and are processed in
    descending order of `start` (right-to-left) so that replacing a later
    span never shifts the offsets of spans earlier in the string. A
    defensive check verifies non-overlap and in-bounds offsets and raises
    ValueError (never including the raw matched value) if violated.
    """
    # Sort right-to-left by start. Ties on start should not occur for a
    # non-overlapping set (would imply zero-length or identical spans);
    # sorting is still well-defined either way.
    ordered = sorted(entities, key=lambda e: e.start, reverse=True)

    # Defensive overlap/bounds check, walking right-to-left: each entity's
    # end must not exceed the start of the previously processed (i.e. the
    # next-higher-start) entity, and offsets must be within `text` bounds.
    prev_start = len(text)
    for e in ordered:
        if e.start < 0 or e.end > len(text) or e.start > e.end:
            raise ValueError(
                f"Entity {e.entity_type} has out-of-bounds offsets "
                f"[{e.start}:{e.end}] for text of length {len(text)}"
            )
        if e.end > prev_start:
            raise ValueError(
                f"Overlapping or unsorted entities detected: {e.entity_type} "
                f"span [{e.start}:{e.end}] overlaps a later-processed span "
                f"starting at {prev_start}"
            )
        prev_start = e.start

    # Local (not Session) bookkeeping for token reuse: exact raw-substring
    # equality per entity type. Persists only as long as the caller keeps
    # `token_registry` alive (default: this single call only).
    seen_tokens: dict[tuple[str, str], str] = (
        token_registry if token_registry is not None else {}
    )
    counters: dict[str, int] = {}
    for (entity_type, _raw_value), token_name in seen_tokens.items():
        n = int(token_name.rsplit("_", 1)[1])
        if n > counters.get(entity_type, 0):
            counters[entity_type] = n

    # Pass 1: decide each entity's replacement text (or None for "ignore").
    # Token numbering is assigned in LEFT-TO-RIGHT document order (first
    # occurrence in the text gets _1, etc.) -- this pass is independent of
    # the right-to-left replacement pass below, which exists purely to
    # avoid offset corruption while editing the string.
    replacements: dict[int, str | None] = {}
    for e in sorted(ordered, key=lambda e: e.start):
        action = policy.action_for(e.entity_type)
        if action == "ignore":
            replacements[id(e)] = None
        elif action == "mask":
            replacements[id(e)] = REDACTED_MARKER
        elif action == "tokenize":
            raw_value = text[e.start:e.end]
            key = (e.entity_type, raw_value)
            token_name = seen_tokens.get(key)
            if token_name is None:
                counters[e.entity_type] = counters.get(e.entity_type, 0) + 1
                token_name = f"{e.entity_type}_{counters[e.entity_type]}"
                seen_tokens[key] = token_name
                session.remember(token_name, raw_value)
            replacements[id(e)] = f"<{token_name}>"
        else:
            # PolicyConfig already validates actions at construction time;
            # this branch should be unreachable.
            raise ValueError(f"Unknown policy action for entity type {e.entity_type}")

    # Pass 2: apply replacements right-to-left so earlier offsets are never
    # invalidated by a preceding (in this loop, i.e. later-in-text) edit.
    result = text
    for e in ordered:
        replacement = replacements[id(e)]
        if replacement is None:
            continue
        result = result[:e.start] + replacement + result[e.end:]

    return result

"""Overlap resolution: deterministic-source entities are trusted over
contextual-source entities, then higher confidence, then longer span, then
a fully order-independent (entity_type, source) tiebreak. Output must be
provably invariant to the order candidates arrive in — detectors run in
no guaranteed order, so nothing here may depend on input/insertion order."""
from __future__ import annotations

from bharatguard.models import PIIEntity

_DETERMINISTIC_SOURCES = {
    "aadhaar_regex_verhoeff", "pan_regex", "phone_regex",
    "email_regex", "upi_regex", "ifsc_regex",
    "api_key_openai", "api_key_aws", "api_key_bearer", "api_key_generic_assignment",
    "card_regex_luhn",
}


def _tier(entity: PIIEntity) -> int:
    return 1 if entity.source in _DETERMINISTIC_SOURCES else 0


def _rank_key(entity: PIIEntity) -> tuple[int, float, int, str, str, int]:
    # (tier, confidence, span length, entity_type, source, -start) — the
    # last two are deterministic, entity-intrinsic tiebreaks (not
    # list-position-dependent). -start is required: two entities can tie on
    # every prior field (same type/source/confidence/span length) while
    # having different start offsets, and max()'s tie-break otherwise falls
    # back to "whichever came first in the list", which is exactly the
    # input-order dependence this module exists to eliminate. If start is
    # also equal once everything else ties, end is equal too (same span
    # length), so the entities are true duplicates and collapsing them is
    # correct.
    return (
        _tier(entity),
        entity.confidence,
        entity.end - entity.start,
        entity.entity_type,
        entity.source,
        -entity.start,
    )


def merge_entities(entities: list[PIIEntity]) -> list[PIIEntity]:
    # Repeatedly take the single globally-best-ranked remaining candidate,
    # keep it, and drop everything that overlaps it. A one-pass sweep that
    # only compares against the first overlapping *kept* entity can drop a
    # non-overlapping entity in a transitive chain (A overlaps B, B overlaps
    # C, A does not overlap C): if B beats A it evicts A from the result
    # entirely, then if C beats B it evicts B too, silently losing A even
    # though A never conflicted with C. Picking the global max each round
    # and only removing entities that actually overlap it avoids that.
    remaining = list(entities)
    kept: list[PIIEntity] = []
    while remaining:
        winner = max(remaining, key=_rank_key)
        kept.append(winner)
        remaining = [
            e for e in remaining
            if e is not winner and not (winner.start < e.end and e.start < winner.end)
        ]
    return sorted(kept, key=lambda e: e.start)

"""Overlap resolution: deterministic-source entities are trusted over
contextual-source entities, then higher confidence, then longer span, then
a fully order-independent (entity_type, source) tiebreak. Output must be
provably invariant to the order candidates arrive in — detectors run in
no guaranteed order, so nothing here may depend on input/insertion order."""
from __future__ import annotations

from bharatguard.models import PIIEntity

_DETERMINISTIC_SOURCES = {
    "aadhaar_regex", "pan_regex", "phone_regex",
    "email_regex", "upi_regex", "ifsc_regex",
}


def _tier(entity: PIIEntity) -> int:
    return 1 if entity.source in _DETERMINISTIC_SOURCES else 0


def _rank_key(entity: PIIEntity) -> tuple[int, float, int, str, str]:
    # (tier, confidence, span length, entity_type, source) — the last two
    # are a deterministic, order-independent final tiebreak. If every field
    # ties, the entities are true duplicates and collapsing them is correct.
    return (
        _tier(entity),
        entity.confidence,
        entity.end - entity.start,
        entity.entity_type,
        entity.source,
    )


def merge_entities(entities: list[PIIEntity]) -> list[PIIEntity]:
    # Sort by start ascending, then span length descending, then the same
    # deterministic tiebreak key so equal-start candidates are processed in
    # a fixed order regardless of input order.
    ordered = sorted(
        entities,
        key=lambda e: (e.start, -(e.end - e.start), e.entity_type, e.source),
    )
    result: list[PIIEntity] = []
    for entity in ordered:
        overlap_idx = next(
            (i for i, kept in enumerate(result) if kept.start < entity.end and entity.start < kept.end),
            None,
        )
        if overlap_idx is None:
            result.append(entity)
            continue
        if _rank_key(entity) > _rank_key(result[overlap_idx]):
            result[overlap_idx] = entity
    return sorted(result, key=lambda e: e.start)

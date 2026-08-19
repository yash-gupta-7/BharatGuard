import itertools

from bharatguard.models import PIIEntity
from bharatguard.detectors.merge import merge_entities


def test_no_overlap_keeps_all():
    entities = [
        PIIEntity("AADHAAR", 0, 12, 0.9, "aadhaar_regex"),
        PIIEntity("PAN", 20, 30, 0.95, "pan_regex"),
    ]
    result = merge_entities(entities)
    assert len(result) == 2


def test_deterministic_wins_over_contextual_on_overlap():
    entities = [
        PIIEntity("ADDRESS", 5, 25, 0.6, "address_keyword"),
        PIIEntity("EMAIL", 10, 20, 0.9, "email_regex"),
    ]
    result = merge_entities(entities)
    assert len(result) == 1
    assert result[0].source == "email_regex"


def test_higher_confidence_wins_among_same_tier():
    entities = [
        PIIEntity("ADDRESS", 0, 10, 0.5, "address_keyword"),
        PIIEntity("ADDRESS", 0, 10, 0.65, "address_trigger_phrase"),
    ]
    result = merge_entities(entities)
    assert len(result) == 1
    assert result[0].confidence == 0.65


def test_longer_span_wins_on_tie_confidence_and_tier():
    entities = [
        PIIEntity("ADDRESS", 0, 10, 0.6, "address_keyword"),
        PIIEntity("ADDRESS", 0, 20, 0.6, "address_keyword"),
    ]
    result = merge_entities(entities)
    assert len(result) == 1
    assert result[0].end == 20


def test_sorted_by_start_offset():
    entities = [
        PIIEntity("PAN", 20, 30, 0.95, "pan_regex"),
        PIIEntity("AADHAAR", 0, 12, 0.9, "aadhaar_regex"),
    ]
    result = merge_entities(entities)
    assert [e.start for e in result] == [0, 20]


def test_true_duplicate_collapses_to_one():
    """Same detector (or two logically-identical detections) producing an
    identical candidate twice must not survive as two entities."""
    entities = [
        PIIEntity("EMAIL", 10, 20, 0.9, "email_regex"),
        PIIEntity("EMAIL", 10, 20, 0.9, "email_regex"),
    ]
    result = merge_entities(entities)
    assert len(result) == 1
    assert result[0] == PIIEntity("EMAIL", 10, 20, 0.9, "email_regex")


def test_final_tiebreak_is_deterministic_and_order_independent():
    """Same tier, same confidence, same span length, different entity_type/source:
    the winner must be chosen by (entity_type, source) alphabetical order, and
    must not depend on which one appears first in the input list."""
    a = PIIEntity("PERSON", 0, 10, 0.7, "spacy_person")
    b = PIIEntity("ADDRESS", 0, 10, 0.7, "address_keyword")
    # Tiebreak picks the entity with the lexicographically greatest
    # (entity_type, source), consistent with "higher wins" for confidence/span.
    # ("PERSON", "spacy_person") > ("ADDRESS", "address_keyword")
    expected_winner = a

    result_ab = merge_entities([a, b])
    result_ba = merge_entities([b, a])

    assert result_ab == result_ba
    assert len(result_ab) == 1
    assert result_ab[0] == expected_winner


def test_multi_way_overlap_picks_single_winner():
    """Three+ overlapping candidates at once must resolve to exactly one
    winner (the deterministic entity), not two or the wrong one."""
    entities = [
        PIIEntity("ADDRESS", 0, 30, 0.5, "address_keyword"),
        PIIEntity("PERSON", 5, 15, 0.99, "spacy_person"),
        PIIEntity("EMAIL", 10, 20, 0.9, "email_regex"),
        PIIEntity("ADDRESS", 8, 12, 0.6, "address_trigger_phrase"),
    ]
    result = merge_entities(entities)
    assert len(result) == 1
    assert result[0].source == "email_regex"


def test_non_overlapping_same_type_entities_stay_separate():
    entities = [
        PIIEntity("ADDRESS", 0, 10, 0.6, "address_keyword"),
        PIIEntity("ADDRESS", 50, 70, 0.6, "address_keyword"),
    ]
    result = merge_entities(entities)
    assert len(result) == 2
    assert [e.start for e in result] == [0, 50]


def test_output_invariant_to_input_order():
    """The most important test in this task: merge_entities output must not
    depend on the order candidates were produced/appended in (i.e. must not
    depend on detector invocation order)."""
    base = [
        PIIEntity("AADHAAR", 0, 12, 0.9, "aadhaar_regex"),
        PIIEntity("ADDRESS", 5, 25, 0.6, "address_keyword"),
        PIIEntity("EMAIL", 10, 20, 0.9, "email_regex"),
        PIIEntity("PAN", 40, 50, 0.95, "pan_regex"),
        PIIEntity("PERSON", 42, 48, 0.8, "spacy_person"),
        PIIEntity("UPI", 60, 75, 0.85, "upi_regex"),
    ]

    permutations = [
        base,
        list(reversed(base)),
        # contextual entity appears before an overlapping deterministic one
        [base[1], base[2], base[0], base[4], base[3], base[5]],
        [base[5], base[3], base[4], base[2], base[1], base[0]],
    ]

    results = [merge_entities(list(p)) for p in permutations]
    first = results[0]
    for r in results[1:]:
        assert r == first

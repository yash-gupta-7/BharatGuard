"""Tests for the evaluator's own logic (evals/run_eval.py). These tests use
small inline fixtures -- they do NOT depend on the content of the real
evals/dataset.jsonl, so they stay stable if the dataset is edited later."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from evals.run_eval import (
    load_dataset,
    ground_truth_span,
    score,
    canonicalize,
    check_leakage,
    STRUCTURED_CANONICAL_TYPES,
)


# ---------------------------------------------------------------------------
# 1. Dataset loading
# ---------------------------------------------------------------------------

def test_load_dataset_parses_jsonl(tmp_path):
    fixture = tmp_path / "mini.jsonl"
    fixture.write_text(
        '{"id": "ex_1", "text": "call 9876543210", '
        '"entities": [{"type": "PHONE", "value": "9876543210"}], "category": "phone_standard"}\n'
        '{"id": "ex_2", "text": "no pii here", "entities": [], "category": "general_false_positive"}\n',
        encoding="utf-8",
    )
    rows = load_dataset(fixture)
    assert len(rows) == 2
    assert rows[0]["id"] == "ex_1"
    assert rows[0]["text"] == "call 9876543210"
    assert rows[0]["entities"] == [{"type": "PHONE", "value": "9876543210"}]
    assert rows[0]["category"] == "phone_standard"
    assert rows[1]["entities"] == []


def test_load_dataset_skips_blank_lines(tmp_path):
    fixture = tmp_path / "mini.jsonl"
    fixture.write_text(
        '{"id": "ex_1", "text": "x", "entities": [], "category": "c"}\n\n',
        encoding="utf-8",
    )
    rows = load_dataset(fixture)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 2. Ground-truth span computation
# ---------------------------------------------------------------------------

def test_ground_truth_span_basic():
    text = "My PAN is ABCPE1234F for tax filing."
    start, end = ground_truth_span(text, "ABCPE1234F")
    assert (start, end) == (10, 20)
    assert text[start:end] == "ABCPE1234F"


def test_ground_truth_span_at_start_of_string():
    text = "9876543210 is my number"
    start, end = ground_truth_span(text, "9876543210")
    assert (start, end) == (0, 10)


# ---------------------------------------------------------------------------
# 3. Span matching / score() -- hand-verifiable cases
# ---------------------------------------------------------------------------

def test_score_hand_case_two_tp_one_fp_one_fn():
    # Gold: PHONE(0,10), EMAIL(20,30), PAN(40,50)
    # Predicted: PHONE(0,10) [correct], EMAIL(20,30) [correct],
    #            AADHAAR(60,72) [false positive, not in gold]
    # PAN(40,50) is missing from predicted -> false negative.
    gold = [("PHONE", 0, 10), ("EMAIL", 20, 30), ("PAN", 40, 50)]
    predicted = [("PHONE", 0, 10), ("EMAIL", 20, 30), ("AADHAAR", 60, 72)]

    result = score(predicted, gold)

    assert result["tp"] == 2
    assert result["fp"] == 1
    assert result["fn"] == 1
    # precision = TP/(TP+FP) = 2/3, recall = TP/(TP+FN) = 2/3
    assert result["precision"] == pytest.approx(2 / 3)
    assert result["recall"] == pytest.approx(2 / 3)
    assert result["f1"] == pytest.approx(2 / 3)


def test_score_hand_case_all_correct_exact_division():
    # 4 gold, 4 predicted, all matching -> TP=4, FP=0, FN=0.
    # precision=recall=f1=1.0 exactly (clean division).
    spans = [("AADHAAR", 0, 12), ("PAN", 20, 30), ("PHONE", 40, 50), ("IFSC", 60, 71)]
    result = score(list(spans), list(spans))
    assert result["tp"] == 4
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0


def test_score_hand_case_no_predictions_all_missed():
    # 2 gold, 0 predicted -> TP=0, FP=0, FN=2.
    # precision undefined (TP+FP==0) -> defined as 0.0; recall = 0/2 = 0.0 exactly.
    gold = [("PHONE", 0, 10), ("EMAIL", 20, 30)]
    result = score([], gold)
    assert result["tp"] == 0
    assert result["fp"] == 0
    assert result["fn"] == 2
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] == 0.0


def test_score_wrong_entity_type_at_same_span_is_both_fp_and_fn():
    # Predicting the right span but the wrong entity_type is not a match --
    # it must count as one false positive (wrong prediction) AND one false
    # negative (the correct gold entity was never produced).
    gold = [("PERSON", 5, 15)]
    predicted = [("ADDRESS", 5, 15)]
    result = score(predicted, gold)
    assert result["tp"] == 0
    assert result["fp"] == 1
    assert result["fn"] == 1


# ---------------------------------------------------------------------------
# 4. Canonicalization helper
# ---------------------------------------------------------------------------

def test_canonicalize_preserves_devanagari_digits():
    # Regression: an ASCII-only "[^A-Za-z0-9]" filter would strip
    # Devanagari digits entirely, collapsing a valid Aadhaar value to ""
    # and making the canonical-substring leak check trivially (and
    # wrongly) true against ANY protected content.
    value = canonicalize("९१२३४५६७८९०५")
    assert value != ""
    assert value == "९१२३४५६७८९०५"


def test_canonicalize_strips_punctuation_and_lowercases():
    assert canonicalize("987-654-3210") == canonicalize("9876543210")
    assert canonicalize("987-654-3210") == "9876543210"
    assert canonicalize("+91 9876543210") == "919876543210"
    assert canonicalize("ABCPE1234F") == canonicalize("abcpe1234f")


# ---------------------------------------------------------------------------
# 5. Leakage detection
# ---------------------------------------------------------------------------

def test_leakage_exact_substring_leak_detected():
    exact, canonical = check_leakage("AADHAAR", "234123412346", "your aadhaar 234123412346 was noted")
    assert exact is True
    assert canonical is True  # exact leak also canonicalizes to a match


def test_leakage_canonical_only_leak_detected():
    # A differently-formatted phone number slipping through: raw value has
    # no punctuation, but the leaked text is spaced/hyphenated differently
    # -- exact substring match fails, canonical match succeeds.
    exact, canonical = check_leakage("PHONE", "9876543210", "call +91-98765-43210 back")
    assert exact is False
    assert canonical is True


def test_leakage_no_leak():
    exact, canonical = check_leakage("PHONE", "9876543210", "your number is <PHONE_1>")
    assert exact is False
    assert canonical is False


def test_leakage_canonical_check_only_applies_to_structured_types():
    assert "AADHAAR" in STRUCTURED_CANONICAL_TYPES
    assert "PAN" in STRUCTURED_CANONICAL_TYPES
    assert "PHONE" in STRUCTURED_CANONICAL_TYPES
    assert "IFSC" in STRUCTURED_CANONICAL_TYPES
    assert "PERSON" not in STRUCTURED_CANONICAL_TYPES
    assert "ADDRESS" not in STRUCTURED_CANONICAL_TYPES


# ---------------------------------------------------------------------------
# 6. Deterministic reproducibility
# ---------------------------------------------------------------------------

def test_score_is_deterministic_across_runs():
    gold = [("PHONE", 0, 10), ("EMAIL", 20, 30), ("PAN", 40, 50)]
    predicted = [("PHONE", 0, 10), ("EMAIL", 20, 30), ("AADHAAR", 60, 72)]
    first = score(predicted, gold)
    second = score(predicted, gold)
    assert first == second


def test_leakage_is_deterministic_across_runs():
    args = ("PHONE", "9876543210", "call +91-98765-43210 back")
    assert check_leakage(*args) == check_leakage(*args)

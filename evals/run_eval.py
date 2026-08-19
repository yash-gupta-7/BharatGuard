"""Reproducible, no-network evaluation harness for BharatGuard's detectors.

Run: python evals/run_eval.py            (summary metrics only)
     python evals/run_eval.py --debug    (also prints per-example detail --
                                           WARNING: prints raw synthetic PII)

--- Methodology ------------------------------------------------------------

Dataset (evals/dataset.jsonl): one JSON object per line --
    {"id": ..., "text": ..., "entities": [{"type": ..., "value": ...}, ...],
     "category": ...}
`entities: []` marks a pure false-positive-trap example (text that looks
like PII but should not be detected).

Ground-truth spans are NOT stored as offsets in the dataset -- they are
derived by locating each entity's `value` substring in `text` via
`str.index()` at evaluation time (see `ground_truth_span()`). This keeps
the dataset human-editable and avoids offset drift if `text` is hand-edited
later. Every dataset entry is expected to have each `value` occur exactly
once in `text` (unambiguous `str.index()`); this is validated during
dataset construction, not at eval time.

Two configurations are evaluated over the SAME dataset with the SAME
detector code -- only the detector list differs:
    Config A -- deterministic only:        DETERMINISTIC_DETECTORS
    Config B -- deterministic + contextual: DETERMINISTIC_DETECTORS
                                             + SpacyPersonDetector()
                                             + IndianAddressDetector()
For each example this script independently replicates the same
detect-and-translate-offsets pipeline core.py uses internally: normalize()
-> run detectors on normalized text -> translate each entity's offsets back
to original-text space via offset_map -> merge_entities(). `PIIGuard`
itself does not expose the detected entity list, so this ~10-line
duplication is necessary to get spans to score against ground truth; it is
not a reason to add a new method to PIIGuard/core.py.

Metrics (span-level exact match): a predicted entity is a true positive
only if (entity_type, start, end) exactly matches a ground-truth entity's
(type, computed_start, computed_end). precision = TP/(TP+FP),
recall = TP/(TP+FN), f1 = 2PR/(P+R) (0.0 when the denominator is 0).
Reported overall and per-entity-type, for both configurations.

Leakage check: for every example, PIIGuard().protect() is run (DEFAULT
policy, unmodified) and the resulting protected content is inspected. For
every ground-truth entity whose type maps to "mask" or "tokenize" under
DEFAULT_POLICY (checked programmatically -- never hardcoded), two checks
are made:
  1. Exact substring leak: is entity["value"] present verbatim in the
     protected content?
  2. Canonical structured-value leak (AADHAAR/PAN/PHONE/IFSC only): strip
     non-alphanumeric characters and lowercase both the ground-truth value
     and the protected content, then check if the canonicalized value is a
     substring of the canonicalized content. Catches cases where only
     punctuation/formatting was stripped but the digits leaked in some
     other form.
Entities whose policy resolves to "ignore" are never counted as leaks
(policy working as configured, not a defect) -- checked programmatically
via DEFAULT_POLICY, not assumed.

IMPORTANT: zero leakage on this dataset is an evaluation-set invariant
(this dataset's specific phrasings happen to be fully caught), NOT proof
BharatGuard can never miss PII in arbitrary real-world input.

Latency: per-example wall-clock time (time.perf_counter()) for
deterministic-only detection, contextual detection, and total (matching
what protect() would do). spaCy's model is loaded once at import time
(module-level `_nlp = spacy.load(...)` in contextual.py), not per call, so
there is no meaningful warm-up/steady-state split to measure here -- this
is stated rather than inventing a fake methodology.

No network call is made anywhere in this script.

Privacy of this script's own output: the default run prints only aggregate
summary statistics -- never a raw example `text` or `value`. `--debug`
opts into printing individual example detail and prints a loud warning
banner when used.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from bharatguard.core import PIIGuard
from bharatguard.detectors.contextual import IndianAddressDetector, SpacyPersonDetector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.merge import merge_entities
from bharatguard.models import PIIEntity
from bharatguard.normalization.normalize import normalize
from bharatguard.policy.policy import DEFAULT_POLICY

DATASET_PATH = Path(__file__).parent / "dataset.jsonl"

CONTEXTUAL_DETECTORS = [SpacyPersonDetector(), IndianAddressDetector()]

# Structured types where formatting variants of the same value are
# meaningful (so a canonicalized-substring check makes sense for them).
STRUCTURED_CANONICAL_TYPES = {"AADHAAR", "PAN", "PHONE", "IFSC"}


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(path: Path | str) -> list[dict]:
    """Parses the JSONL dataset into a list of row dicts. Blank lines are
    skipped."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def ground_truth_span(text: str, value: str) -> tuple[int, int]:
    """Locates `value` in `text` via str.index() and returns (start, end).
    Raises ValueError if `value` is not present (a malformed dataset
    entry)."""
    start = text.index(value)
    return start, start + len(value)


# ---------------------------------------------------------------------------
# Detection pipeline (replicates core.py's internal pipeline, since
# PIIGuard.protect() does not expose the entity list)
# ---------------------------------------------------------------------------

def _translate_entity(entity: PIIEntity, offset_map: list[int]) -> PIIEntity:
    if entity.end <= entity.start:
        orig_start = offset_map[entity.start] if entity.start < len(offset_map) else entity.start
        return PIIEntity(entity.entity_type, orig_start, orig_start, entity.confidence, entity.source)
    orig_start = offset_map[entity.start]
    orig_end = offset_map[entity.end - 1] + 1
    return PIIEntity(entity.entity_type, orig_start, orig_end, entity.confidence, entity.source)


def detect(text: str, detectors: list) -> tuple[list[PIIEntity], float]:
    """Runs `detectors` over `text` end-to-end (normalize -> detect ->
    translate -> merge) and returns (merged_entities, elapsed_seconds)."""
    t0 = time.perf_counter()
    normalized_text, offset_map = normalize(text)
    raw_entities: list[PIIEntity] = []
    for detector in detectors:
        raw_entities.extend(detector.detect(normalized_text))
    translated = [_translate_entity(e, offset_map) for e in raw_entities]
    merged = merge_entities(translated)
    elapsed = time.perf_counter() - t0
    return merged, elapsed


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score(predicted: list[tuple[str, int, int]], gold: list[tuple[str, int, int]]) -> dict:
    """Span-level exact-match scoring. `predicted` and `gold` are lists of
    (entity_type, start, end) tuples. Returns tp/fp/fn counts plus
    precision/recall/f1 (0.0 when a denominator is 0, never a ZeroDivisionError)."""
    pred_set = set(predicted)
    gold_set = set(gold)
    tp = len(pred_set & gold_set)
    fp = len(pred_set - gold_set)
    fn = len(gold_set - pred_set)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


# ---------------------------------------------------------------------------
# Leakage checking
# ---------------------------------------------------------------------------

def canonicalize(value: str) -> str:
    """Strips non-alphanumeric characters and lowercases -- used to catch
    leaks where only punctuation/formatting differs from the raw value,
    e.g. "987-654-3210" and "9876543210" canonicalize identically.

    Deliberately does NOT strip a leading country code (e.g. "+91"): this
    helper is applied to BOTH the ground-truth value and the (potentially
    long) protected message content for a substring check, and stripping
    a fixed prefix would only be valid at the very start of a string --
    applying it to arbitrary message content would silently corrupt
    unrelated text rather than normalize a phone number. It is also
    type-agnostic (used for AADHAAR/PAN/PHONE/IFSC alike), and a blanket
    "91" strip would risk false structure on AADHAAR values that
    legitimately start with those digits. In this dataset the PHONE
    ground-truth values are already the bare digit sequence (the phone
    regex's capture group excludes the +91/0 prefix), so this does not
    cost any real coverage here.

    Uses `str.isalnum()` per character rather than an ASCII-only regex --
    important for Devanagari-digit Aadhaar values: an ASCII-only
    "[^A-Za-z0-9]" filter would strip Devanagari digits entirely,
    reducing a valid ground-truth value to "" and making the canonical
    substring check trivially (and wrongly) true against any content.
    """
    return "".join(ch for ch in value if ch.isalnum()).lower()


def check_leakage(entity_type: str, value: str, protected_content: str) -> tuple[bool, bool]:
    """Returns (exact_substring_leak, canonical_leak) for one ground-truth
    value against one piece of protected content. Canonical leak is only
    meaningful for STRUCTURED_CANONICAL_TYPES; other types report
    canonical_leak == exact_substring_leak (canonicalization adds no extra
    signal for free-form values like PERSON/ADDRESS)."""
    exact = value in protected_content
    if entity_type in STRUCTURED_CANONICAL_TYPES:
        canonical = canonicalize(value) in canonicalize(protected_content)
    else:
        canonical = exact
    return exact, canonical


# ---------------------------------------------------------------------------
# Evaluation run
# ---------------------------------------------------------------------------

def _gold_spans(row: dict) -> list[tuple[str, int, int]]:
    spans = []
    for ent in row["entities"]:
        start, end = ground_truth_span(row["text"], ent["value"])
        spans.append((ent["type"], start, end))
    return spans


def _pred_spans(entities: list[PIIEntity]) -> list[tuple[str, int, int]]:
    return [(e.entity_type, e.start, e.end) for e in entities]


def evaluate_config(rows: list[dict], detectors: list) -> dict:
    """Runs detection + scoring for every row under one detector list.
    Returns overall metrics, per-entity-type metrics, and latency stats."""
    all_predicted: list[tuple[str, int, int]] = []
    all_gold: list[tuple[str, int, int]] = []
    by_type_predicted: dict[str, list] = {}
    by_type_gold: dict[str, list] = {}
    latencies: list[float] = []

    for row in rows:
        gold = _gold_spans(row)
        entities, elapsed = detect(row["text"], detectors)
        predicted = _pred_spans(entities)
        latencies.append(elapsed)

        all_predicted.extend(predicted)
        all_gold.extend(gold)
        for t, s, e in predicted:
            by_type_predicted.setdefault(t, []).append((t, s, e))
        for t, s, e in gold:
            by_type_gold.setdefault(t, []).append((t, s, e))

    overall = score(all_predicted, all_gold)

    entity_types = sorted(set(by_type_predicted) | set(by_type_gold))
    per_type = {
        t: score(by_type_predicted.get(t, []), by_type_gold.get(t, []))
        for t in entity_types
    }

    latencies_sorted = sorted(latencies)
    n = len(latencies_sorted)
    latency_stats = {
        "count": n,
        "mean_seconds": sum(latencies_sorted) / n if n else 0.0,
        "min_seconds": latencies_sorted[0] if n else 0.0,
        "max_seconds": latencies_sorted[-1] if n else 0.0,
        "median_seconds": latencies_sorted[n // 2] if n else 0.0,
    }

    return {"overall": overall, "per_type": per_type, "latency": latency_stats}


def evaluate_leakage(rows: list[dict]) -> dict:
    """Runs PIIGuard().protect() (DEFAULT policy) for every example and
    checks whether any ground-truth PII value leaked into the protected
    output. Only entities whose DEFAULT_POLICY action is "mask" or
    "tokenize" are checked -- "ignore" entities are excluded on purpose."""
    guard = PIIGuard()
    total_checked = 0
    exact_leaks = 0
    canonical_leaks = 0
    total_leaked = 0

    for row in rows:
        protected = guard.protect([{"role": "user", "content": row["text"]}])
        content = protected.messages[0]["content"]
        for ent in row["entities"]:
            action = DEFAULT_POLICY.get(ent["type"])
            if action not in ("mask", "tokenize"):
                continue  # "ignore" (or unknown type) -- not checked
            total_checked += 1
            exact, canonical = check_leakage(ent["type"], ent["value"], content)
            leaked = exact or canonical
            if exact:
                exact_leaks += 1
            if canonical:
                canonical_leaks += 1
            if leaked:
                total_leaked += 1

    leakage_rate = total_leaked / total_checked if total_checked else 0.0
    return {
        "total_pii_values_checked": total_checked,
        "exact_substring_leaks": exact_leaks,
        "canonical_leaks": canonical_leaks,
        "total_leaked": total_leaked,
        "leakage_rate": leakage_rate,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_config_report(name: str, result: dict) -> None:
    o = result["overall"]
    print(f"\n=== {name} -- overall ===")
    print(f"  TP={o['tp']} FP={o['fp']} FN={o['fn']}  "
          f"precision={o['precision']:.3f} recall={o['recall']:.3f} f1={o['f1']:.3f}")

    print(f"  -- per entity type --")
    for t, s in sorted(result["per_type"].items()):
        print(f"  {t:10s} TP={s['tp']:3d} FP={s['fp']:3d} FN={s['fn']:3d}  "
              f"precision={s['precision']:.3f} recall={s['recall']:.3f} f1={s['f1']:.3f}")

    lat = result["latency"]
    print(f"  -- latency (n={lat['count']}) --")
    print(f"  mean={lat['mean_seconds']*1000:.2f}ms  median={lat['median_seconds']*1000:.2f}ms  "
          f"min={lat['min_seconds']*1000:.2f}ms  max={lat['max_seconds']*1000:.2f}ms")


def _print_leakage_report(leakage: dict) -> None:
    print("\n=== Privacy leakage (PIIGuard().protect(), DEFAULT_POLICY) ===")
    print(f"  total_pii_values_checked={leakage['total_pii_values_checked']}")
    print(f"  exact_substring_leaks={leakage['exact_substring_leaks']}")
    print(f"  canonical_leaks={leakage['canonical_leaks']}")
    print(f"  total_leaked={leakage['total_leaked']}")
    print(f"  leakage_rate={leakage['leakage_rate']:.4f}")
    print(
        "  NOTE: zero leakage here is an evaluation-set invariant (this "
        "dataset's phrasings are all caught), NOT proof BharatGuard can "
        "never miss PII in arbitrary real-world input."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="BharatGuard evaluation harness")
    parser.add_argument(
        "--debug", action="store_true",
        help="Print per-example detail (raw synthetic PII values). Off by default.",
    )
    args = parser.parse_args()

    if args.debug:
        print("!" * 70)
        print("!! --debug prints synthetic PII test fixtures to stdout !!")
        print("!" * 70)

    rows = load_dataset(DATASET_PATH)
    print(f"Loaded {len(rows)} dataset examples from {DATASET_PATH.name}")

    config_a = evaluate_config(rows, DETERMINISTIC_DETECTORS)
    _print_config_report("Config A (deterministic only)", config_a)

    config_b = evaluate_config(rows, DETERMINISTIC_DETECTORS + CONTEXTUAL_DETECTORS)
    _print_config_report("Config B (deterministic + contextual)", config_b)

    leakage = evaluate_leakage(rows)
    _print_leakage_report(leakage)

    if args.debug:
        print("\n=== --debug: per-example detail ===")
        for row in rows:
            entities, _ = detect(row["text"], DETERMINISTIC_DETECTORS + CONTEXTUAL_DETECTORS)
            print(f"[{row['id']}] category={row['category']}")
            print(f"  text: {row['text']!r}")
            print(f"  gold: {row['entities']}")
            print(f"  predicted: {[(e.entity_type, e.start, e.end) for e in entities]}")


if __name__ == "__main__":
    main()

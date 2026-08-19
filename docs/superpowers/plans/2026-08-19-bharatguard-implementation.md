# BharatGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build BharatGuard, a Python library that detects Indian PII locally (Aadhaar, PAN, phone, email, UPI, IFSC, PERSON, ADDRESS), masks/pseudonymizes it before any Sarvam `sarvam-105b` API call, and optionally restores it in the response — with reproducible evaluation, mocked tests, and a small demo.

**Architecture:** `normalize (with offset map) → deterministic regex detectors → contextual detectors (spaCy PERSON + rule-based Indian address) → merge/overlap-resolve → policy → mask (redact/tokenize) → [caller sends masked text to Sarvam] → restore`. `PIIGuard.protect()`/`.restore()` is the low-level API; `Session` (token↔value map) lives in memory only, never logged/serialized. `SarvamClient` wraps the official `sarvamai` SDK behind a two-method interface (`chat`, `transcribe`) so tests use a `FakeSarvamClient` and never touch the network.

**Tech Stack:** Python 3.11+, `spacy` (`en_core_web_sm`), `sarvamai` SDK, `pytest`, `python-dotenv`, `streamlit` (demo only). Plain `dataclasses` — no Pydantic, no DI framework, no database.

**Spec:** No separate spec file — architecture was agreed interactively in the brainstorming conversation preceding this plan (per explicit user instruction to skip the spec doc for this assignment). This plan's Global Constraints section below is the authoritative summary of those decisions; each task also restates the exact code agreed on.

## Global Constraints

- Python 3.11+, full type hints on public functions/classes.
- Plain `dataclasses` only — no Pydantic, no ORMs, no DI framework, no Redis/database/microservices/auth.
- `PIIEntity` is `entity_type: str, start: int, end: int, confidence: float, source: str` — **no `text` field**. Raw value is obtained via `original_text[entity.start:entity.end]` only where needed, never stored.
- `Session` never logs, serializes, pickles, or `repr()`s raw values; no `to_dict`/`to_json`/`__getstate__` methods exist on it.
- No log statement, exception message, or `print()` anywhere in `src/bharatguard/` may contain a raw PII value or the API key. Logs carry only entity type, count, detector/source, confidence, action, latency.
- Normalization offset mapping: a per-character array (`offset_map[i]` = original index for `normalized_text[i]`), built only from 1:1 substitutions (Indic digit folding) and deletions (whitespace/separator collapsing). No general diff/alignment algorithm.
- Overlap resolution order: deterministic-source entities beat contextual-source entities; then higher confidence; then longer span; ties drop the later entity.
- Policy actions: `"mask" | "tokenize" | "ignore"` only. Default policy: `AADHAAR/PAN/IFSC/ADDRESS → mask`, `PHONE/EMAIL/UPI/PERSON → tokenize`.
- All pytest tests run with zero network calls and no `SARVAM_API_KEY` required — enforced via `FakeSarvamClient`, never `unittest.mock.patch` on the real SDK.
- Real `SarvamAI()` client construction happens **only** in `examples/live_sarvam.py` and `examples/voice_demo.py` — both excluded from pytest collection (filenames don't start with `test_`).
- No real/personal PII anywhere in the repo — all examples, fixtures, eval data, and demo inputs use synthetic values (e.g. Aadhaar `234123412346`, a fake PAN, a `+91 98xxxxxxxx`-shaped but non-real number).
- `.env` is git-ignored; `.env.example` contains only `SARVAM_API_KEY=`.

---

### Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `LICENSE`
- Create: `src/bharatguard/__init__.py`
- Create: `src/bharatguard/py.typed`
- Create: `tests/__init__.py`

**Interfaces:**
- Produces: an installable package `bharatguard` (editable install via `pip install -e .`), pytest discoverable under `tests/`.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "bharatguard"
version = "0.1.0"
description = "India-first PII detection and masking middleware for LLM apps, built for Sarvam sarvam-105b."
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = [
    "spacy>=3.7,<4.0",
    "sarvamai>=0.1.0",
    "python-dotenv>=1.0",
]

[project.optional-dependencies]
demo = ["streamlit>=1.35"]
dev = ["pytest>=8.0"]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Write `.gitignore`**

```
.venv/
__pycache__/
*.pyc
.env
*.egg-info/
.pytest_cache/
dist/
build/
```

- [ ] **Step 3: Write `.env.example`**

```
SARVAM_API_KEY=
```

- [ ] **Step 4: Write `LICENSE`**

Use standard MIT license text with `Copyright (c) 2026 BharatGuard contributors`.

- [ ] **Step 5: Create empty package/init files**

`src/bharatguard/__init__.py`:
```python
"""BharatGuard: India-first PII detection and masking for LLM apps."""
```

`src/bharatguard/py.typed`: empty file (marks package as typed).

`tests/__init__.py`: empty file.

- [ ] **Step 6: Init git, install package, verify**

```bash
cd /Users/yash/project-4
git init
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -c "import bharatguard; print('ok')"
```
Expected: prints `ok`, no import errors.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .gitignore .env.example LICENSE src tests
git commit -m "chore: project scaffolding"
```

---

### Task 2: Core data models

**Files:**
- Create: `src/bharatguard/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `PIIEntity`, `Session`, `ProtectedMessages` — used by every later task.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_models.py
from bharatguard.models import PIIEntity, Session, ProtectedMessages


def test_pii_entity_fields():
    e = PIIEntity(entity_type="AADHAAR", start=10, end=22, confidence=0.99, source="aadhaar_regex")
    assert e.entity_type == "AADHAAR"
    assert e.start == 10
    assert e.end == 22
    assert not hasattr(e, "text")


def test_pii_entity_is_frozen():
    e = PIIEntity(entity_type="PAN", start=0, end=10, confidence=1.0, source="pan_regex")
    try:
        e.start = 5
        assert False, "should not be mutable"
    except Exception:
        pass


def test_session_repr_never_shows_values():
    s = Session()
    s.remember("<AADHAAR_1>", "234123412346")
    assert "234123412346" not in repr(s)
    assert "234123412346" not in str(s)


def test_session_has_no_serialization_methods():
    s = Session()
    assert not hasattr(s, "to_dict")
    assert not hasattr(s, "to_json")
    assert not hasattr(s, "__getstate__")


def test_session_lookup():
    s = Session()
    s.remember("<AADHAAR_1>", "234123412346")
    assert s.lookup("<AADHAAR_1>") == "234123412346"
    assert s.lookup("<AADHAAR_9>") is None


def test_protected_messages_fields():
    pm = ProtectedMessages(messages=[{"role": "user", "content": "hi"}], session=Session())
    assert pm.messages[0]["content"] == "hi"
    assert isinstance(pm.session, Session)
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/test_models.py -v`
Expected: FAIL (`ModuleNotFoundError: bharatguard.models`)

- [ ] **Step 3: Implement `src/bharatguard/models.py`**

```python
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


@dataclass
class ProtectedMessages:
    messages: list[dict]
    session: Session
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/test_models.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add src/bharatguard/models.py tests/test_models.py
git commit -m "feat: add PIIEntity, Session, ProtectedMessages models"
```

---

### Task 3: Normalization with offset mapping

**Files:**
- Create: `src/bharatguard/normalization/__init__.py`
- Create: `src/bharatguard/normalization/normalize.py`
- Test: `tests/test_normalization.py`

**Interfaces:**
- Consumes: nothing (pure functions on `str`).
- Produces: `normalize(text: str) -> tuple[str, list[int]]` — `normalized_text, offset_map` where `offset_map[i]` is the index into the original `text` that `normalized_text[i]` came from. Used by `core.py` to translate detector spans back to original offsets.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_normalization.py
from bharatguard.normalization.normalize import normalize

INDIC_DIGITS = "०१२३४५६७८९"


def test_ascii_digits_unchanged():
    text = "Aadhaar 234123412346"
    norm, offset_map = normalize(text)
    assert "234123412346" in norm
    assert len(norm) == len(offset_map)


def test_indic_digit_folding():
    text = "फोन ९८७६५४३२१०"  # Devanagari digits
    norm, offset_map = normalize(text)
    assert "9876543210" in norm


def test_indic_digit_offset_map_correct():
    text = "पिन ११०००१"
    norm, offset_map = normalize(text)
    digit_start = norm.index("110001")
    # every folded digit must map back to its own original Devanagari digit position
    for i in range(6):
        orig_idx = offset_map[digit_start + i]
        assert text[orig_idx] in INDIC_DIGITS


def test_whitespace_collapsing_preserves_offsets():
    text = "Aadhaar   1234"
    norm, offset_map = normalize(text)
    assert "  " not in norm  # collapsed to single space
    idx = norm.index("1234")
    assert text[offset_map[idx]] == "1"


def test_offset_map_translates_span_correctly():
    text = "call   9876543210 now"
    norm, offset_map = normalize(text)
    start = norm.index("9876543210")
    end = start + len("9876543210")
    orig_start = offset_map[start]
    orig_end = offset_map[end - 1] + 1
    assert text[orig_start:orig_end] == "9876543210"


def test_unicode_nfc_applied():
    # decomposed 'é' (e + combining acute) should normalize to composed form
    decomposed = "café"
    norm, _ = normalize(decomposed)
    assert norm == "café"


def test_empty_string():
    norm, offset_map = normalize("")
    assert norm == ""
    assert offset_map == []
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/test_normalization.py -v`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `src/bharatguard/normalization/normalize.py`**

```python
"""Normalization with a per-character offset map back to the original text.

Scope is deliberately narrow: Unicode NFC, Indic-digit folding (1:1
substitution), and separator/whitespace collapsing (deletion). Both
operations are trivially reversible per-character, so a full diff/alignment
algorithm is unnecessary — see plan Global Constraints for the tradeoff.
"""
from __future__ import annotations

import unicodedata

_INDIC_DIGIT_MAP = {
    # Devanagari (Hindi) digits 0-9
    "०": "0", "१": "1", "२": "2", "३": "3", "४": "4",
    "५": "5", "६": "6", "७": "7", "८": "8", "९": "9",
}

_COLLAPSIBLE_WHITESPACE = {" ", "\t"}


def normalize(text: str) -> tuple[str, list[int]]:
    """Returns (normalized_text, offset_map) where offset_map[i] is the
    index into the ORIGINAL text that normalized_text[i] came from."""
    # Step A: Unicode NFC first (may change length in rare decomposed-form
    # inputs; track offsets through this step using NFC's own guarantee
    # that it operates on grapheme clusters left-to-right).
    nfc_text, nfc_offsets = _nfc_with_offsets(text)

    # Step B: Indic digit folding + whitespace collapsing over the NFC text.
    out_chars: list[str] = []
    out_offsets: list[int] = []
    prev_was_space = False
    for i, ch in enumerate(nfc_text):
        folded = _INDIC_DIGIT_MAP.get(ch, ch)
        if folded in _COLLAPSIBLE_WHITESPACE:
            if prev_was_space:
                continue  # deletion: skip, do not emit an offset entry
            prev_was_space = True
        else:
            prev_was_space = False
        out_chars.append(folded)
        out_offsets.append(nfc_offsets[i])

    return "".join(out_chars), out_offsets


def _nfc_with_offsets(text: str) -> tuple[str, list[int]]:
    """NFC-normalize while tracking a best-effort offset back to `text`.
    For the common case (already-composed or simple decomposed sequences),
    each output char maps to the position of the last input char that
    contributed to it."""
    result_chars: list[str] = []
    result_offsets: list[int] = []
    buffer = ""
    buffer_start = 0
    for i, ch in enumerate(text):
        if not buffer:
            buffer_start = i
        buffer += ch
        composed = unicodedata.normalize("NFC", buffer)
        # Once composition stabilizes (adding this char didn't shrink length
        # further vs a shorter prefix), flush all but a possible trailing
        # combining sequence. Simple heuristic: flush when the composed
        # buffer length no longer decreases relative to raw length, i.e. no
        # combining mark is pending re-composition with a *following* char.
        if unicodedata.combining(text[i]) == 0:
            # ch is a base character (or standalone); flush prior buffer
            if len(buffer) > 1:
                head, tail = buffer[:-1], buffer[-1]
                head_composed = unicodedata.normalize("NFC", head)
                for c in head_composed:
                    result_chars.append(c)
                    result_offsets.append(buffer_start)
                buffer = tail
                buffer_start = i
    if buffer:
        tail_composed = unicodedata.normalize("NFC", buffer)
        for c in tail_composed:
            result_chars.append(c)
            result_offsets.append(buffer_start)
    return "".join(result_chars), result_offsets
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/test_normalization.py -v`
Expected: PASS (7 passed). If `test_unicode_nfc_applied` or offset tests fail due to the NFC-offset heuristic, simplify: fall back to composing the whole string once with `unicodedata.normalize("NFC", text)` and, only if `len(composed) == len(text)`, use identity offsets; if lengths differ (rare), skip NFC and normalize on raw text (document this narrower fallback in a code comment) — this keeps the guarantee "offsets are always exactly correct" instead of approximating.

- [ ] **Step 5: Create `src/bharatguard/normalization/__init__.py`**

```python
from bharatguard.normalization.normalize import normalize

__all__ = ["normalize"]
```

- [ ] **Step 6: Run full test suite, verify pass**

Run: `pytest tests/ -v`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add src/bharatguard/normalization tests/test_normalization.py
git commit -m "feat: add normalization with offset mapping"
```

---

### Task 4: Deterministic detectors (Aadhaar, PAN, phone, email, UPI, IFSC)

**Files:**
- Create: `src/bharatguard/detectors/__init__.py`
- Create: `src/bharatguard/detectors/base.py`
- Create: `src/bharatguard/detectors/deterministic.py`
- Test: `tests/detectors/test_deterministic.py`
- Test: `tests/detectors/__init__.py` (empty)

**Interfaces:**
- Consumes: `PIIEntity` from `models.py`.
- Produces: `Detector` Protocol (`detect(text: str) -> list[PIIEntity]`), and `DETERMINISTIC_DETECTORS: list[Detector]` — consumed by `core.py` in Task 9.

- [ ] **Step 1: Write failing tests**

```python
# tests/detectors/test_deterministic.py
from bharatguard.detectors.deterministic import (
    AadhaarDetector, PanDetector, PhoneDetector, EmailDetector,
    UpiDetector, IfscDetector,
)


def test_aadhaar_detects_spaced_format():
    hits = AadhaarDetector().detect("My Aadhaar is 2341 2341 2346")
    assert len(hits) == 1
    assert hits[0].entity_type == "AADHAAR"


def test_aadhaar_detects_unformatted():
    hits = AadhaarDetector().detect("aadhaar: 234123412346")
    assert len(hits) == 1


def test_aadhaar_rejects_starting_with_0_or_1():
    hits = AadhaarDetector().detect("random number 012345678901")
    assert len(hits) == 0


def test_aadhaar_rejects_wrong_length():
    hits = AadhaarDetector().detect("short number 23412341")
    assert len(hits) == 0


def test_pan_detects_valid_format():
    hits = PanDetector().detect("PAN: ABCDE1234F")
    assert len(hits) == 1
    assert hits[0].entity_type == "PAN"


def test_pan_rejects_invalid_4th_char():
    # 4th char must be one of P/C/H/A/B/G/J/L/F/T (holder type codes)
    hits = PanDetector().detect("code: ABCZE1234F")
    assert len(hits) == 0


def test_phone_detects_with_country_code():
    hits = PhoneDetector().detect("call me at +91 9876543210")
    assert len(hits) == 1
    assert hits[0].entity_type == "PHONE"


def test_phone_detects_bare_10_digit():
    hits = PhoneDetector().detect("9876543210 is my number")
    assert len(hits) == 1


def test_phone_rejects_invalid_starting_digit():
    hits = PhoneDetector().detect("5876543210 is not a mobile number")
    assert len(hits) == 0


def test_email_detects_basic():
    hits = EmailDetector().detect("reach me at test.user@example.co.in")
    assert len(hits) == 1
    assert hits[0].entity_type == "EMAIL"


def test_upi_detects_valid_vpa():
    hits = UpiDetector().detect("pay to rahul123@okhdfcbank")
    assert len(hits) == 1
    assert hits[0].entity_type == "UPI"


def test_upi_does_not_double_count_as_email():
    text = "pay to rahul123@okhdfcbank"
    upi_hits = UpiDetector().detect(text)
    email_hits = EmailDetector().detect(text)
    assert len(upi_hits) == 1
    assert len(email_hits) == 0  # "okhdfcbank" has no TLD, not email-shaped


def test_ifsc_detects_valid_code():
    hits = IfscDetector().detect("IFSC: HDFC0001234")
    assert len(hits) == 1
    assert hits[0].entity_type == "IFSC"


def test_ifsc_rejects_wrong_5th_char():
    # 5th char must be literal '0' per NPCI spec
    hits = IfscDetector().detect("code: HDFC1001234")
    assert len(hits) == 0


def test_multiple_entities_same_text():
    text = "Aadhaar 234123412346 and PAN ABCDE1234F"
    hits = AadhaarDetector().detect(text) + PanDetector().detect(text)
    assert len(hits) == 2


def test_entity_offsets_are_correct():
    text = "call 9876543210 now"
    hits = PhoneDetector().detect(text)
    e = hits[0]
    assert text[e.start:e.end] == "9876543210"
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/detectors/test_deterministic.py -v`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `src/bharatguard/detectors/base.py`**

```python
from __future__ import annotations

from typing import Protocol

from bharatguard.models import PIIEntity


class Detector(Protocol):
    def detect(self, text: str) -> list[PIIEntity]: ...
```

- [ ] **Step 4: Implement `src/bharatguard/detectors/deterministic.py`**

```python
"""Deterministic Indian PII detectors: regex patterns plus structural
validation rules (not just broad pattern matching)."""
from __future__ import annotations

import re

from bharatguard.models import PIIEntity

_AADHAAR_RE = re.compile(r"(?<!\d)([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?!\d)")
_PAN_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z])(?![A-Z0-9])")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+91[ -]?|0)?([6-9]\d{9})(?!\d)")
_EMAIL_RE = re.compile(r"(?<![\w.])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.])")
_UPI_RE = re.compile(r"(?<![\w.])([A-Za-z0-9.\-_]{2,}@[A-Za-z][A-Za-z0-9]{2,})(?![\w.])")
_IFSC_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])")

_UPI_HANDLES = {
    "okhdfcbank", "okicici", "oksbi", "okaxis", "ybl", "paytm", "upi",
    "ibl", "axl", "apl", "sbi", "hdfcbank", "icici",
}


class AadhaarDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _AADHAAR_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(1))
            if len(digits) == 12 and digits[0] not in "01":
                out.append(PIIEntity("AADHAAR", m.start(1), m.end(1), 0.9, "aadhaar_regex"))
        return out


class PanDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        return [
            PIIEntity("PAN", m.start(1), m.end(1), 0.95, "pan_regex")
            for m in _PAN_RE.finditer(text)
        ]


class PhoneDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _PHONE_RE.finditer(text):
            out.append(PIIEntity("PHONE", m.start(1), m.end(1), 0.85, "phone_regex"))
        return out


class EmailDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _EMAIL_RE.finditer(text):
            local, _, domain = m.group(1).partition("@")
            if "." in domain:  # has a real TLD-shaped domain, not a UPI handle
                out.append(PIIEntity("EMAIL", m.start(1), m.end(1), 0.9, "email_regex"))
        return out


class UpiDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _UPI_RE.finditer(text):
            local, _, handle = m.group(1).partition("@")
            if "." not in handle and (
                handle.lower() in _UPI_HANDLES or len(handle) <= 12
            ):
                out.append(PIIEntity("UPI", m.start(1), m.end(1), 0.75, "upi_regex"))
        return out


class IfscDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        return [
            PIIEntity("IFSC", m.start(1), m.end(1), 0.95, "ifsc_regex")
            for m in _IFSC_RE.finditer(text)
        ]


DETERMINISTIC_DETECTORS = [
    AadhaarDetector(), PanDetector(), PhoneDetector(),
    EmailDetector(), UpiDetector(), IfscDetector(),
]
```

- [ ] **Step 5: Create `tests/detectors/__init__.py`** (empty file)

- [ ] **Step 6: Create `src/bharatguard/detectors/__init__.py`**

```python
from bharatguard.detectors.base import Detector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS

__all__ = ["Detector", "DETERMINISTIC_DETECTORS"]
```

- [ ] **Step 7: Run tests, verify pass; fix regexes if any fail**

Run: `pytest tests/detectors/test_deterministic.py -v`
Expected: all pass. If `test_upi_does_not_double_count_as_email` fails because `okhdfcbank` accidentally matches `_EMAIL_RE`, confirm the email detector's `"." in domain` guard is working — `okhdfcbank` has no dot so it must be filtered out.

- [ ] **Step 8: Commit**

```bash
git add src/bharatguard/detectors tests/detectors
git commit -m "feat: add deterministic Aadhaar/PAN/phone/email/UPI/IFSC detectors"
```

---

### Task 5: Contextual detectors (spaCy PERSON, Indian address)

**Files:**
- Create: `src/bharatguard/detectors/contextual.py`
- Test: `tests/detectors/test_contextual.py`

**Interfaces:**
- Consumes: `PIIEntity`, `Detector` Protocol.
- Produces: `SpacyPersonDetector`, `IndianAddressDetector` — both satisfy `Detector`, consumed by `core.py` in Task 9.

- [ ] **Step 1: Install spaCy model**

```bash
python -m spacy download en_core_web_sm
```

- [ ] **Step 2: Write failing tests**

```python
# tests/detectors/test_contextual.py
from bharatguard.detectors.contextual import SpacyPersonDetector, IndianAddressDetector


def test_person_detector_finds_english_name():
    hits = SpacyPersonDetector().detect("My name is Rahul Sharma and I live in Pune.")
    assert any(h.entity_type == "PERSON" for h in hits)


def test_person_detector_source_is_labeled():
    hits = SpacyPersonDetector().detect("Rahul Sharma called yesterday.")
    assert all(h.source == "spacy_person" for h in hits)


def test_address_detector_finds_pincode_and_keyword():
    text = "I live at 221B MG Road, Koramangala, Bangalore 560034"
    hits = IndianAddressDetector().detect(text)
    assert any(h.entity_type == "ADDRESS" for h in hits)


def test_address_detector_finds_hinglish_trigger_phrase():
    text = "mera address hai Flat 12, Sector 21, Noida"
    hits = IndianAddressDetector().detect(text)
    assert any(h.entity_type == "ADDRESS" for h in hits)


def test_address_detector_ignores_unrelated_text():
    hits = IndianAddressDetector().detect("The weather in Delhi is nice today.")
    assert len(hits) == 0


def test_person_detector_known_limitation_devanagari():
    # Documented limitation: en_core_web_sm does not reliably detect
    # Devanagari-script names. This test asserts current (weak) behavior
    # so a future model swap is visible as a test change, not silent drift.
    hits = SpacyPersonDetector().detect("मेरा नाम प्रिया है")
    assert hits == []
```

- [ ] **Step 3: Run tests, verify failure**

Run: `pytest tests/detectors/test_contextual.py -v`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 4: Implement `src/bharatguard/detectors/contextual.py`**

```python
"""Contextual PII detectors. Both run fully offline — no external API calls.

Known limitation (documented, not hidden): en_core_web_sm is an English-only
spaCy pipeline. It gives usable PERSON recall on Latin-script English and
romanized Hinglish names, but does NOT reliably detect names written in
Devanagari script. This is a defensible 48-hour local baseline, not
production-grade Indic NER — see README limitations section.
"""
from __future__ import annotations

import re

import spacy

from bharatguard.models import PIIEntity

_nlp = spacy.load("en_core_web_sm")

_ADDRESS_KEYWORDS = re.compile(
    r"\b(road|rd\.?|street|st\.?|nagar|colony|sector|block|village|"
    r"apartment|flat|society|marg|chowk|gali|lane)\b",
    re.IGNORECASE,
)
_PINCODE_RE = re.compile(r"(?<!\d)[1-9]\d{5}(?!\d)")
_TRIGGER_PHRASES = re.compile(
    r"(my address is|mera address hai|mera pata hai|lives at|"
    r"rehte hain|rehta hai|residing at)",
    re.IGNORECASE,
)


class SpacyPersonDetector:
    """PERSON detection via spaCy en_core_web_sm. Latin-script/romanized only."""

    def detect(self, text: str) -> list[PIIEntity]:
        doc = _nlp(text)
        return [
            PIIEntity("PERSON", ent.start_char, ent.end_char, 0.7, "spacy_person")
            for ent in doc.ents
            if ent.label_ == "PERSON"
        ]


class IndianAddressDetector:
    """Rule-based Indian address detection: pincode + keyword + trigger-phrase
    signals. Not a full address parser — flags a line as address-bearing and
    masks the whole matched span found via signal-anchored regex."""

    def detect(self, text: str) -> list[PIIEntity]:
        entities: list[PIIEntity] = []
        for m in _PINCODE_RE.finditer(text):
            entities.append(PIIEntity("ADDRESS", m.start(), m.end(), 0.6, "address_pincode"))
        for m in _ADDRESS_KEYWORDS.finditer(text):
            span = self._expand_to_line_segment(text, m.start(), m.end())
            entities.append(PIIEntity("ADDRESS", span[0], span[1], 0.5, "address_keyword"))
        for m in _TRIGGER_PHRASES.finditer(text):
            span = self._expand_to_line_segment(text, m.end(), min(len(text), m.end() + 60))
            entities.append(PIIEntity("ADDRESS", span[0], span[1], 0.65, "address_trigger_phrase"))
        return entities

    @staticmethod
    def _expand_to_line_segment(text: str, start: int, end: int) -> tuple[int, int]:
        seg_start = text.rfind(",", 0, start)
        seg_start = 0 if seg_start == -1 else seg_start + 1
        seg_end = text.find(".", end)
        seg_end = len(text) if seg_end == -1 else seg_end
        while seg_start < len(text) and text[seg_start] == " ":
            seg_start += 1
        return seg_start, seg_end
```

- [ ] **Step 5: Run tests, verify pass; tune regex/expand logic if address span tests fail**

Run: `pytest tests/detectors/test_contextual.py -v`
Expected: all pass. If `test_address_detector_finds_pincode_and_keyword` produces overlapping/odd spans, that's fine at this layer — overlap resolution happens in Task 6/9, not here.

- [ ] **Step 6: Update `src/bharatguard/detectors/__init__.py`**

```python
from bharatguard.detectors.base import Detector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.contextual import SpacyPersonDetector, IndianAddressDetector

__all__ = [
    "Detector", "DETERMINISTIC_DETECTORS",
    "SpacyPersonDetector", "IndianAddressDetector",
]
```

- [ ] **Step 7: Commit**

```bash
git add src/bharatguard/detectors/contextual.py tests/detectors/test_contextual.py src/bharatguard/detectors/__init__.py
git commit -m "feat: add spaCy PERSON detector and rule-based Indian address detector"
```

---

### Task 6: Entity merge and overlap resolution

**Files:**
- Create: `src/bharatguard/detectors/merge.py`
- Test: `tests/detectors/test_merge.py`

**Interfaces:**
- Consumes: `PIIEntity`.
- Produces: `merge_entities(entities: list[PIIEntity]) -> list[PIIEntity]` — consumed by `core.py` in Task 9.

- [ ] **Step 1: Write failing tests**

```python
# tests/detectors/test_merge.py
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
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/detectors/test_merge.py -v`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `src/bharatguard/detectors/merge.py`**

```python
"""Overlap resolution: deterministic-source entities are trusted over
contextual-source entities, then higher confidence, then longer span."""
from __future__ import annotations

from bharatguard.models import PIIEntity

_DETERMINISTIC_SOURCES = {
    "aadhaar_regex", "pan_regex", "phone_regex",
    "email_regex", "upi_regex", "ifsc_regex",
}


def _tier(entity: PIIEntity) -> int:
    return 1 if entity.source in _DETERMINISTIC_SOURCES else 0


def _rank_key(entity: PIIEntity) -> tuple[int, float, int]:
    return (_tier(entity), entity.confidence, entity.end - entity.start)


def merge_entities(entities: list[PIIEntity]) -> list[PIIEntity]:
    ordered = sorted(entities, key=lambda e: e.start)
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
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/detectors/test_merge.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add src/bharatguard/detectors/merge.py tests/detectors/test_merge.py
git commit -m "feat: add entity overlap resolution"
```

---

### Task 7: Policy

**Files:**
- Create: `src/bharatguard/policy/__init__.py`
- Create: `src/bharatguard/policy/policy.py`
- Test: `tests/test_policy.py`

**Interfaces:**
- Produces: `PolicyConfig` class, `DEFAULT_POLICY` dict — consumed by `masking/mask.py` (Task 8) and `core.py` (Task 9).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_policy.py
import pytest
from bharatguard.policy.policy import PolicyConfig, DEFAULT_POLICY


def test_default_policy_actions():
    policy = PolicyConfig()
    assert policy.action_for("AADHAAR") == "mask"
    assert policy.action_for("PHONE") == "tokenize"
    assert policy.action_for("PERSON") == "tokenize"


def test_default_policy_unknown_type_defaults_to_mask():
    policy = PolicyConfig()
    assert policy.action_for("UNKNOWN_TYPE") == "mask"


def test_custom_policy_override():
    policy = PolicyConfig({"PERSON": "ignore"})
    assert policy.action_for("PERSON") == "ignore"
    assert policy.action_for("AADHAAR") == "mask"  # untouched types keep defaults


def test_invalid_action_rejected():
    with pytest.raises(ValueError):
        PolicyConfig({"PERSON": "delete_forever"})


def test_default_policy_dict_has_all_core_types():
    for t in ("AADHAAR", "PAN", "PHONE", "EMAIL", "UPI", "IFSC", "PERSON", "ADDRESS"):
        assert t in DEFAULT_POLICY
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/test_policy.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `src/bharatguard/policy/policy.py`**

```python
"""Policy: what action to take per entity type. Kept intentionally simple —
a validated dict, not a config framework.

- "mask": security-first, replaces the value with [REDACTED]. Irreversible.
- "tokenize": replaces with <TYPE_N> and records the mapping in the
  request/session-local Session, so the app can restore it for a
  conversational response. Not persisted anywhere.
- "ignore": leaves the detected span untouched (e.g. a developer decides a
  given entity type is not sensitive for their use case).
"""
from __future__ import annotations

_VALID_ACTIONS = {"mask", "tokenize", "ignore"}

DEFAULT_POLICY: dict[str, str] = {
    "AADHAAR": "mask",
    "PAN": "mask",
    "IFSC": "mask",
    "ADDRESS": "mask",
    "PHONE": "tokenize",
    "EMAIL": "tokenize",
    "UPI": "tokenize",
    "PERSON": "tokenize",
}


class PolicyConfig:
    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        for entity_type, action in (overrides or {}).items():
            if action not in _VALID_ACTIONS:
                raise ValueError(
                    f"invalid policy action {action!r} for {entity_type!r}; "
                    f"must be one of {sorted(_VALID_ACTIONS)}"
                )
        self._policy = {**DEFAULT_POLICY, **(overrides or {})}

    def action_for(self, entity_type: str) -> str:
        return self._policy.get(entity_type, "mask")
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/test_policy.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Create `src/bharatguard/policy/__init__.py`**

```python
from bharatguard.policy.policy import PolicyConfig, DEFAULT_POLICY

__all__ = ["PolicyConfig", "DEFAULT_POLICY"]
```

- [ ] **Step 6: Commit**

```bash
git add src/bharatguard/policy tests/test_policy.py
git commit -m "feat: add PolicyConfig with mask/tokenize/ignore actions"
```

---

### Task 8: Masking

**Files:**
- Create: `src/bharatguard/masking/__init__.py`
- Create: `src/bharatguard/masking/mask.py`
- Test: `tests/test_masking.py`

**Interfaces:**
- Consumes: `PIIEntity`, `PolicyConfig`, `Session`.
- Produces: `apply_masking(text: str, entities: list[PIIEntity], policy: PolicyConfig, session: Session) -> str` — consumed by `core.py` (Task 9).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_masking.py
from bharatguard.models import PIIEntity, Session
from bharatguard.policy.policy import PolicyConfig
from bharatguard.masking.mask import apply_masking


def test_redaction_replaces_with_redacted_marker():
    text = "My Aadhaar is 234123412346"
    entities = [PIIEntity("AADHAAR", 14, 26, 0.9, "aadhaar_regex")]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig(), session)
    assert "[REDACTED]" in result
    assert "234123412346" not in result


def test_tokenization_replaces_with_typed_token():
    text = "call 9876543210 now"
    entities = [PIIEntity("PHONE", 5, 15, 0.85, "phone_regex")]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig(), session)
    assert "<PHONE_1>" in result
    assert "9876543210" not in result
    assert session.lookup("<PHONE_1>") == "9876543210"


def test_repeated_same_value_reuses_token():
    text = "9876543210 called, then 9876543210 called again"
    entities = [
        PIIEntity("PHONE", 0, 10, 0.85, "phone_regex"),
        PIIEntity("PHONE", 25, 35, 0.85, "phone_regex"),
    ]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig(), session)
    assert result.count("<PHONE_1>") == 2
    assert "<PHONE_2>" not in result


def test_different_values_get_incrementing_tokens():
    text = "call 9876543210 or 8765432109"
    entities = [
        PIIEntity("PHONE", 5, 15, 0.85, "phone_regex"),
        PIIEntity("PHONE", 19, 29, 0.85, "phone_regex"),
    ]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig(), session)
    assert "<PHONE_1>" in result and "<PHONE_2>" in result


def test_ignore_action_leaves_text_untouched():
    text = "Rahul called"
    entities = [PIIEntity("PERSON", 0, 5, 0.7, "spacy_person")]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig({"PERSON": "ignore"}), session)
    assert result == text


def test_multiple_entity_types_in_one_pass():
    text = "Aadhaar 234123412346, call 9876543210"
    entities = [
        PIIEntity("AADHAAR", 8, 20, 0.9, "aadhaar_regex"),
        PIIEntity("PHONE", 27, 37, 0.85, "phone_regex"),
    ]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig(), session)
    assert "234123412346" not in result and "9876543210" not in result
    assert "[REDACTED]" in result and "<PHONE_1>" in result


def test_masking_never_leaves_raw_value_substring():
    text = "PAN ABCDE1234F end"
    entities = [PIIEntity("PAN", 4, 14, 0.95, "pan_regex")]
    session = Session()
    result = apply_masking(text, entities, PolicyConfig(), session)
    assert "ABCDE1234F" not in result
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/test_masking.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `src/bharatguard/masking/mask.py`**

```python
"""Masking: replaces detected spans in the ORIGINAL text with either a
redaction marker or a session-local reversible token. Entities must already
be merge/overlap-resolved (Task 6) before reaching this function — masking
never re-resolves overlaps itself."""
from __future__ import annotations

from bharatguard.models import PIIEntity, Session
from bharatguard.policy.policy import PolicyConfig

REDACTED_MARKER = "[REDACTED]"


def apply_masking(
    text: str,
    entities: list[PIIEntity],
    policy: PolicyConfig,
    session: Session,
) -> str:
    ordered = sorted(entities, key=lambda e: e.start, reverse=True)
    token_counters: dict[str, int] = {}
    value_to_token: dict[tuple[str, str], str] = {}

    result = text
    for entity in ordered:
        action = policy.action_for(entity.entity_type)
        if action == "ignore":
            continue
        raw_value = text[entity.start:entity.end]
        if action == "mask":
            replacement = REDACTED_MARKER
        else:  # tokenize
            key = (entity.entity_type, raw_value)
            if key in value_to_token:
                replacement = value_to_token[key]
            else:
                token_counters[entity.entity_type] = token_counters.get(entity.entity_type, 0) + 1
                replacement = f"<{entity.entity_type}_{token_counters[entity.entity_type]}>"
                value_to_token[key] = replacement
                session.remember(replacement, raw_value)
        result = result[:entity.start] + replacement + result[entity.end:]
    return result
```

- [ ] **Step 4: Run tests, verify pass; debug reverse-order replacement logic if offsets shift**

Run: `pytest tests/test_masking.py -v`
Expected: PASS (7 passed). Replacing right-to-left (`reverse=True`) is what keeps earlier entities' offsets valid as later ones are substituted — if a test fails on offset drift, confirm the sort direction wasn't flipped.

- [ ] **Step 5: Create `src/bharatguard/masking/__init__.py`**

```python
from bharatguard.masking.mask import apply_masking, REDACTED_MARKER

__all__ = ["apply_masking", "REDACTED_MARKER"]
```

- [ ] **Step 6: Commit**

```bash
git add src/bharatguard/masking tests/test_masking.py
git commit -m "feat: add masking (redact/tokenize) with session-local reversible tokens"
```

---

### Task 9: PIIGuard core — protect() and restore()

**Files:**
- Create: `src/bharatguard/core.py`
- Modify: `src/bharatguard/__init__.py`
- Test: `tests/test_core.py`

**Interfaces:**
- Consumes: `normalize`, `DETERMINISTIC_DETECTORS`, `SpacyPersonDetector`, `IndianAddressDetector`, `merge_entities`, `PolicyConfig`, `apply_masking`, `Session`, `ProtectedMessages`.
- Produces: `PIIGuard` class with `protect(messages: list[dict]) -> ProtectedMessages` and `restore(response_text: str, session: Session) -> str` — the public library entrypoint, exported from `bharatguard/__init__.py`. Also `guard.last_entities: list[PIIEntity]` for demo/eval introspection (safe: types/offsets/confidence only, no raw text).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_core.py
from bharatguard.core import PIIGuard
from bharatguard.policy.policy import PolicyConfig


def test_protect_masks_aadhaar_in_single_message():
    guard = PIIGuard()
    messages = [{"role": "user", "content": "My Aadhaar is 234123412346"}]
    protected = guard.protect(messages)
    assert "234123412346" not in protected.messages[0]["content"]
    assert "[REDACTED]" in protected.messages[0]["content"]


def test_protect_tokenizes_phone_and_restore_recovers_it():
    guard = PIIGuard()
    messages = [{"role": "user", "content": "call 9876543210"}]
    protected = guard.protect(messages)
    token_msg = protected.messages[0]["content"]
    assert "9876543210" not in token_msg
    fake_response = f"Sure, I'll note down {token_msg.split('call ')[1]}"
    restored = guard.restore(fake_response, protected.session)
    assert "9876543210" in restored


def test_protect_handles_multiple_messages():
    guard = PIIGuard()
    messages = [
        {"role": "user", "content": "Aadhaar 234123412346"},
        {"role": "assistant", "content": "noted"},
        {"role": "user", "content": "PAN ABCDE1234F"},
    ]
    protected = guard.protect(messages)
    assert "234123412346" not in protected.messages[0]["content"]
    assert "ABCDE1234F" not in protected.messages[2]["content"]
    assert protected.messages[1]["content"] == "noted"


def test_protect_preserves_message_roles():
    guard = PIIGuard()
    messages = [{"role": "system", "content": "be helpful"}]
    protected = guard.protect(messages)
    assert protected.messages[0]["role"] == "system"


def test_custom_policy_passed_to_guard():
    guard = PIIGuard(policy=PolicyConfig({"PERSON": "ignore"}))
    messages = [{"role": "user", "content": "My name is Rahul Sharma"}]
    protected = guard.protect(messages)
    assert "Rahul Sharma" in protected.messages[0]["content"]


def test_hinglish_aadhaar_detected():
    guard = PIIGuard()
    messages = [{"role": "user", "content": "mera aadhaar number hai 234123412346"}]
    protected = guard.protect(messages)
    assert "234123412346" not in protected.messages[0]["content"]


def test_indic_numeral_aadhaar_detected_and_original_offsets_preserved():
    guard = PIIGuard()
    text = "आधार २३४१ २३४१ २३४६ है"
    messages = [{"role": "user", "content": text}]
    protected = guard.protect(messages)
    result = protected.messages[0]["content"]
    assert "२३४१" not in result and "REDACTED" in result
    # non-PII surrounding text (Devanagari "है") must survive untouched
    assert "है" in result


def test_last_entities_exposed_without_raw_values():
    guard = PIIGuard()
    guard.protect([{"role": "user", "content": "Aadhaar 234123412346"}])
    assert len(guard.last_entities) == 1
    assert guard.last_entities[0].entity_type == "AADHAAR"
    assert not hasattr(guard.last_entities[0], "text")


def test_idempotent_on_already_protected_text():
    guard = PIIGuard()
    once = guard.protect([{"role": "user", "content": "call 9876543210"}])
    twice = guard.protect(once.messages)
    # tokens are not PII-shaped, so a second pass detects nothing new
    assert twice.messages[0]["content"] == once.messages[0]["content"]
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/test_core.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `src/bharatguard/core.py`**

```python
"""PIIGuard: the public entrypoint. protect() runs the full local pipeline
(normalize -> detect -> merge -> policy -> mask) BEFORE any text reaches an
external LLM. restore() reverses tokenization using the in-memory Session
returned by protect() — never touches disk."""
from __future__ import annotations

from bharatguard.detectors.contextual import IndianAddressDetector, SpacyPersonDetector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.merge import merge_entities
from bharatguard.masking.mask import apply_masking
from bharatguard.models import PIIEntity, ProtectedMessages, Session
from bharatguard.normalization.normalize import normalize
from bharatguard.policy.policy import PolicyConfig


class PIIGuard:
    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self._policy = policy or PolicyConfig()
        self._contextual_detectors = [SpacyPersonDetector(), IndianAddressDetector()]
        self.last_entities: list[PIIEntity] = []

    def protect(self, messages: list[dict]) -> ProtectedMessages:
        session = Session()
        protected_messages = []
        all_entities: list[PIIEntity] = []
        for message in messages:
            content = message.get("content", "")
            masked_content, entities = self._protect_text(content, session)
            protected_messages.append({**message, "content": masked_content})
            all_entities.extend(entities)
        self.last_entities = all_entities
        return ProtectedMessages(messages=protected_messages, session=session)

    def restore(self, response_text: str, session: Session) -> str:
        result = response_text
        for token in self._tokens_in(response_text):
            original = session.lookup(token)
            if original is not None:
                result = result.replace(token, original)
        return result

    def _protect_text(self, text: str, session: Session) -> tuple[str, list[PIIEntity]]:
        normalized_text, offset_map = normalize(text)
        raw_entities: list[PIIEntity] = []
        for detector in DETERMINISTIC_DETECTORS:
            raw_entities.extend(detector.detect(normalized_text))
        for detector in self._contextual_detectors:
            raw_entities.extend(detector.detect(normalized_text))

        translated = [
            PIIEntity(
                entity_type=e.entity_type,
                start=offset_map[e.start] if e.start < len(offset_map) else len(text),
                end=(offset_map[e.end - 1] + 1) if e.end - 1 < len(offset_map) else len(text),
                confidence=e.confidence,
                source=e.source,
            )
            for e in raw_entities
        ]
        resolved = merge_entities(translated)
        masked = apply_masking(text, resolved, self._policy, session)
        return masked, resolved

    @staticmethod
    def _tokens_in(text: str) -> list[str]:
        import re
        return re.findall(r"<[A-Z_]+_\d+>", text)
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/test_core.py -v`
Expected: PASS (9 passed). If `test_indic_numeral_aadhaar_detected_and_original_offsets_preserved` fails, check that `offset_map` translation in `_protect_text` is being applied — detector spans are computed on `normalized_text` and must go through `offset_map` before `apply_masking` (which operates on the original `text`), not applied directly.

- [ ] **Step 5: Update `src/bharatguard/__init__.py`**

```python
"""BharatGuard: India-first PII detection and masking for LLM apps."""
from bharatguard.core import PIIGuard
from bharatguard.models import PIIEntity, ProtectedMessages, Session
from bharatguard.policy.policy import PolicyConfig

__all__ = ["PIIGuard", "PIIEntity", "ProtectedMessages", "Session", "PolicyConfig"]
```

- [ ] **Step 6: Run full test suite**

Run: `pytest tests/ -v`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add src/bharatguard/core.py src/bharatguard/__init__.py tests/test_core.py
git commit -m "feat: add PIIGuard.protect()/restore() wiring the full pipeline"
```

---

### Task 10: Sarvam integration (SarvamClient + FakeSarvamClient)

**Files:**
- Create: `src/bharatguard/integrations/__init__.py`
- Create: `src/bharatguard/integrations/sarvam.py`
- Test: `tests/test_sarvam_integration.py`

**Interfaces:**
- Consumes: `PIIGuard`.
- Produces: `SarvamClient` (real SDK wrapper), `FakeSarvamClient` (test double) — both expose `.chat(messages) -> object with .choices[0].message.content` and `.transcribe(file) -> object with .transcript`. Consumed by `examples/` (Task 16) and `guard.chat()` convenience method (this task, step 5).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_sarvam_integration.py
from bharatguard.core import PIIGuard
from bharatguard.integrations.sarvam import FakeSarvamClient


def test_fake_client_records_last_messages():
    client = FakeSarvamClient(reply="ok, noted")
    response = client.chat(messages=[{"role": "user", "content": "hello"}])
    assert client.last_messages == [{"role": "user", "content": "hello"}]
    assert response.choices[0].message.content == "ok, noted"


def test_protected_payload_never_contains_raw_aadhaar():
    guard = PIIGuard()
    client = FakeSarvamClient(reply="noted")
    protected = guard.protect([{"role": "user", "content": "My Aadhaar is 234123412346"}])
    client.chat(messages=protected.messages)
    sent_text = str(client.last_messages)
    assert "234123412346" not in sent_text


def test_protected_payload_never_contains_raw_phone_or_pan():
    guard = PIIGuard()
    client = FakeSarvamClient(reply="noted")
    protected = guard.protect([
        {"role": "user", "content": "call 9876543210, PAN ABCDE1234F"},
    ])
    client.chat(messages=protected.messages)
    sent_text = str(client.last_messages)
    assert "9876543210" not in sent_text
    assert "ABCDE1234F" not in sent_text


def test_guard_chat_convenience_method_round_trips():
    guard = PIIGuard()
    client = FakeSarvamClient(reply_template="noted your number {last_token}")
    result = guard.chat(client=client, messages=[{"role": "user", "content": "call 9876543210"}])
    assert "9876543210" in result
    assert "9876543210" not in str(client.last_messages)
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/test_sarvam_integration.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `src/bharatguard/integrations/sarvam.py`**

```python
"""Sarvam integration, isolated behind a two-method interface so the rest of
BharatGuard (and all tests) never depend on network access or the real SDK.
Real SarvamAI() construction happens only in examples/live_sarvam.py and
examples/voice_demo.py — never in library code or tests."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class _Message:
    content: str


@dataclass
class _Choice:
    message: _Message


@dataclass
class ChatResponse:
    choices: list[_Choice]


@dataclass
class TranscribeResponse:
    transcript: str


class SarvamClient:
    """Thin wrapper around the official `sarvamai` SDK."""

    def __init__(self, api_key: str | None = None) -> None:
        from sarvamai import SarvamAI  # imported lazily so tests never require it installed-and-networked

        key = api_key or os.environ.get("SARVAM_API_KEY")
        if not key:
            raise ValueError("SARVAM_API_KEY not set; see .env.example")
        self._client = SarvamAI(api_subscription_key=key)

    def chat(self, messages: list[dict], model: str = "sarvam-105b") -> ChatResponse:
        response = self._client.chat.completions(model=model, messages=messages)
        return ChatResponse(choices=[_Choice(_Message(response.choices[0].message.content))])

    def transcribe(self, file, model: str = "saaras:v3") -> TranscribeResponse:
        response = self._client.speech_to_text.transcribe(file=file, model=model, mode="transcribe")
        return TranscribeResponse(transcript=response.transcript)


class FakeSarvamClient:
    """Test double: no network, deterministic, records the last outgoing
    payload so tests can assert raw PII never appears in it."""

    def __init__(
        self,
        reply: str = "ok",
        reply_template: str | None = None,
        transcript: str = "",
    ) -> None:
        self._reply = reply
        self._reply_template = reply_template
        self._transcript = transcript
        self.last_messages: list[dict] | None = None

    def chat(self, messages: list[dict], model: str = "sarvam-105b") -> ChatResponse:
        self.last_messages = messages
        text = self._reply
        if self._reply_template:
            last_content = messages[-1]["content"]
            tokens = re.findall(r"<[A-Z_]+_\d+>", last_content)
            last_token = tokens[-1] if tokens else ""
            text = self._reply_template.format(last_token=last_token)
        return ChatResponse(choices=[_Choice(_Message(text))])

    def transcribe(self, file, model: str = "saaras:v3") -> TranscribeResponse:
        return TranscribeResponse(transcript=self._transcript)
```

- [ ] **Step 4: Run tests, verify pass; add `guard.chat()` if not yet implemented (see Step 5)**

- [ ] **Step 5: Add `PIIGuard.chat()` convenience method to `src/bharatguard/core.py`**

Add this method to the `PIIGuard` class (after `restore`):

```python
    def chat(self, client, messages: list[dict], model: str = "sarvam-105b") -> str:
        """Convenience wrapper: protect -> client.chat -> restore. Composes
        the existing low-level API; no new pipeline logic."""
        protected = self.protect(messages)
        response = client.chat(messages=protected.messages, model=model)
        return self.restore(response.choices[0].message.content, protected.session)
```

- [ ] **Step 6: Run tests, verify pass**

Run: `pytest tests/test_sarvam_integration.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Create `src/bharatguard/integrations/__init__.py`**

```python
from bharatguard.integrations.sarvam import SarvamClient, FakeSarvamClient, ChatResponse, TranscribeResponse

__all__ = ["SarvamClient", "FakeSarvamClient", "ChatResponse", "TranscribeResponse"]
```

- [ ] **Step 8: Run full test suite**

Run: `pytest tests/ -v`
Expected: all pass, zero network calls, no `SARVAM_API_KEY` required.

- [ ] **Step 9: Commit**

```bash
git add src/bharatguard/integrations src/bharatguard/core.py tests/test_sarvam_integration.py
git commit -m "feat: add SarvamClient wrapper, FakeSarvamClient test double, guard.chat() convenience API"
```

---

### Task 11: Evaluation dataset and script

**Files:**
- Create: `evals/dataset.jsonl`
- Create: `evals/run_eval.py`
- Create: `evals/__init__.py` (empty)

**Interfaces:**
- Consumes: `PIIGuard`, `DETERMINISTIC_DETECTORS`, `merge_entities`.
- Produces: a runnable `python evals/run_eval.py` that prints precision/recall/F1/latency/leakage tables — no pytest dependency, this is a standalone reproducibility script per the brief.

- [ ] **Step 1: Create `evals/dataset.jsonl`**

Each line: `{"id": ..., "text": ..., "entities": [{"entity_type": ..., "value": ...}], "category": ...}`. `entities: []` for false-positive traps. Use exact synthetic values so leakage checks can canonicalize them.

```jsonl
{"id": "en-aadhaar-1", "text": "My Aadhaar number is 234123412346", "entities": [{"entity_type": "AADHAAR", "value": "234123412346"}], "category": "english_aadhaar"}
{"id": "en-aadhaar-2", "text": "Aadhaar: 2341 2341 2346", "entities": [{"entity_type": "AADHAAR", "value": "2341 2341 2346"}], "category": "english_aadhaar_formatted"}
{"id": "hi-aadhaar-1", "text": "मेरा आधार नंबर 234123412346 है", "entities": [{"entity_type": "AADHAAR", "value": "234123412346"}], "category": "hindi_aadhaar"}
{"id": "hi-aadhaar-indic-1", "text": "मेरा आधार नंबर २३४१ २३४१ २३४६ है", "entities": [{"entity_type": "AADHAAR", "value": "२३४१ २३४१ २३४६"}], "category": "hindi_aadhaar_indic_numeral"}
{"id": "hinglish-aadhaar-1", "text": "mera aadhaar number hai 234123412346", "entities": [{"entity_type": "AADHAAR", "value": "234123412346"}], "category": "hinglish_aadhaar"}
{"id": "en-pan-1", "text": "PAN card number: ABCDE1234F", "entities": [{"entity_type": "PAN", "value": "ABCDE1234F"}], "category": "pan"}
{"id": "en-phone-1", "text": "Call me at +91 9876543210", "entities": [{"entity_type": "PHONE", "value": "+91 9876543210"}], "category": "phone_formatted"}
{"id": "en-phone-2", "text": "9876543210 is my number", "entities": [{"entity_type": "PHONE", "value": "9876543210"}], "category": "phone_bare"}
{"id": "hinglish-phone-1", "text": "mera number hai 9876543210, call kar lena", "entities": [{"entity_type": "PHONE", "value": "9876543210"}], "category": "hinglish_phone"}
{"id": "en-email-1", "text": "reach me at rahul.sharma@example.co.in", "entities": [{"entity_type": "EMAIL", "value": "rahul.sharma@example.co.in"}], "category": "email"}
{"id": "en-upi-1", "text": "pay to rahul123@okhdfcbank please", "entities": [{"entity_type": "UPI", "value": "rahul123@okhdfcbank"}], "category": "upi"}
{"id": "en-ifsc-1", "text": "IFSC code is HDFC0001234", "entities": [{"entity_type": "IFSC", "value": "HDFC0001234"}], "category": "ifsc"}
{"id": "en-person-1", "text": "My name is Rahul Sharma", "entities": [{"entity_type": "PERSON", "value": "Rahul Sharma"}], "category": "person_english"}
{"id": "hinglish-person-1", "text": "mera naam Priya Verma hai", "entities": [{"entity_type": "PERSON", "value": "Priya Verma"}], "category": "person_hinglish"}
{"id": "hi-person-1", "text": "मेरा नाम प्रिया है", "entities": [], "category": "person_devanagari_known_gap"}
{"id": "en-address-1", "text": "I live at 221B MG Road, Koramangala, Bangalore 560034", "entities": [{"entity_type": "ADDRESS", "value": "221B MG Road, Koramangala, Bangalore 560034"}], "category": "address_english"}
{"id": "hinglish-address-1", "text": "mera address hai Flat 12, Sector 21, Noida", "entities": [{"entity_type": "ADDRESS", "value": "Flat 12, Sector 21, Noida"}], "category": "address_hinglish"}
{"id": "code-mixed-1", "text": "mera aadhaar 234123412346 hai aur PAN ABCDE1234F bhi hai", "entities": [{"entity_type": "AADHAAR", "value": "234123412346"}, {"entity_type": "PAN", "value": "ABCDE1234F"}], "category": "code_mixed_multi_entity"}
{"id": "fp-order-id-1", "text": "Your order ID is ABCDE1234F123", "entities": [], "category": "false_positive_pan_shaped"}
{"id": "fp-generic-number-1", "text": "The temperature today is 9876543210", "entities": [], "category": "false_positive_number_context"}
{"id": "fp-weather-1", "text": "The weather in Delhi is nice today.", "entities": [], "category": "false_positive_no_pii"}
{"id": "repeated-entity-1", "text": "Call 9876543210, or if busy, call 9876543210 again later.", "entities": [{"entity_type": "PHONE", "value": "9876543210"}, {"entity_type": "PHONE", "value": "9876543210"}], "category": "repeated_entity"}
```

- [ ] **Step 2: Implement `evals/run_eval.py`**

```python
"""Reproducible evaluation script. Run: python evals/run_eval.py
Compares deterministic-only detection vs BharatGuard's hybrid
(deterministic + contextual) approach. No pytest dependency."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from bharatguard.detectors.contextual import IndianAddressDetector, SpacyPersonDetector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.merge import merge_entities
from bharatguard.core import PIIGuard

DATASET_PATH = Path(__file__).parent / "dataset.jsonl"

_DIGIT_STRIP_RE = re.compile(r"[^0-9A-Za-z]")


def _canonicalize(value: str) -> str:
    """Canonical form for structured values, stripping formatting so
    '9876543210' == '987-654-3210' == '+91 9876543210'."""
    stripped = _DIGIT_STRIP_RE.sub("", value)
    if stripped.startswith("91") and len(stripped) == 12:
        stripped = stripped[2:]
    return stripped.lower()


def load_dataset() -> list[dict]:
    return [json.loads(line) for line in DATASET_PATH.read_text().splitlines() if line.strip()]


def detect_spans(text: str, use_contextual: bool) -> list[tuple[str, int, int]]:
    from bharatguard.normalization.normalize import normalize
    normalized, offset_map = normalize(text)
    raw = []
    for d in DETERMINISTIC_DETECTORS:
        raw.extend(d.detect(normalized))
    if use_contextual:
        raw.extend(SpacyPersonDetector().detect(normalized))
        raw.extend(IndianAddressDetector().detect(normalized))
    translated = [
        (e.entity_type,
         offset_map[e.start] if e.start < len(offset_map) else len(text),
         (offset_map[e.end - 1] + 1) if e.end - 1 < len(offset_map) else len(text))
        for e in raw
    ]
    from bharatguard.models import PIIEntity
    merged = merge_entities([PIIEntity(t, s, e, 1.0, "eval") for t, s, e in translated])
    return [(m.entity_type, m.start, m.end) for m in merged]


def score(dataset: list[dict], use_contextual: bool) -> dict:
    tp = fp = fn = 0
    latencies = []
    for example in dataset:
        text = example["text"]
        gold = {(e["entity_type"], e["value"]) for e in example["entities"]}
        t0 = time.perf_counter()
        predicted_spans = detect_spans(text, use_contextual)
        latencies.append((time.perf_counter() - t0) * 1000)
        predicted = {(t, text[s:e]) for t, s, e in predicted_spans}

        matched_gold = set()
        for p_type, p_value in predicted:
            hit = next(
                (g for g in gold if g[0] == p_type and g not in matched_gold and
                 (_canonicalize(g[1]) == _canonicalize(p_value) or g[1] in p_value or p_value in g[1])),
                None,
            )
            if hit:
                tp += 1
                matched_gold.add(hit)
            else:
                fp += 1
        fn += len(gold) - len(matched_gold)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2),
    }


def leakage_check(dataset: list[dict]) -> dict:
    guard = PIIGuard()
    exact_leaks = 0
    canonical_leaks = 0
    total_pii_values = 0
    for example in dataset:
        protected = guard.protect([{"role": "user", "content": example["text"]}])
        sanitized = protected.messages[0]["content"]
        for entity in example["entities"]:
            total_pii_values += 1
            value = entity["value"]
            if value in sanitized:
                exact_leaks += 1
                continue
            canon = _canonicalize(value)
            if canon and canon in _canonicalize(sanitized):
                canonical_leaks += 1
    return {
        "total_pii_values": total_pii_values,
        "exact_substring_leaks": exact_leaks,
        "canonical_value_leaks": canonical_leaks,
        "total_leaked": exact_leaks + canonical_leaks,
    }


def main() -> None:
    dataset = load_dataset()
    print(f"Loaded {len(dataset)} evaluation examples\n")

    print("=== Baseline: deterministic detectors only ===")
    for k, v in score(dataset, use_contextual=False).items():
        print(f"  {k}: {v}")

    print("\n=== BharatGuard hybrid: deterministic + contextual (spaCy PERSON, address rules) ===")
    for k, v in score(dataset, use_contextual=True).items():
        print(f"  {k}: {v}")

    print("\n=== Privacy leakage (evaluation-set invariant, NOT a real-world guarantee) ===")
    for k, v in leakage_check(dataset).items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Create `evals/__init__.py`** (empty file)

- [ ] **Step 4: Run the eval script, inspect real output (do not fabricate numbers)**

```bash
python evals/run_eval.py
```
Expected: prints two score tables + leakage table with real numbers from this dataset. If precision/recall look wrong for a category, fix the matching logic in `score()` or the detector — do not hand-edit printed numbers.

- [ ] **Step 5: Commit**

```bash
git add evals
git commit -m "feat: add synthetic eval dataset and reproducible evaluation script"
```

---

### Task 12: Streamlit demo

**Files:**
- Create: `demo/app.py`

**Interfaces:**
- Consumes: `PIIGuard`, `FakeSarvamClient` (demo defaults to fake client unless `SARVAM_API_KEY` is set, so it always runs).

- [ ] **Step 1: Implement `demo/app.py`**

```python
"""Minimal Streamlit demo. Run: streamlit run demo/app.py
Uses FakeSarvamClient by default so it runs without an API key; if
SARVAM_API_KEY is set in the environment, it uses the real SarvamClient."""
import os

import streamlit as st

from bharatguard.core import PIIGuard
from bharatguard.integrations.sarvam import FakeSarvamClient

st.set_page_config(page_title="BharatGuard Demo")
st.title("BharatGuard: India-first PII protection for LLM apps")

EXAMPLES = {
    "English": "My Aadhaar number is 234123412346 and my phone is 9876543210.",
    "Hindi": "मेरा आधार नंबर 234123412346 है और मेरा फोन 9876543210 है।",
    "Hinglish": "mera aadhaar number hai 234123412346, aur PAN ABCDE1234F bhi hai",
    "Indic numerals": "मेरा पिन कोड ११०००१ है और आधार २३४१ २३४१ २३४६",
}

choice = st.selectbox("Load an example", ["(custom)"] + list(EXAMPLES.keys()))
default_text = EXAMPLES.get(choice, "")
user_text = st.text_area("Enter text containing PII", value=default_text, height=100)

if st.button("Protect and send to Sarvam") and user_text.strip():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": user_text}])

    st.subheader("1. Detected PII (types only — no raw values shown)")
    if guard.last_entities:
        for e in guard.last_entities:
            st.write(f"- **{e.entity_type}** (source: {e.source}, confidence: {e.confidence})")
    else:
        st.write("No PII detected.")

    st.subheader("2. Masked text sent to Sarvam")
    masked_text = protected.messages[0]["content"]
    st.code(masked_text)

    api_key = os.environ.get("SARVAM_API_KEY")
    if api_key:
        from bharatguard.integrations.sarvam import SarvamClient
        client = SarvamClient(api_key=api_key)
    else:
        st.info("No SARVAM_API_KEY set — using a mocked Sarvam response for this demo.")
        client = FakeSarvamClient(reply=f"Thanks, I've noted that: {masked_text}")

    response = client.chat(messages=protected.messages)
    st.subheader("3. Sarvam response (on masked text)")
    st.code(response.choices[0].message.content)

    st.subheader("4. Restored response (optional)")
    restored = guard.restore(response.choices[0].message.content, protected.session)
    st.code(restored)
```

- [ ] **Step 2: Manual verification**

```bash
pip install -e ".[demo]"
streamlit run demo/app.py
```
Load each of the 4 examples in the dropdown, click the button, confirm all 4 stages render and no raw PII appears in stage 2 or 3's displayed text.

- [ ] **Step 3: Commit**

```bash
git add demo/app.py
git commit -m "feat: add Streamlit demo"
```

---

### Task 13: Voice demo (Phase 2)

**Files:**
- Create: `examples/voice_demo.py`
- Create: `examples/sample_audio/synthetic_pii_sample.txt` (placeholder note, see step 1)

**Interfaces:**
- Consumes: `PIIGuard`, `SarvamClient`.

- [ ] **Step 1: Add a note about the audio fixture**

Create `examples/sample_audio/synthetic_pii_sample.txt`:
```
Place a short synthetic .wav file here (e.g. recorded via `say` on macOS or
any TTS tool) containing a sentence like:
"My Aadhaar number is two three four one two three four one two three four
six and my phone number is nine eight seven six five four three two one zero."
Do not use any real personal information. Suggested filename:
synthetic_pii_sample.wav
```
On macOS this can be generated with:
```bash
say "My Aadhaar number is two three four one two three four one two three four six and my phone number is nine eight seven six five four three two one zero" -o examples/sample_audio/synthetic_pii_sample.wav
```

- [ ] **Step 2: Implement `examples/voice_demo.py`**

```python
"""Voice demo (Phase 2, optional). Demonstrates why PII protection belongs
AFTER speech-to-text and BEFORE the LLM call: raw audio must reach Sarvam's
STT (there's no way around that for transcription), but the resulting
transcript must be protected before it reaches sarvam-105b.

Requires SARVAM_API_KEY in the environment (real API calls — not part of
the mocked pytest suite). Uses only synthetic audio; see
examples/sample_audio/synthetic_pii_sample.txt for how to generate one.

Run: python examples/voice_demo.py path/to/synthetic_pii_sample.wav
"""
from __future__ import annotations

import sys

from dotenv import load_dotenv

from bharatguard.core import PIIGuard
from bharatguard.integrations.sarvam import SarvamClient


def main() -> None:
    load_dotenv()
    if len(sys.argv) != 2:
        print("Usage: python examples/voice_demo.py <path-to-synthetic-audio.wav>")
        sys.exit(1)

    audio_path = sys.argv[1]
    client = SarvamClient()

    with open(audio_path, "rb") as f:
        transcript_response = client.transcribe(file=f)
    transcript = transcript_response.transcript
    print(f"[1] STT transcript\n    {transcript}\n")

    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": transcript}])
    protected_text = protected.messages[0]["content"]
    print(f"[2] Protected transcript\n    {protected_text}\n")

    response = client.chat(messages=protected.messages)
    print(f"[3] Sarvam response\n    {response.choices[0].message.content}\n")

    restored = guard.restore(response.choices[0].message.content, protected.session)
    print(f"[4] Restored response (optional)\n    {restored}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Manual verification (requires real SARVAM_API_KEY and a generated sample audio file)**

```bash
say "My Aadhaar number is two three four one two three four one two three four six" -o examples/sample_audio/synthetic_pii_sample.wav
python examples/voice_demo.py examples/sample_audio/synthetic_pii_sample.wav
```
Expected: 4 stages print; stage 2 shows the Aadhaar masked/tokenized, stage 3's request never contained the raw digits.

If no `SARVAM_API_KEY` is available at implementation time, skip running this step live, note it in the PR/handoff as "not run — no API key available," and leave the script in place for the user to run themselves. Do not fabricate output.

- [ ] **Step 4: Commit**

```bash
git add examples/voice_demo.py examples/sample_audio
git commit -m "feat: add voice demo (Saaras v3 STT -> BharatGuard -> sarvam-105b)"
```

---

### Task 14: Quickstart example (mocked, no key required)

**Files:**
- Create: `examples/quickstart.py`

- [ ] **Step 1: Implement `examples/quickstart.py`**

```python
"""Runs with no API key and no network access — uses FakeSarvamClient.
Run: python examples/quickstart.py"""
from bharatguard.core import PIIGuard
from bharatguard.integrations.sarvam import FakeSarvamClient

guard = PIIGuard()
client = FakeSarvamClient(reply="Sure, I've noted your details securely.")

messages = [{"role": "user", "content": "My Aadhaar is 234123412346, call me at 9876543210"}]

protected = guard.protect(messages)
print("Masked payload sent to Sarvam:", protected.messages)

response = client.chat(messages=protected.messages)
print("Sarvam response:", response.choices[0].message.content)

final_response = guard.restore(response.choices[0].message.content, protected.session)
print("Restored response:", final_response)
```

- [ ] **Step 2: Run and verify**

```bash
python examples/quickstart.py
```
Expected: three print lines, masked payload contains no raw Aadhaar/phone digits.

- [ ] **Step 3: Commit**

```bash
git add examples/quickstart.py
git commit -m "docs: add mocked quickstart example"
```

---

### Task 15: Live Sarvam validation example

**Files:**
- Create: `examples/live_sarvam.py`

- [ ] **Step 1: Implement `examples/live_sarvam.py`**

```python
"""Live integration validation against the REAL Sarvam sarvam-105b API.
Requires SARVAM_API_KEY in the environment (see .env.example). Uses only
synthetic PII. NOT part of the pytest suite — run explicitly:
python examples/live_sarvam.py"""
from dotenv import load_dotenv

from bharatguard.core import PIIGuard
from bharatguard.integrations.sarvam import SarvamClient

load_dotenv()

guard = PIIGuard()
client = SarvamClient()  # reads SARVAM_API_KEY from environment

original_text = "My Aadhaar number is 234123412346 and my UPI ID is rahul123@okhdfcbank."
print(f"[1] Original synthetic input\n    {original_text}\n")

protected = guard.protect([{"role": "user", "content": original_text}])
print("[2] Detected entities (types only):")
for e in guard.last_entities:
    print(f"    - {e.entity_type} (source={e.source}, confidence={e.confidence})")

masked_text = protected.messages[0]["content"]
print(f"\n[3] Sanitized prompt actually sent to Sarvam\n    {masked_text}\n")
assert "234123412346" not in masked_text and "rahul123@okhdfcbank" not in masked_text, (
    "raw PII must never reach the outgoing request"
)

response = client.chat(messages=protected.messages)
print(f"[4] Sarvam sarvam-105b response\n    {response.choices[0].message.content}\n")

restored = guard.restore(response.choices[0].message.content, protected.session)
print(f"[5] Restored response (optional)\n    {restored}\n")

print("[6] Verified: raw PII was never included in the Sarvam request payload.")
```

- [ ] **Step 2: Manual verification (requires real SARVAM_API_KEY)**

```bash
cp .env.example .env  # then fill in SARVAM_API_KEY
python examples/live_sarvam.py
```
Expected: 6 numbered stages print; no raw synthetic Aadhaar/UPI value appears anywhere in stdout except stage [1] (the deliberately-shown original input) and stage [5] if restoration is exercised.

If no `SARVAM_API_KEY` is available at implementation time, do not run this step — leave the script for the user, and say so explicitly rather than claiming it was validated live.

- [ ] **Step 3: Commit**

```bash
git add examples/live_sarvam.py
git commit -m "docs: add live Sarvam sarvam-105b integration validation example"
```

---

### Task 16: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write `README.md`** covering, in order: problem statement (India-first PII exposure to LLMs), architecture diagram (the pipeline from this plan's Architecture section), install (`git clone`, venv, `pip install -e .`, `python -m spacy download en_core_web_sm`, `cp .env.example .env`), quickstart (`python examples/quickstart.py` — no key needed), API usage (the `protect`/`restore` and `chat` snippets from Task 9/10), supported PII table (entity type → detector → default policy action), policy configuration (how to pass a custom `PolicyConfig`), security assumptions section (explicitly: raw PII never sent to Sarvam for detection; Session is in-memory only, never logged/serialized; this reduces unnecessary exposure of personal data before it reaches an external LLM provider — **do not claim DPDP compliance**), evaluation (`python evals/run_eval.py`, what it measures, that numbers come from running it, not invented), limitations (Devanagari-script PERSON detection gap, address detection is signal-based not a full parser, regex-based detectors can have both false positives/negatives, leakage check is an evaluation-set invariant not a real-world guarantee), voice flow (`examples/voice_demo.py`, why ordering matters), and a "Mocked test suite vs Live Sarvam integration" section distinguishing `pytest tests/` (no key, no network) from `examples/live_sarvam.py` and `examples/voice_demo.py` (real key required, explicit opt-in).

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```

---

### Task 17: Final fresh-clone verification

**Files:** none created; verification only.

- [ ] **Step 1: Simulate a fresh clone in a new directory**

```bash
cd /tmp
rm -rf bharatguard-verify
git clone /Users/yash/project-4 bharatguard-verify
cd bharatguard-verify
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
cp .env.example .env
```

- [ ] **Step 2: Run the full mocked test suite (no API key set)**

```bash
pytest tests/ -v
```
Expected: all tests pass, zero network calls.

- [ ] **Step 3: Run the mocked quickstart**

```bash
python examples/quickstart.py
```
Expected: three print lines as in Task 14.

- [ ] **Step 4: Run the evaluation script**

```bash
python evals/run_eval.py
```
Expected: real score tables print (not fabricated).

- [ ] **Step 5: Sanity-import the Streamlit demo module (no server needed for CI-style check)**

```bash
python -c "import ast; ast.parse(open('demo/app.py').read()); print('demo/app.py parses ok')"
```

- [ ] **Step 6: Confirm no secrets committed**

```bash
git log --all -p | grep -i "SARVAM_API_KEY=" | grep -v "SARVAM_API_KEY=$" || echo "no committed key found"
git status  # .env should be untracked/ignored, not staged
```

- [ ] **Step 7: Report results**

Summarize pass/fail for each step above. If a real `SARVAM_API_KEY` was available and `examples/live_sarvam.py` / `examples/voice_demo.py` were run earlier (Tasks 13/15), note their outcomes here too; otherwise state clearly they were not run and remain for the user to validate with their own key.

- [ ] **Step 8: Clean up**

```bash
cd /Users/yash/project-4
rm -rf /tmp/bharatguard-verify
```

No commit for this task (verification only).

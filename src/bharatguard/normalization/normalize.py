"""Normalization with a per-character offset map back to the original text.

Scope is deliberately narrow: Unicode NFC, Indic-digit folding (1:1
substitution), and separator/whitespace collapsing (deletion). This keeps
offset tracking simple enough to do with a lightweight array instead of a
general diff/alignment algorithm.

``normalize(text)`` returns ``(normalized_text, offset_map)`` where
``offset_map[i]`` is the index into the ORIGINAL text that
``normalized_text[i]`` came from. For any detector span ``(start, end)`` on
``normalized_text``, the corresponding original span is
``(offset_map[start], offset_map[end - 1] + 1)``.
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
    if not text:
        return "", []

    # Step A: Unicode NFC. Composition can change string length for inputs
    # containing decomposed sequences (base char + combining marks), which
    # makes exact per-character offset tracking non-trivial in the general
    # case. Rather than risk an incorrect offset from a heuristic aligner,
    # we take the safe fallback: compose once and only use it if the length
    # is unchanged (the common case for already-composed or ASCII/Indic
    # script text, which have no combining-mark sequences). If NFC would
    # change the length, we skip NFC for this input entirely and normalize
    # the raw text instead — a narrower guarantee (rare decomposed inputs
    # keep their original form) in exchange for offsets that are always
    # exactly correct.
    composed = unicodedata.normalize("NFC", text)
    if len(composed) == len(text):
        nfc_text = composed
    else:
        nfc_text = text

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
        out_offsets.append(i)

    return "".join(out_chars), out_offsets

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
    masks the whole matched span found via signal-anchored regex. Different
    signals can and will produce multiple/overlapping ADDRESS entities for
    the same underlying address; resolving that overlap is Task 6's job."""

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

"""Deterministic Indian PII detectors: regex patterns plus structural
validation rules (not just broad pattern matching).

Local-only: no network calls, no external APIs, no LLM calls. Never log or
print matched values here -- raw PII must never leave the process.
"""
from __future__ import annotations

import re

from bharatguard.models import PIIEntity

# ---------------------------------------------------------------------------
# Verhoeff checksum (UIDAI's Aadhaar check-digit algorithm).
# Reference tables: https://en.wikipedia.org/wiki/Verhoeff_algorithm
# ---------------------------------------------------------------------------
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff_valid(digits: str) -> bool:
    """True if the last digit of `digits` is a valid Verhoeff check digit
    for the preceding digits (UIDAI's rule for genuine Aadhaar numbers)."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
_AADHAAR_RE = re.compile(r"(?<!\d)([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?!\d)")
_PAN_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z])(?![A-Z0-9])")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+91[ -]?|0)?([6-9]\d{4}[ -]?\d{5})(?!\d)")
_EMAIL_RE = re.compile(r"(?<![\w.])([A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9_])")
_UPI_RE = re.compile(r"(?<![\w.])([A-Za-z0-9.\-_]{2,}@[A-Za-z][A-Za-z0-9]{2,})(?!\w)(?!\.[A-Za-z0-9])")
_IFSC_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])")


class AadhaarDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _AADHAAR_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(1))
            if len(digits) != 12 or digits[0] in "01":
                continue
            # Genuine Aadhaar numbers always satisfy UIDAI's Verhoeff check
            # digit, so a shape match that fails it is rejected outright
            # (raises precision without costing recall on real numbers).
            if not _verhoeff_valid(digits):
                continue
            out.append(PIIEntity("AADHAAR", m.start(1), m.end(1), 0.95, "aadhaar_regex_verhoeff"))
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
            _, _, domain = m.group(1).partition("@")
            if "." in domain:  # has a real TLD-shaped domain, not a UPI handle
                out.append(PIIEntity("EMAIL", m.start(1), m.end(1), 0.9, "email_regex"))
        return out


class UpiDetector:
    def detect(self, text: str) -> list[PIIEntity]:
        # Design limitation (documented, not fully resolvable with regex):
        # a short handle with no dot in its suffix is structurally
        # ambiguous between "UPI VPA" and "invalid/no-TLD email-like
        # string" -- e.g. "a@bc" could be either. We treat any @-suffix
        # with no dot as UPI-shaped, which is the closer real-world match.
        out = []
        for m in _UPI_RE.finditer(text):
            _, _, handle = m.group(1).partition("@")
            if "." not in handle:
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

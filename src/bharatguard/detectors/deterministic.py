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


def _luhn_valid(digits: str) -> bool:
    """True if `digits` satisfies the Luhn checksum (ISO/IEC 7812-1) --
    the check-digit standard used by all major payment card networks."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
_AADHAAR_RE = re.compile(r"(?<!\d)([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?!\d)")
_PAN_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z])(?![A-Z0-9])")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+91[ -]?|0)?([6-9]\d{4}[ -]?\d{5})(?!\d)")
_EMAIL_RE = re.compile(r"(?<![\w.])([A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9_])")
_UPI_RE = re.compile(r"(?<![\w.])([A-Za-z0-9.\-_]{2,}@[A-Za-z][A-Za-z0-9]{2,})(?!\w)(?!\.[A-Za-z0-9])")
_IFSC_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])")

# Common secret/API-key shapes. Heuristic, not an exhaustive secret scanner --
# same documented-ambiguity spirit as the UPI/email overlap note above.
_OPENAI_KEY_RE = re.compile(r"(?<![\w-])(sk-[A-Za-z0-9]{20,})(?![\w-])")
_AWS_ACCESS_KEY_RE = re.compile(r"(?<!\w)(AKIA[0-9A-Z]{16})(?!\w)")
_BEARER_TOKEN_RE = re.compile(r"(?i:bearer)\s+([A-Za-z0-9\-_.]{20,})")
_GENERIC_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i:\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*[\"']?)([A-Za-z0-9_\-]{16,})(?=[\"']?(?:\s|$|[,;)]))"
)

# Payment card numbers: 13-19 digits (covers Visa/Mastercard/Amex/RuPay/
# Discover ranges), optionally grouped with spaces or hyphens.
_CARD_RE = re.compile(r"(?<![\d\-])(\d(?:[ -]?\d){12,18})(?![\d\-])")


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


class ApiKeyDetector:
    """Detects common secret/API-key shapes: OpenAI-style (sk-...), AWS
    access keys (AKIA...), Bearer tokens, and generic key=value/key:value
    assignments. A heuristic pattern-matcher, not an exhaustive secret
    scanner -- real secrets come in far more shapes than these four."""

    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _OPENAI_KEY_RE.finditer(text):
            out.append(PIIEntity("API_KEY", m.start(1), m.end(1), 0.9, "api_key_openai"))
        for m in _AWS_ACCESS_KEY_RE.finditer(text):
            out.append(PIIEntity("API_KEY", m.start(1), m.end(1), 0.9, "api_key_aws"))
        for m in _BEARER_TOKEN_RE.finditer(text):
            out.append(PIIEntity("API_KEY", m.start(1), m.end(1), 0.85, "api_key_bearer"))
        for m in _GENERIC_SECRET_ASSIGNMENT_RE.finditer(text):
            out.append(PIIEntity("API_KEY", m.start(1), m.end(1), 0.7, "api_key_generic_assignment"))
        return out


class CardNumberDetector:
    """Detects payment card numbers via shape + Luhn checksum validation
    -- the same "reject shape matches that fail the real check digit"
    approach used for Aadhaar. 13-19 digits, optionally grouped with
    spaces/hyphens (e.g. "4111 1111 1111 1111")."""

    def detect(self, text: str) -> list[PIIEntity]:
        out = []
        for m in _CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(1))
            if not (13 <= len(digits) <= 19):
                continue
            if not _luhn_valid(digits):
                continue
            out.append(PIIEntity("CARD_NUMBER", m.start(1), m.end(1), 0.9, "card_regex_luhn"))
        return out


DETERMINISTIC_DETECTORS = [
    AadhaarDetector(), PanDetector(), PhoneDetector(),
    EmailDetector(), UpiDetector(), IfscDetector(), ApiKeyDetector(),
    CardNumberDetector(),
]

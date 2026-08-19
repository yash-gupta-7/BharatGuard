"""LOCAL / MOCKED quickstart -- no SARVAM_API_KEY required.

Standalone script -- NOT part of the pytest suite, makes no network calls.
Demonstrates both the explicit low-level API (protect -> send -> restore)
and the guard.chat() convenience API, against a FakeSarvamClient so this
runs anywhere with just `pip install -e ".[dev]"` and no API key.

Uses ONLY synthetic PII (the same fabricated-but-Verhoeff-valid Aadhaar
number used in this project's test fixtures -- not a real person's number).

Run: python examples/quickstart.py
"""
from __future__ import annotations

from bharatguard import PIIGuard
from bharatguard.integrations.sarvam import FakeSarvamClient

SYNTHETIC_AADHAAR = "234123412346"  # synthetic, passes Verhoeff -- see tests/test_core.py
SYNTHETIC_PHONE = "9876543210"  # synthetic -- see tests/test_core.py


def explicit_api() -> None:
    print("=== Explicit low-level API: protect() -> send -> restore() ===\n")

    original_text = f"My Aadhaar number is {SYNTHETIC_AADHAAR} and my phone is {SYNTHETIC_PHONE}."
    print(f"1. Original input:\n   {original_text}\n")

    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": original_text}])
    sanitized_content = protected.messages[0]["content"]
    print(f"2. Protected/sanitized message (this is what would be sent to Sarvam):\n   {sanitized_content}\n")

    assert SYNTHETIC_AADHAAR not in sanitized_content, (
        "Raw synthetic Aadhaar digits leaked into the sanitized payload."
    )
    assert SYNTHETIC_PHONE not in sanitized_content, (
        "Raw synthetic phone digits leaked into the sanitized payload."
    )
    print("3. Verified: no raw Aadhaar/phone digits present in the sanitized payload.\n")

    # PHONE is "tokenize" under DEFAULT_POLICY, so the sanitized text contains
    # a <PHONE_n> token we can echo back and restore below.
    client = FakeSarvamClient(
        chat_response=f"Thanks, I've noted the number {_extract_phone_token(sanitized_content)} for this request."
    )
    response = client.chat(protected.messages)
    assistant_text = response.choices[0].message.content
    print(f"4. (Mocked) Sarvam response:\n   {assistant_text}\n")

    restored = guard.restore(assistant_text, protected.session)
    print(f"5. Restored response (token swapped back to the real phone number):\n   {restored}\n")


def _extract_phone_token(sanitized_content: str) -> str:
    import re

    match = re.search(r"<PHONE_\d+>", sanitized_content)
    return match.group(0) if match else "<PHONE_1>"


def convenience_api() -> None:
    print("=== Convenience API: guard.chat() composes protect -> chat -> restore ===\n")

    original_text = f"My phone is {SYNTHETIC_PHONE}."
    guard = PIIGuard()
    # guard.chat() calls protect() itself, so we don't know the token label
    # ahead of time -- the FakeSarvamClient just echoes a fixed reply here to
    # keep the example simple; in a real integration Sarvam would echo the
    # token it was actually given.
    client = FakeSarvamClient(chat_response="Got it, noted.")
    restored = guard.chat(client, [{"role": "user", "content": original_text}])
    print(f"guard.chat() result (already restored, no raw PII ever left this process):\n   {restored}\n")


def main() -> None:
    explicit_api()
    convenience_api()


if __name__ == "__main__":
    main()

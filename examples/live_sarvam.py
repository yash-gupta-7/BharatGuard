"""Live sanity check for the SarvamClient wrapper.

Standalone script -- NOT part of the pytest suite. Makes a real call to the
Sarvam API using sarvam-105b. Requires a real SARVAM_API_KEY in .env.

Uses ONLY synthetic PII (the same fabricated-but-Verhoeff-valid Aadhaar
number used in this project's test fixtures -- not a real person's number).

Run: python examples/live_sarvam.py
"""
from __future__ import annotations

import sys

from dotenv import load_dotenv

from bharatguard import PIIGuard
from bharatguard.integrations.sarvam import SarvamClient

SYNTHETIC_AADHAAR = "234123412346"  # synthetic, passes Verhoeff -- see tests/test_core.py


def main() -> None:
    load_dotenv()

    original_text = f"My Aadhaar number is {SYNTHETIC_AADHAAR}."
    print(f"1. Original input:\n   {original_text}\n")

    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": original_text}])
    sanitized_content = protected.messages[0]["content"]
    print(f"2-3. Protected/sanitized message (this is what gets sent to Sarvam):\n   {sanitized_content}\n")

    # 4. Assert no raw PII before making any network call.
    assert SYNTHETIC_AADHAAR not in sanitized_content, (
        "Raw synthetic Aadhaar digits leaked into the sanitized payload -- aborting before network call."
    )
    print("4. Verified: no raw Aadhaar digits present in the sanitized payload.\n")

    # 5. Real network call.
    try:
        client = SarvamClient()
    except ValueError as exc:
        print(f"{exc}")
        sys.exit(1)
    response = client.chat(protected.messages)

    # 6. Print the response.
    assistant_text = response.choices[0].message.content
    print(f"5-6. Sarvam response:\n   {assistant_text}\n")

    # 7. Restore and print.
    restored = guard.restore(assistant_text, protected.session)
    print(f"7-8. Restored response:\n   {restored}\n")


if __name__ == "__main__":
    main()

"""Live sanity check for the Saaras v3 voice pipeline.

Standalone script -- NOT part of the pytest suite. Demonstrates the voice
privacy boundary:

    local audio -> Sarvam Saaras v3 STT -> transcript -> PIIGuard.protect()
        -> sanitized transcript -> sarvam-105b -> response -> PIIGuard.restore()

Raw audio must reach Sarvam's STT (unavoidable -- that's the only way to get
a transcript), but the RESULTING TRANSCRIPT is protected before it ever
reaches the chat model. Uses ONLY synthetic PII (the same fabricated Aadhaar
and phone numbers used throughout this project's tests/examples -- not a
real person's data).

Requires a real SARVAM_API_KEY in .env.

Usage:
    python examples/voice_demo.py <path-to-audio-file>

To generate the bundled synthetic sample yourself (macOS `say`, 16kHz mono
PCM WAV -- see examples/sample_audio/README.md for details):

    say -o examples/sample_audio/synthetic_pii_sample.wav \\
        --file-format=WAVE --data-format=LEI16@16000 \\
        "My Aadhaar number is two three four one two three four one two \\
        three four six and my phone number is nine eight seven six five \\
        four three two one zero"
"""
from __future__ import annotations

import mimetypes
import os
import sys

from dotenv import load_dotenv

from bharatguard import PIIGuard
from bharatguard.integrations.sarvam import SarvamClient

SYNTHETIC_AADHAAR = "234123412346"  # synthetic, passes Verhoeff -- see tests/test_core.py
SYNTHETIC_PHONE = "9876543210"  # synthetic -- see tests/test_core.py


def main() -> None:
    load_dotenv()

    if not os.environ.get("SARVAM_API_KEY"):
        print("SARVAM_API_KEY not set -- see .env.example")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: python examples/voice_demo.py <path-to-audio-file>")
        print(
            "No sample yet? Generate one -- see "
            "examples/sample_audio/README.md"
        )
        sys.exit(1)

    audio_path = sys.argv[1]
    if not os.path.isfile(audio_path):
        print(f"Audio file not found: {audio_path}")
        print("Usage: python examples/voice_demo.py <path-to-audio-file>")
        print(
            "No sample yet? Generate one -- see "
            "examples/sample_audio/README.md"
        )
        sys.exit(1)

    client = SarvamClient()
    guard = PIIGuard()

    # [1] Raw audio -> Saaras v3 STT. Audio necessarily reaches Sarvam
    # unprotected -- there is no way to transcribe it otherwise. The
    # resulting TEXT transcript is what must be protected before any LLM
    # call.
    content_type = mimetypes.guess_type(audio_path)[0] or "application/octet-stream"
    try:
        with open(audio_path, "rb") as audio_file:
            transcribe_result = client.transcribe(
                (os.path.basename(audio_path), audio_file, content_type)
            )
    except RuntimeError as exc:
        # SarvamClient.transcribe() already strips the raw SDK exception
        # down to only its type name -- nothing sensitive to re-expose here.
        print(f"Transcription failed: {exc}")
        sys.exit(1)

    transcript = transcribe_result.transcript
    print(f"[1] STT TRANSCRIPT\n    {transcript}\n")

    # [2] Protect the transcript before it goes anywhere near the LLM.
    protected = guard.protect([{"role": "user", "content": transcript}])
    protected_text = protected.messages[0]["content"]
    print(f"[2] PROTECTED TRANSCRIPT\n    {protected_text}\n")

    # Hard requirement: verify no raw PII survived protection BEFORE the
    # network call, so a failure here prevents the unsafe call from ever
    # happening.
    assert SYNTHETIC_AADHAAR not in protected_text, (
        "Raw synthetic Aadhaar digits leaked into the protected transcript -- "
        "aborting before network call."
    )
    assert SYNTHETIC_PHONE not in protected_text, (
        "Raw synthetic phone digits leaked into the protected transcript -- "
        "aborting before network call."
    )

    # [3] Only the protected messages are sent to the chat model.
    response = client.chat(protected.messages)
    assistant_text = response.choices[0].message.content
    print(f"[3] SARVAM RESPONSE\n    {assistant_text}\n")

    # [4] Restore any echoed tokens back to their original values.
    restored = guard.restore(assistant_text, protected.session)
    print(f"[4] RESTORED RESPONSE\n    {restored}\n")


if __name__ == "__main__":
    main()

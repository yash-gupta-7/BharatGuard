# Synthetic voice sample

`synthetic_pii_sample.wav` is a synthetic, machine-generated (macOS `say`)
audio clip. It contains no real person's data -- only the fabricated Aadhaar
(`234123412346`) and phone (`9876543210`) numbers already used throughout
this project's tests and examples.

Generated with:

```bash
say -o examples/sample_audio/synthetic_pii_sample.wav \
    --file-format=WAVE --data-format=LEI16@16000 \
    "My Aadhaar number is two three four one two three four one two three \
    four six and my phone number is nine eight seven six five four three \
    two one zero"
```

16kHz mono 16-bit PCM WAV -- a standard, widely accepted STT input format.
`say -o` defaults to `.aiff`; `--file-format=WAVE --data-format=LEI16@16000`
produces a plain PCM `.wav` instead.

If the file is missing (e.g. after a fresh clone without it committed),
regenerate it with the command above, then run:

```bash
python examples/voice_demo.py examples/sample_audio/synthetic_pii_sample.wav
```

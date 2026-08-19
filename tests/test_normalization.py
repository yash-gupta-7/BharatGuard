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


def test_unicode_nfc_applied_when_length_preserving():
    # Already-composed input is the common case: NFC is effectively a no-op
    # and offsets stay an identity mapping.
    composed = "caf" + "\u00e9"  # pre-composed single-codepoint 'e-acute'
    norm, offset_map = normalize(composed)
    assert norm == composed
    assert offset_map == list(range(len(composed)))


def test_unicode_nfc_decomposed_input_does_not_corrupt_offsets():
    # Decomposed input ('e' + combining acute accent = 2 codepoints) would
    # shrink under NFC composition (to 1 codepoint). This implementation
    # deliberately does NOT attempt to offset-track a length-changing
    # composition (see normalize.py: composing only happens when it is
    # length-preserving, to guarantee offsets are never wrong). Instead the
    # raw decomposed text is passed through unchanged, and offsets remain a
    # correct identity mapping -- a narrower NFC guarantee traded for an
    # offset map that is never incorrect.
    decomposed = "caf" + "e" + "\u0301"  # e + combining acute accent
    norm, offset_map = normalize(decomposed)
    assert norm == decomposed  # NFC skipped for this input (narrower guarantee)
    assert offset_map == list(range(len(decomposed)))
    for i in range(len(norm)):
        assert decomposed[offset_map[i]] == norm[i]


def test_empty_string():
    norm, offset_map = normalize("")
    assert norm == ""
    assert offset_map == []


# --- Required additions per task-3 spec ---


def test_ascii_noop_offset_map_is_identity():
    """Simple ASCII, no-op case: offset_map documents identity mapping."""
    text = "hello world 123"
    norm, offset_map = normalize(text)
    assert norm == text
    assert offset_map == list(range(len(text)))


def test_chars_after_collapsed_separator_map_correctly():
    """Characters after a collapsed run of separators must map to their own
    original position, not be shifted by the deleted characters."""
    text = "A    B"  # 4 spaces between A and B
    norm, offset_map = normalize(text)
    assert norm == "A B"
    # 'B' in original text is at index 5
    b_idx_in_norm = norm.index("B")
    assert offset_map[b_idx_in_norm] == text.index("B")
    assert text[offset_map[b_idx_in_norm]] == "B"


def test_hindi_sentence_indic_digit_offsets():
    text = "मेरा आधार नंबर १२३४ है"
    norm, offset_map = normalize(text)
    assert "1234" in norm
    digit_start = norm.index("1234")
    for i in range(4):
        orig_idx = offset_map[digit_start + i]
        assert text[orig_idx] in INDIC_DIGITS
    # verify exact round trip of the digit run
    orig_start = offset_map[digit_start]
    orig_end = offset_map[digit_start + 3] + 1
    assert text[orig_start:orig_end] == "१२३४"


def test_mixed_ascii_hindi_digits_punctuation():
    text = "Call राज on  ९८७६५४३२१०, ok?"
    norm, offset_map = normalize(text)
    assert len(norm) == len(offset_map)
    # ASCII prefix "Call" is unaffected
    call_idx = norm.index("Call")
    assert offset_map[call_idx] == text.index("Call")
    # Hindi word राज unaffected content-wise
    raj_idx_norm = norm.index("राज")
    raj_idx_orig = text.index("राज")
    for i in range(3):
        assert offset_map[raj_idx_norm + i] == raj_idx_orig + i
    # folded digit run round-trips to the original Indic digits
    digit_start = norm.index("9876543210")
    orig_start = offset_map[digit_start]
    orig_end = offset_map[digit_start + 9] + 1
    assert text[orig_start:orig_end] == "९८७६५४३२१०"
    # trailing punctuation preserved and offset-correct
    q_idx = norm.index("?")
    assert text[offset_map[q_idx]] == "?"


def test_span_translation_phone_like_span_in_mixed_text():
    """Simulate a detector locating a phone-shaped digit run in normalized
    text, then translating the span back through offset_map to the ORIGINAL
    text (which uses Indic digits and extra spacing) and proving the
    round-trip lands on the exact original substring."""
    text = "उसका नंबर है:   ९८७६५४३२१०  कृपया कॉल करें"
    norm, offset_map = normalize(text)

    # detector finds a 10-digit run on normalized text via plain string search
    digit_run_start = norm.index("9876543210")
    digit_run_end = digit_run_start + len("9876543210")

    orig_start = offset_map[digit_run_start]
    orig_end = offset_map[digit_run_end - 1] + 1

    # The original substring is the Indic-digit phone number, NOT the
    # ASCII-folded one, and must match exactly (not just "look plausible").
    assert text[orig_start:orig_end] == "९८७६५४३२१०"

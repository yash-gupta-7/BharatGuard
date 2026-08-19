from bharatguard.detectors.contextual import SpacyPersonDetector, IndianAddressDetector
from bharatguard.normalization.normalize import normalize


# ---------------------------------------------------------------------------
# PERSON
# ---------------------------------------------------------------------------

def test_person_detector_finds_english_name():
    hits = SpacyPersonDetector().detect("My name is Rahul Sharma and I live in Pune.")
    assert any(h.entity_type == "PERSON" for h in hits)


def test_person_detector_finds_hinglish_sentence_name():
    hits = SpacyPersonDetector().detect("mera naam Priya Verma hai")
    assert any(h.entity_type == "PERSON" for h in hits)


def test_person_detector_source_is_labeled():
    hits = SpacyPersonDetector().detect("Rahul Sharma called yesterday.")
    assert len(hits) > 0
    assert all(h.source == "spacy_person" for h in hits)


def test_person_detector_known_limitation_devanagari():
    # Documented limitation: en_core_web_sm is an English-only pipeline and
    # does not reliably detect Devanagari-script names. This test asserts
    # current (weak) behavior so a future model swap is visible as a test
    # change, not silent drift. This is NOT a bug to fix in this task.
    hits = SpacyPersonDetector().detect("मेरा नाम प्रिया है")
    assert hits == []


# ---------------------------------------------------------------------------
# ADDRESS
# ---------------------------------------------------------------------------

def test_address_detector_finds_pincode_match():
    text = "Send it to Bangalore 560034 please"
    hits = IndianAddressDetector().detect(text)
    assert any(h.source == "address_pincode" for h in hits)


def test_address_detector_finds_keyword_match():
    text = "I live at 221B MG Road, Koramangala, Bangalore 560034"
    hits = IndianAddressDetector().detect(text)
    assert any(h.entity_type == "ADDRESS" for h in hits)
    assert any(h.source == "address_keyword" for h in hits)


def test_address_detector_finds_sector_keyword():
    hits = IndianAddressDetector().detect("Flat 12, Sector 21, Noida")
    assert any(h.source == "address_keyword" for h in hits)


def test_address_detector_finds_hinglish_trigger_phrase():
    text = "mera address hai Flat 12, Sector 21, Noida"
    hits = IndianAddressDetector().detect(text)
    assert any(h.entity_type == "ADDRESS" for h in hits)
    assert any(h.source == "address_trigger_phrase" for h in hits)


def test_address_detector_ignores_unrelated_text():
    hits = IndianAddressDetector().detect("The weather in Delhi is nice today.")
    assert len(hits) == 0


def test_address_detector_overlapping_signals_on_same_address():
    # Pincode + keyword signals both fire on the same underlying address.
    # This is expected: Task 6's merge/overlap-resolution step (not built
    # here) is responsible for collapsing these into one entity.
    text = "I live at 221B MG Road, Koramangala, Bangalore 560034"
    hits = IndianAddressDetector().detect(text)
    sources = {h.source for h in hits}
    assert "address_pincode" in sources
    assert "address_keyword" in sources
    assert len(hits) >= 2


# ---------------------------------------------------------------------------
# Offset / normalize() composition (contextual layer)
# ---------------------------------------------------------------------------

def test_address_pincode_offset_survives_normalize_composition():
    # Extra internal spaces get collapsed by normalize(); prove that an
    # ADDRESS span detected on the *normalized* text still translates back
    # through offset_map to the correct substring of the ORIGINAL text.
    original = "mera  pata  hai  Sector 21, Noida 201301"
    normalized_text, offset_map = normalize(original)
    hits = IndianAddressDetector().detect(normalized_text)
    pincode_hits = [h for h in hits if h.source == "address_pincode"]
    assert len(pincode_hits) == 1
    e = pincode_hits[0]
    orig_start = offset_map[e.start]
    orig_end = offset_map[e.end - 1] + 1
    assert original[orig_start:orig_end] == "201301"

from bharatguard.detectors.deterministic import (
    AadhaarDetector, PanDetector, PhoneDetector, EmailDetector,
    UpiDetector, IfscDetector, ApiKeyDetector, CardNumberDetector,
)
from bharatguard.normalization.normalize import normalize

# Synthetic Aadhaar-shaped numbers that pass the Verhoeff checksum (computed,
# not guessed) via the reference algorithm at
# https://en.wikipedia.org/wiki/Verhoeff_algorithm
VALID_AADHAAR_1 = "234123412346"
VALID_AADHAAR_2 = "500040003006"


# ---------------------------------------------------------------------------
# Aadhaar
# ---------------------------------------------------------------------------

def test_aadhaar_detects_spaced_format():
    hits = AadhaarDetector().detect("My Aadhaar is 2341 2341 2346")
    assert len(hits) == 1
    assert hits[0].entity_type == "AADHAAR"


def test_aadhaar_detects_unformatted():
    hits = AadhaarDetector().detect(f"aadhaar: {VALID_AADHAAR_1}")
    assert len(hits) == 1


def test_aadhaar_detects_hyphenated_format():
    text = "aadhaar: 5000-4000-3006"
    hits = AadhaarDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "5000-4000-3006"


def test_aadhaar_rejects_starting_with_0_or_1():
    hits = AadhaarDetector().detect("random number 012345678901")
    assert len(hits) == 0


def test_aadhaar_rejects_wrong_length():
    hits = AadhaarDetector().detect("short number 23412341")
    assert len(hits) == 0


def test_aadhaar_rejects_shape_match_that_fails_verhoeff_checksum():
    # 234123412340 is 12 digits, starts with 2-9, but fails the Verhoeff
    # checksum (only ...2346 is the valid check digit for this base).
    hits = AadhaarDetector().detect("random 234123412340 here")
    assert len(hits) == 0


def test_aadhaar_offset_correct():
    text = f"My Aadhaar is {VALID_AADHAAR_1} thanks"
    hits = AadhaarDetector().detect(text)
    e = hits[0]
    assert text[e.start:e.end] == VALID_AADHAAR_1


def test_aadhaar_hindi_hinglish_context():
    text = f"mera aadhaar number hai {VALID_AADHAAR_1}"
    hits = AadhaarDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == VALID_AADHAAR_1


def test_aadhaar_at_start_of_string():
    text = f"{VALID_AADHAAR_1} is my aadhaar number"
    hits = AadhaarDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == VALID_AADHAAR_1


def test_aadhaar_indic_digit_integration_via_normalize():
    # Devanagari-digit Aadhaar in original text; normalize() folds digits,
    # detector runs on normalized text, span translated back through
    # offset_map should recover the original Indic-digit substring.
    original = "mera aadhaar hai २३४१२३४१२३४६ theek hai"
    normalized_text, offset_map = normalize(original)
    hits = AadhaarDetector().detect(normalized_text)
    assert len(hits) == 1
    e = hits[0]
    orig_start = offset_map[e.start]
    orig_end = offset_map[e.end - 1] + 1
    assert original[orig_start:orig_end] == "२३४१२३४१२३४६"


# ---------------------------------------------------------------------------
# PAN
# ---------------------------------------------------------------------------

def test_pan_detects_valid_format():
    hits = PanDetector().detect("PAN: ABCPE1234F")
    assert len(hits) == 1
    assert hits[0].entity_type == "PAN"


def test_pan_detects_another_valid_holder_code():
    text = "company PAN is XYZCA5678L"
    hits = PanDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "XYZCA5678L"


def test_pan_rejects_invalid_4th_char():
    # 4th char must be one of P/C/H/A/B/G/J/L/F/T (holder type codes)
    hits = PanDetector().detect("code: ABCZE1234F")
    assert len(hits) == 0


def test_pan_offset_at_end_of_string():
    text = "my PAN number is ABCPE1234F"
    hits = PanDetector().detect(text)
    e = hits[0]
    assert text[e.start:e.end] == "ABCPE1234F"
    assert e.end == len(text)


# ---------------------------------------------------------------------------
# Phone
# ---------------------------------------------------------------------------

def test_phone_detects_with_country_code():
    hits = PhoneDetector().detect("call me at +91 9876543210")
    assert len(hits) == 1
    assert hits[0].entity_type == "PHONE"


def test_phone_detects_bare_10_digit():
    hits = PhoneDetector().detect("9876543210 is my number")
    assert len(hits) == 1


def test_phone_detects_with_hyphen_separators():
    text = "reach 98765-43210 today"
    hits = PhoneDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "98765-43210"


def test_phone_rejects_invalid_starting_digit():
    hits = PhoneDetector().detect("5876543210 is not a mobile number")
    assert len(hits) == 0


def test_phone_rejects_when_embedded_in_longer_digit_run():
    # An 11-digit run containing a valid-looking 10-digit tail must not be
    # sliced out as a phone number — it's shaped like an unrelated large
    # number (e.g. an account/reference number), not a mobile number.
    hits = PhoneDetector().detect("reference 69876543210 for this order")
    assert len(hits) == 0


def test_phone_hindi_hinglish_context():
    text = "mera phone number hai 9876543210 aap call karo"
    hits = PhoneDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "9876543210"


def test_phone_at_end_of_string():
    text = "you can call me at 9876543210"
    hits = PhoneDetector().detect(text)
    e = hits[0]
    assert text[e.start:e.end] == "9876543210"
    assert e.end == len(text)


def test_entity_offsets_are_correct():
    text = "call 9876543210 now"
    hits = PhoneDetector().detect(text)
    e = hits[0]
    assert text[e.start:e.end] == "9876543210"


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def test_email_detects_basic():
    hits = EmailDetector().detect("reach me at test.user@example.co.in")
    assert len(hits) == 1
    assert hits[0].entity_type == "EMAIL"


def test_email_detects_simple_domain():
    text = "email: rahul@gmail.com"
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "rahul@gmail.com"


def test_email_rejects_no_tld_domain():
    # Looks email-shaped but the domain has no dot -> not a real email
    # (this is UPI-handle shape, see UPI tests below).
    hits = EmailDetector().detect("pay to rahul123@okhdfcbank")
    assert len(hits) == 0


def test_email_offset_correct():
    text = f"my email is test.user@example.co.in for contact"
    hits = EmailDetector().detect(text)
    e = hits[0]
    assert text[e.start:e.end] == "test.user@example.co.in"


# ---------------------------------------------------------------------------
# UPI
# ---------------------------------------------------------------------------

def test_upi_detects_valid_vpa():
    hits = UpiDetector().detect("pay to rahul123@okhdfcbank")
    assert len(hits) == 1
    assert hits[0].entity_type == "UPI"


def test_upi_detects_another_bank_suffix():
    text = "send money to priya.k@ybl"
    hits = UpiDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "priya.k@ybl"


def test_upi_does_not_double_count_as_email():
    text = "pay to rahul123@okhdfcbank"
    upi_hits = UpiDetector().detect(text)
    email_hits = EmailDetector().detect(text)
    assert len(upi_hits) == 1
    assert len(email_hits) == 0  # "okhdfcbank" has no TLD, not email-shaped


def test_upi_rejects_actual_email_shape():
    # A real email (dotted domain) must not be double-counted as UPI.
    hits = UpiDetector().detect("reach me at test.user@example.co.in")
    assert len(hits) == 0


# ---------------------------------------------------------------------------
# Email/UPI sentence-final-punctuation regression tests (Task 11)
# ---------------------------------------------------------------------------

def test_email_trailing_period_excluded_from_offsets():
    text = "Contact me at priya.verma@gmail.com."
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "priya.verma@gmail.com"


def test_email_trailing_comma_excluded_from_offsets():
    text = "Email me at priya.verma@gmail.com, thanks."
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "priya.verma@gmail.com"


def test_email_trailing_exclamation_excluded_from_offsets():
    text = "Email me at priya.verma@gmail.com!"
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "priya.verma@gmail.com"


def test_email_trailing_question_mark_excluded_from_offsets():
    text = "Is your email priya.verma@gmail.com?"
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "priya.verma@gmail.com"


def test_email_in_parentheses_excludes_closing_paren():
    text = "(reach me at test@example.com)"
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "test@example.com"


def test_email_no_trailing_punctuation_still_detected():
    text = "my email is test.user@example.co.in for contact"
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "test.user@example.co.in"


def test_email_multi_label_domain_with_trailing_period():
    text = "contact admin@mail.example.co.in."
    hits = EmailDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "admin@mail.example.co.in"


def test_upi_trailing_period_excluded_from_offsets():
    text = "pay to rahul123@okhdfcbank."
    hits = UpiDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "rahul123@okhdfcbank"


def test_upi_trailing_comma_excluded_from_offsets():
    text = "pay to rahul123@okhdfcbank, please"
    hits = UpiDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "rahul123@okhdfcbank"


def test_upi_does_not_leak_into_real_email_domain_label():
    # Critical regression-prevention test: relaxing the UPI trailing
    # lookahead to allow a sentence-final "." must NOT also allow it to
    # match into a real email's domain label (e.g. "example" out of
    # "user@example.com"). Only the EMAIL detector should fire here.
    text = "user@example.com"
    upi_hits = UpiDetector().detect(text)
    email_hits = EmailDetector().detect(text)
    assert upi_hits == []
    assert len(email_hits) == 1
    assert text[email_hits[0].start:email_hits[0].end] == "user@example.com"


def test_upi_no_trailing_punctuation_still_detected():
    text = "send money to priya.k@ybl now"
    hits = UpiDetector().detect(text)
    assert len(hits) == 1
    e = hits[0]
    assert text[e.start:e.end] == "priya.k@ybl"


# ---------------------------------------------------------------------------
# IFSC
# ---------------------------------------------------------------------------

def test_ifsc_detects_valid_code():
    hits = IfscDetector().detect("IFSC: HDFC0001234")
    assert len(hits) == 1
    assert hits[0].entity_type == "IFSC"


def test_ifsc_detects_another_valid_code():
    text = "branch code SBIN0123456 for transfer"
    hits = IfscDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "SBIN0123456"


def test_ifsc_rejects_wrong_5th_char():
    # 5th char must be literal '0' per NPCI spec
    hits = IfscDetector().detect("code: HDFC1001234")
    assert len(hits) == 0


# ---------------------------------------------------------------------------
# API key / secret
# ---------------------------------------------------------------------------

def test_api_key_detects_openai_style():
    text = "use sk-abcdEFGH1234567890ijklMNOP as the key"
    hits = ApiKeyDetector().detect(text)
    assert len(hits) == 1
    assert hits[0].entity_type == "API_KEY"
    assert text[hits[0].start:hits[0].end] == "sk-abcdEFGH1234567890ijklMNOP"


def test_api_key_detects_aws_access_key():
    # AWS's own documentation example key -- a publicly known placeholder,
    # not a real credential: https://docs.aws.amazon.com/IAM/
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = ApiKeyDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "AKIAIOSFODNN7EXAMPLE"


def test_api_key_detects_bearer_token():
    text = "Authorization: Bearer abcdefghij1234567890XYZ"
    hits = ApiKeyDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "abcdefghij1234567890XYZ"


def test_api_key_detects_generic_assignment():
    text = 'config: api_key="myTestSecretValue1234"'
    hits = ApiKeyDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "myTestSecretValue1234"


def test_api_key_detects_generic_token_colon_form():
    text = "token: abcdefghijklmnop1234"
    hits = ApiKeyDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "abcdefghijklmnop1234"


def test_api_key_rejects_short_assignment():
    hits = ApiKeyDetector().detect("key=short")
    assert len(hits) == 0


def test_api_key_rejects_plain_english_sentence():
    hits = ApiKeyDetector().detect("That secret is safe between us for now.")
    assert len(hits) == 0


def test_api_key_at_start_middle_end_of_text():
    prefix_text = "sk-abcdEFGH1234567890ijklMNOP is the new key"
    middle_text = "please rotate sk-abcdEFGH1234567890ijklMNOP right away"
    suffix_text = "the new key is sk-abcdEFGH1234567890ijklMNOP"
    for text in (prefix_text, middle_text, suffix_text):
        hits = ApiKeyDetector().detect(text)
        assert len(hits) == 1
        assert text[hits[0].start:hits[0].end] == "sk-abcdEFGH1234567890ijklMNOP"


# ---------------------------------------------------------------------------
# Card number
# ---------------------------------------------------------------------------
# Canonical, publicly-published test card numbers (Stripe/PayPal test docs)
# -- Luhn-valid, not real credentials, same convention as this project's
# use of AWS's own AKIAIOSFODNN7EXAMPLE for the API-key detector tests.
VALID_VISA_TEST_CARD = "4111111111111111"
VALID_AMEX_TEST_CARD = "378282246310005"
VALID_MASTERCARD_TEST_CARD = "5555555555554444"


def test_card_detects_unformatted_visa():
    text = f"card number {VALID_VISA_TEST_CARD} on file"
    hits = CardNumberDetector().detect(text)
    assert len(hits) == 1
    assert hits[0].entity_type == "CARD_NUMBER"
    assert text[hits[0].start:hits[0].end] == VALID_VISA_TEST_CARD


def test_card_detects_space_grouped_visa():
    text = "card number 4111 1111 1111 1111 on file"
    hits = CardNumberDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "4111 1111 1111 1111"


def test_card_detects_hyphen_grouped_mastercard():
    text = "pay with 5555-5555-5555-4444 please"
    hits = CardNumberDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "5555-5555-5555-4444"


def test_card_detects_15_digit_amex():
    text = f"amex {VALID_AMEX_TEST_CARD} expires soon"
    hits = CardNumberDetector().detect(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == VALID_AMEX_TEST_CARD


def test_card_rejects_invalid_luhn_checksum():
    # last digit changed from a valid test card -- breaks the checksum
    hits = CardNumberDetector().detect("card 4111111111111112 declined")
    assert len(hits) == 0


def test_card_rejects_short_digit_run():
    # 12 digits -- below the 13-digit minimum, not card-shaped
    hits = CardNumberDetector().detect("reference number 411111111111")
    assert len(hits) == 0


def test_card_does_not_collide_with_aadhaar():
    # A valid Aadhaar (12 digits) must not also be flagged as a card
    text = f"aadhaar {VALID_AADHAAR_1}"
    card_hits = CardNumberDetector().detect(text)
    assert len(card_hits) == 0


def test_card_at_start_middle_end_of_text():
    prefix = f"{VALID_VISA_TEST_CARD} is the card on file"
    middle = f"please use {VALID_VISA_TEST_CARD} for this order"
    suffix = f"the card on file is {VALID_VISA_TEST_CARD}"
    for text in (prefix, middle, suffix):
        hits = CardNumberDetector().detect(text)
        assert len(hits) == 1
        assert text[hits[0].start:hits[0].end] == VALID_VISA_TEST_CARD


# ---------------------------------------------------------------------------
# Cross-detector
# ---------------------------------------------------------------------------

def test_multiple_entities_same_text():
    text = f"Aadhaar {VALID_AADHAAR_1} and PAN ABCPE1234F"
    hits = AadhaarDetector().detect(text) + PanDetector().detect(text)
    assert len(hits) == 2


def test_multiple_entity_types_with_correct_individual_offsets():
    text = f"Call {'9876543210'} or email rahul@gmail.com about PAN ABCPE1234F"
    phone_hits = PhoneDetector().detect(text)
    email_hits = EmailDetector().detect(text)
    pan_hits = PanDetector().detect(text)
    assert len(phone_hits) == 1
    assert len(email_hits) == 1
    assert len(pan_hits) == 1
    assert text[phone_hits[0].start:phone_hits[0].end] == "9876543210"
    assert text[email_hits[0].start:email_hits[0].end] == "rahul@gmail.com"
    assert text[pan_hits[0].start:pan_hits[0].end] == "ABCPE1234F"

import pytest

from bharatguard.models import PIIEntity, Session
from bharatguard.policy.policy import PolicyConfig
from bharatguard.masking.mask import apply_masking, REDACTED_MARKER


def make_entity(entity_type, start, end, confidence=0.9, source="test"):
    return PIIEntity(entity_type=entity_type, start=start, end=end, confidence=confidence, source=source)


def test_mask_action_replaces_with_redacted_marker():
    text = "My PAN is ABCPD1234E please help"
    e = make_entity("PAN", 10, 20)
    assert text[10:20] == "ABCPD1234E"
    session = Session()
    policy = PolicyConfig()
    result = apply_masking(text, [e], policy, session)
    assert result == f"My PAN is {REDACTED_MARKER} please help"


def test_tokenize_action_replaces_with_type_token():
    text = "call 9876543210 now"
    e = make_entity("PHONE", 5, 15)
    session = Session()
    policy = PolicyConfig()
    result = apply_masking(text, [e], policy, session)
    assert result == "call <PHONE_1> now"
    assert session.lookup("PHONE_1") == "9876543210"


def test_tokenize_same_value_reuses_token():
    text = "9876543210 and again 9876543210"
    e1 = make_entity("PHONE", 0, 10)
    e2 = make_entity("PHONE", 21, 31)
    session = Session()
    policy = PolicyConfig()
    result = apply_masking(text, [e1, e2], policy, session)
    assert result == "<PHONE_1> and again <PHONE_1>"


def test_tokenize_different_values_get_different_tokens():
    text = "9876543210 and 8765432109"
    e1 = make_entity("PHONE", 0, 10)
    e2 = make_entity("PHONE", 15, 25)
    session = Session()
    policy = PolicyConfig()
    result = apply_masking(text, [e1, e2], policy, session)
    assert result == "<PHONE_1> and <PHONE_2>"


def test_ignore_action_leaves_value_unchanged():
    text = "phone is 9876543210 here"
    e = make_entity("PHONE", 9, 19)
    session = Session()
    policy = PolicyConfig(overrides={"PHONE": "ignore"})
    result = apply_masking(text, [e], policy, session)
    assert result == text


def test_right_to_left_replacement_no_offset_corruption():
    # entity near start with shorter replacement len than original span,
    # and another entity later -- verify start entity is still correct
    # after later entity replaced.
    text = "PAN ABCPD1234E and phone 9876543210 end"
    e_pan = make_entity("PAN", 4, 14)
    e_phone = make_entity("PHONE", 25, 35)
    session = Session()
    policy = PolicyConfig()
    result = apply_masking(text, [e_pan, e_phone], policy, session)
    assert result == f"PAN {REDACTED_MARKER} and phone <PHONE_1> end"


def test_multiple_entities_beginning_middle_end():
    text = "ABCPD1234E middle 9876543210 end EMAILhere"
    # PAN at start, PHONE in middle -- straightforward multi test
    e_pan = make_entity("PAN", 0, 10)
    e_phone = make_entity("PHONE", 19, 29)
    session = Session()
    policy = PolicyConfig()
    result = apply_masking(text, [e_pan, e_phone], policy, session)
    assert result.startswith(REDACTED_MARKER)
    assert "<PHONE_1>" in result


def test_overlapping_entities_raise_value_error():
    text = "9876543210"
    e1 = make_entity("PHONE", 0, 10)
    e2 = make_entity("PHONE", 5, 10)
    session = Session()
    policy = PolicyConfig()
    with pytest.raises(ValueError):
        apply_masking(text, [e1, e2], policy, session)


def test_out_of_bounds_entity_raises_value_error():
    text = "short"
    e = make_entity("PHONE", 0, 100)
    session = Session()
    policy = PolicyConfig()
    with pytest.raises(ValueError):
        apply_masking(text, [e], policy, session)


def test_exception_message_never_contains_raw_value():
    text = "9876543210"
    e1 = make_entity("PHONE", 0, 10)
    e2 = make_entity("PHONE", 5, 10)
    session = Session()
    policy = PolicyConfig()
    with pytest.raises(ValueError) as excinfo:
        apply_masking(text, [e1, e2], policy, session)
    assert "9876543210" not in str(excinfo.value)


def test_apply_masking_does_not_mutate_input_text_type():
    # Python strings are immutable, but ensure the original object we pass
    # in is untouched (not that it could be, but assert equality holds).
    text = "9876543210"
    original = text
    e = make_entity("PHONE", 0, 10)
    session = Session()
    policy = PolicyConfig()
    apply_masking(text, [e], policy, session)
    assert text == original

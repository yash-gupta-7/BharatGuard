"""Security tests for PIIGuard.protect()/restore(). All PII values below
are synthetic. The Aadhaar number is a fabricated number that happens to
satisfy the Verhoeff checksum algorithm structurally -- it is not a real
person's number."""
import copy
import re

import pytest

from bharatguard import PIIGuard, PolicyConfig, Session
from bharatguard.masking.mask import REDACTED_MARKER

SYNTHETIC_AADHAAR = "234123412346"  # passes Verhoeff, synthetic
SYNTHETIC_PAN = "ABCPD1234E"
SYNTHETIC_PHONE_1 = "9876543210"
SYNTHETIC_PHONE_2 = "8765432109"


def _canon(s: str) -> str:
    """Test-only helper: strips non-alphanumeric chars and lowercases, so
    differently-formatted variants of the same value are still caught by
    the leak check. Deliberately NOT used in production masking logic."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def assert_no_leak(raw_value: str, *haystacks: str) -> None:
    for haystack in haystacks:
        assert raw_value not in haystack, f"raw value leaked verbatim in: {haystack!r}"
        assert _canon(raw_value) not in _canon(haystack), (
            f"canonicalized raw value leaked in: {haystack!r}"
        )


# ---------------------------------------------------------------------------
# 1-2: mask actions
# ---------------------------------------------------------------------------

def test_aadhaar_masked_to_redacted():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"my aadhaar is {SYNTHETIC_AADHAAR}"}])
    content = protected.messages[0]["content"]
    assert REDACTED_MARKER in content
    assert SYNTHETIC_AADHAAR not in content


def test_pan_masked_to_redacted():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"my pan is {SYNTHETIC_PAN}"}])
    content = protected.messages[0]["content"]
    assert REDACTED_MARKER in content
    assert SYNTHETIC_PAN not in content


# ---------------------------------------------------------------------------
# 3-5: tokenize + reuse behavior
# ---------------------------------------------------------------------------

def test_phone_tokenized():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"call me at {SYNTHETIC_PHONE_1}"}])
    content = protected.messages[0]["content"]
    assert "<PHONE_1>" in content
    assert SYNTHETIC_PHONE_1 not in content


def test_repeated_same_phone_reuses_token():
    guard = PIIGuard()
    text = f"call {SYNTHETIC_PHONE_1} or call {SYNTHETIC_PHONE_1} again"
    protected = guard.protect([{"role": "user", "content": text}])
    content = protected.messages[0]["content"]
    assert content.count("<PHONE_1>") == 2
    assert "<PHONE_2>" not in content


def test_different_phones_get_different_tokens():
    guard = PIIGuard()
    text = f"first {SYNTHETIC_PHONE_1} second {SYNTHETIC_PHONE_2}"
    protected = guard.protect([{"role": "user", "content": text}])
    content = protected.messages[0]["content"]
    assert "<PHONE_1>" in content
    assert "<PHONE_2>" in content


# ---------------------------------------------------------------------------
# 6-7: multiple PII types, and position (start/middle/end)
# ---------------------------------------------------------------------------

def test_multiple_pii_types_in_one_message():
    guard = PIIGuard()
    text = f"Aadhaar {SYNTHETIC_AADHAAR} PAN {SYNTHETIC_PAN} phone {SYNTHETIC_PHONE_1}"
    protected = guard.protect([{"role": "user", "content": text}])
    content = protected.messages[0]["content"]
    assert SYNTHETIC_AADHAAR not in content
    assert SYNTHETIC_PAN not in content
    assert SYNTHETIC_PHONE_1 not in content
    assert REDACTED_MARKER in content
    assert "<PHONE_1>" in content


def test_pii_at_start_of_text():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"{SYNTHETIC_PAN} is my PAN"}])
    content = protected.messages[0]["content"]
    assert content.startswith(REDACTED_MARKER)
    assert SYNTHETIC_PAN not in content


def test_pii_in_middle_of_text():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"my pan {SYNTHETIC_PAN} is private"}])
    content = protected.messages[0]["content"]
    assert REDACTED_MARKER in content
    assert content.startswith("my pan")
    assert content.endswith("is private")


def test_pii_at_end_of_text():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"my pan is {SYNTHETIC_PAN}"}])
    content = protected.messages[0]["content"]
    assert content.endswith(REDACTED_MARKER)
    assert SYNTHETIC_PAN not in content


# ---------------------------------------------------------------------------
# 8: cross-message token reuse
# ---------------------------------------------------------------------------

def test_cross_message_token_reuse():
    guard = PIIGuard()
    protected = guard.protect([
        {"role": "user", "content": f"my phone is {SYNTHETIC_PHONE_1}"},
        {"role": "assistant", "content": "noted"},
        {"role": "user", "content": f"again, it's {SYNTHETIC_PHONE_1}"},
    ])
    first_content = protected.messages[0]["content"]
    third_content = protected.messages[2]["content"]
    assert "<PHONE_1>" in first_content
    assert "<PHONE_1>" in third_content
    assert "<PHONE_2>" not in third_content


# ---------------------------------------------------------------------------
# 9: mixed Hindi/Hinglish/English content
# ---------------------------------------------------------------------------

def test_mixed_hinglish_content_protected():
    guard = PIIGuard()
    text = f"mera phone number hai {SYNTHETIC_PHONE_1}, PAN card {SYNTHETIC_PAN} bhi hai"
    protected = guard.protect([{"role": "user", "content": text}])
    content = protected.messages[0]["content"]
    assert SYNTHETIC_PHONE_1 not in content
    assert SYNTHETIC_PAN not in content


# ---------------------------------------------------------------------------
# 10: original messages not mutated
# ---------------------------------------------------------------------------

def test_original_messages_not_mutated():
    original = [{"role": "user", "content": f"pan {SYNTHETIC_PAN}"}]
    snapshot = copy.deepcopy(original)
    guard = PIIGuard()
    guard.protect(original)
    assert original == snapshot


# ---------------------------------------------------------------------------
# 11: repr/str(session) never leaks
# ---------------------------------------------------------------------------

def test_session_repr_and_str_never_leak():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"phone {SYNTHETIC_PHONE_1}, pan {SYNTHETIC_PAN}"}])
    assert SYNTHETIC_PHONE_1 not in repr(protected.session)
    assert SYNTHETIC_PHONE_1 not in str(protected.session)
    assert SYNTHETIC_PAN not in repr(protected.session)
    assert "Session(entities=" in repr(protected.session)


# ---------------------------------------------------------------------------
# 12-13: raw values never appear in output, recoverable only via Session
# ---------------------------------------------------------------------------

def test_raw_values_never_in_protected_output_and_only_recoverable_via_session():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"phone {SYNTHETIC_PHONE_1}"}])
    content = protected.messages[0]["content"]
    assert SYNTHETIC_PHONE_1 not in content
    # only path back to the raw value: session.lookup()
    assert protected.session.lookup("PHONE_1") == SYNTHETIC_PHONE_1


# ---------------------------------------------------------------------------
# 14-15: restore()
# ---------------------------------------------------------------------------

def test_restore_replaces_known_token():
    guard = PIIGuard()
    protected = guard.protect([{"role": "user", "content": f"phone {SYNTHETIC_PHONE_1}"}])
    response = "Sure, I noted your number <PHONE_1>."
    restored = guard.restore(response, protected.session)
    assert SYNTHETIC_PHONE_1 in restored
    assert "<PHONE_1>" not in restored


def test_restore_leaves_unknown_token_untouched():
    guard = PIIGuard()
    session = Session()
    response = "here is a foreign token <PHONE_99> untouched"
    restored = guard.restore(response, session)
    assert restored == response


# ---------------------------------------------------------------------------
# 16 + negative case: action="ignore"
# ---------------------------------------------------------------------------

def test_ignore_action_leaves_value_in_output_not_a_leak():
    policy = PolicyConfig(overrides={"PHONE": "ignore"})
    guard = PIIGuard(policy=policy)
    protected = guard.protect([{"role": "user", "content": f"phone {SYNTHETIC_PHONE_1}"}])
    content = protected.messages[0]["content"]
    # intentional: policy says ignore, value must remain, this is NOT a leak
    assert SYNTHETIC_PHONE_1 in content


# ---------------------------------------------------------------------------
# 17: custom PolicyConfig override
# ---------------------------------------------------------------------------

def test_custom_policy_override_changes_only_that_type():
    policy = PolicyConfig(overrides={"PHONE": "mask"})
    guard = PIIGuard(policy=policy)
    text = f"phone {SYNTHETIC_PHONE_1} pan {SYNTHETIC_PAN}"
    protected = guard.protect([{"role": "user", "content": text}])
    content = protected.messages[0]["content"]
    assert "<PHONE_1>" not in content
    assert content.count(REDACTED_MARKER) == 2  # both PHONE and PAN masked


# ---------------------------------------------------------------------------
# 18: replacement ordering / no offset corruption at the protect() level
# ---------------------------------------------------------------------------

def test_replacement_ordering_no_offset_corruption():
    guard = PIIGuard()
    text = f"start pan {SYNTHETIC_PAN} middle phone {SYNTHETIC_PHONE_1} end"
    protected = guard.protect([{"role": "user", "content": text}])
    content = protected.messages[0]["content"]
    assert content.startswith("start pan ")
    assert REDACTED_MARKER in content
    assert "<PHONE_1>" in content
    assert content.endswith(" end")
    assert SYNTHETIC_PAN not in content
    assert SYNTHETIC_PHONE_1 not in content


# ---------------------------------------------------------------------------
# Critical privacy invariant test (thorough)
# ---------------------------------------------------------------------------

def test_privacy_invariant_no_raw_value_leaks_for_mask_or_tokenize():
    guard = PIIGuard()
    messages = [
        {"role": "user", "content": (
            f"Aadhaar {SYNTHETIC_AADHAAR}, PAN {SYNTHETIC_PAN}, "
            f"phone {SYNTHETIC_PHONE_1}, another phone {SYNTHETIC_PHONE_2}"
        )},
    ]
    protected = guard.protect(messages)
    all_content = " ".join(m["content"] for m in protected.messages)
    session_dump = repr(protected.session) + str(protected.session)

    # exact + canonicalized-variant checks for every protected raw value
    for raw in (SYNTHETIC_AADHAAR, SYNTHETIC_PAN, SYNTHETIC_PHONE_1, SYNTHETIC_PHONE_2):
        assert_no_leak(raw, all_content, session_dump)

    # differently-formatted variants of the phone number must also be absent
    formatted_variants = [
        f"+91 {SYNTHETIC_PHONE_1}",
        f"{SYNTHETIC_PHONE_1[:5]}-{SYNTHETIC_PHONE_1[5:]}",
    ]
    for variant in formatted_variants:
        assert _canon(variant) not in _canon(all_content)
        assert _canon(variant) not in _canon(session_dump)

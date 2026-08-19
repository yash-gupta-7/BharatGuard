"""Tests for the SarvamClient SDK wrapper (src/bharatguard/integrations/sarvam.py).

No test in this file makes a network call: the real `sarvamai.SarvamAI`
class construction is always mocked/stubbed via `unittest.mock.patch`, or
avoided entirely by exercising only the ValueError-when-missing-key path.
`FakeSarvamClient` is used for the security-invariant integration test and
never touches the network either.

All PII values below are synthetic, matching the fixtures used elsewhere
in this project's test suite (see tests/test_core.py).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from bharatguard import PIIGuard
from bharatguard.integrations.sarvam import (
    ChatResponse,
    FakeSarvamClient,
    SarvamClient,
    TranscribeResponse,
)

SYNTHETIC_AADHAAR = "234123412346"  # passes Verhoeff, synthetic -- see tests/test_core.py
FAKE_KEY = "test-key-not-real"


# ---------------------------------------------------------------------------
# 1. Construction never exposes the API key via repr()/str()
# ---------------------------------------------------------------------------

def test_repr_does_not_leak_api_key():
    with patch("bharatguard.integrations.sarvam.SarvamAI"):
        client = SarvamClient(api_key=FAKE_KEY)
    assert FAKE_KEY not in repr(client)
    assert FAKE_KEY not in str(client)


def test_missing_api_key_raises_value_error_without_leaking_anything():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError) as exc_info:
            SarvamClient()
    # Points to .env.example, doesn't contain any key material (there is none to leak).
    assert "SARVAM_API_KEY" in str(exc_info.value)
    assert ".env.example" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 2-3. chat() delegates to the SDK correctly, messages passed through unchanged
# ---------------------------------------------------------------------------

def _make_sdk_chat_response(content: str) -> MagicMock:
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def test_chat_delegates_to_sdk_with_default_model():
    with patch("bharatguard.integrations.sarvam.SarvamAI") as mock_sdk_cls:
        mock_sdk = mock_sdk_cls.return_value
        mock_sdk.chat.completions.return_value = _make_sdk_chat_response("hello back")

        client = SarvamClient(api_key=FAKE_KEY)
        messages = [{"role": "user", "content": "hello"}]
        client.chat(messages)

        mock_sdk.chat.completions.assert_called_once_with(
            model="sarvam-105b", messages=messages
        )


def test_chat_passes_messages_through_unchanged():
    with patch("bharatguard.integrations.sarvam.SarvamAI") as mock_sdk_cls:
        mock_sdk = mock_sdk_cls.return_value
        mock_sdk.chat.completions.return_value = _make_sdk_chat_response("ok")

        client = SarvamClient(api_key=FAKE_KEY)
        messages = [{"role": "user", "content": "hello"}, {"role": "system", "content": "sys"}]
        original = [dict(m) for m in messages]
        client.chat(messages, model="sarvam-105b")

        _, kwargs = mock_sdk.chat.completions.call_args
        assert kwargs["messages"] == original
        assert kwargs["messages"] is messages  # no copying/wrapping/transformation


def test_chat_accepts_custom_model():
    with patch("bharatguard.integrations.sarvam.SarvamAI") as mock_sdk_cls:
        mock_sdk = mock_sdk_cls.return_value
        mock_sdk.chat.completions.return_value = _make_sdk_chat_response("ok")

        client = SarvamClient(api_key=FAKE_KEY)
        client.chat([{"role": "user", "content": "hi"}], model="some-other-model")

        _, kwargs = mock_sdk.chat.completions.call_args
        assert kwargs["model"] == "some-other-model"


# ---------------------------------------------------------------------------
# 4. SDK response converted into the expected simple response representation
# ---------------------------------------------------------------------------

def test_chat_returns_simple_response_representation():
    with patch("bharatguard.integrations.sarvam.SarvamAI") as mock_sdk_cls:
        mock_sdk = mock_sdk_cls.return_value
        mock_sdk.chat.completions.return_value = _make_sdk_chat_response("assistant text")

        client = SarvamClient(api_key=FAKE_KEY)
        result = client.chat([{"role": "user", "content": "hi"}])

        assert isinstance(result, ChatResponse)
        assert result.choices[0].message.content == "assistant text"


# ---------------------------------------------------------------------------
# 5. SDK errors surface without leaking raw input/API credentials
# ---------------------------------------------------------------------------

def test_chat_error_does_not_leak_api_key_or_message_content():
    with patch("bharatguard.integrations.sarvam.SarvamAI") as mock_sdk_cls:
        mock_sdk = mock_sdk_cls.return_value
        mock_sdk.chat.completions.side_effect = RuntimeError("upstream 500")

        client = SarvamClient(api_key=FAKE_KEY)
        secret_content = "super secret raw PII content 234123412346"
        with pytest.raises(Exception) as exc_info:
            client.chat([{"role": "user", "content": secret_content}])

        assert FAKE_KEY not in str(exc_info.value)
        assert secret_content not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6. transcribe() delegates correctly to Saaras v3
# ---------------------------------------------------------------------------

def test_transcribe_delegates_to_sdk_with_saaras_v3():
    with patch("bharatguard.integrations.sarvam.SarvamAI") as mock_sdk_cls:
        mock_sdk = mock_sdk_cls.return_value
        sdk_response = MagicMock()
        sdk_response.transcript = "transcribed text"
        mock_sdk.speech_to_text.transcribe.return_value = sdk_response

        client = SarvamClient(api_key=FAKE_KEY)
        fake_file = object()
        result = client.transcribe(fake_file)

        mock_sdk.speech_to_text.transcribe.assert_called_once_with(
            file=fake_file, model="saaras:v3", mode="transcribe"
        )
        assert isinstance(result, TranscribeResponse)
        assert result.transcript == "transcribed text"


# ---------------------------------------------------------------------------
# 7. (structural) No test in this file makes a network call -- every test
# either patches bharatguard.integrations.sarvam.SarvamAI, or exercises only
# the ValueError-before-SDK-construction path. Grepped manually: no test
# constructs SarvamClient without patching SarvamAI first, except the
# missing-key test which raises before any SDK call would occur.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 8. FakeSarvamClient-based integration test proving the security invariant:
# protected messages only, no raw PII reaches the client.
# ---------------------------------------------------------------------------

def test_protected_messages_reaching_fake_client_contain_no_raw_pii():
    guard = PIIGuard()
    fake_client = FakeSarvamClient()

    messages = [{"role": "user", "content": f"My Aadhaar number is {SYNTHETIC_AADHAAR}."}]
    protected = guard.protect(messages)

    fake_client.chat(protected.messages)

    assert fake_client.last_messages == protected.messages
    for message in fake_client.last_messages:
        assert SYNTHETIC_AADHAAR not in message["content"]


def test_fake_sarvam_client_chat_returns_configurable_canned_response():
    fake_client = FakeSarvamClient(chat_response="canned reply")
    result = fake_client.chat([{"role": "user", "content": "hi"}])
    assert result.choices[0].message.content == "canned reply"


def test_fake_sarvam_client_transcribe_no_network_and_records_call():
    fake_client = FakeSarvamClient(transcribe_response="canned transcript")
    result = fake_client.transcribe("fake-file-object")
    assert result.transcript == "canned transcript"
    assert fake_client.last_transcribe_file == "fake-file-object"

"""Thin wrapper around the official Sarvam SDK (`sarvamai`).

This is the ONLY module in BharatGuard allowed to import `sarvamai` -- see
the "Architectural boundary" section of the Task 8 brief. `SarvamClient` is
a dumb transport layer: it performs no PII detection or masking of its own.
Callers are responsible for passing already-protected messages (produced by
`PIIGuard.protect()`) into `chat()`.

Never log or print the messages/content sent or received here, and never
include prompt content, response content, or the API key in any exception
message raised or re-raised from this module.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from sarvamai import SarvamAI

_MISSING_KEY_MESSAGE = (
    "SARVAM_API_KEY is not set. Provide it via the api_key argument or set "
    "the SARVAM_API_KEY environment variable -- see .env.example."
)


@dataclass
class Message:
    content: str | None


@dataclass
class Choice:
    message: Message


@dataclass
class ChatResponse:
    """Small, explicit stand-in for the SDK's chat completion response,
    mirroring its choices[0].message.content shape closely enough to be
    unsurprising to callers, without exposing the raw SDK object."""
    choices: list[Choice]


@dataclass
class TranscribeResponse:
    transcript: str


class SarvamClient:
    """Wraps `sarvamai.SarvamAI` for chat completions and speech-to-text.
    Does not detect or mask PII -- callers must pass already-protected
    messages (see `bharatguard.PIIGuard.protect()`)."""

    def __init__(self, api_key: str | None = None) -> None:
        key = api_key if api_key is not None else os.environ.get("SARVAM_API_KEY")
        if not key:
            raise ValueError(_MISSING_KEY_MESSAGE)
        self._sdk = SarvamAI(api_subscription_key=key)

    def __repr__(self) -> str:
        return "SarvamClient()"

    __str__ = __repr__

    def chat(self, messages: list[dict], model: str = "sarvam-105b") -> ChatResponse:
        try:
            response = self._sdk.chat.completions(model=model, messages=messages)
        except Exception as exc:
            raise RuntimeError(
                f"Sarvam chat completion failed ({type(exc).__name__})"
            ) from None
        content = response.choices[0].message.content
        return ChatResponse(choices=[Choice(message=Message(content=content))])

    def transcribe(self, file, model: str = "saaras:v3") -> TranscribeResponse:
        try:
            response = self._sdk.speech_to_text.transcribe(
                file=file, model=model, mode="transcribe"
            )
        except Exception as exc:
            raise RuntimeError(
                f"Sarvam transcription failed ({type(exc).__name__})"
            ) from None
        return TranscribeResponse(transcript=response.transcript)


class FakeSarvamClient:
    """No-network test double with the same two-method interface as
    SarvamClient. Records the last call so tests can assert on the outgoing
    payload, and returns a configurable canned response."""

    def __init__(
        self,
        chat_response: str = "fake response",
        transcribe_response: str = "fake transcript",
    ) -> None:
        self._chat_response = chat_response
        self._transcribe_response = transcribe_response
        self.last_messages: list[dict] = []
        self.last_transcribe_file = None

    def chat(self, messages: list[dict], model: str = "sarvam-105b") -> ChatResponse:
        self.last_messages = messages
        return ChatResponse(choices=[Choice(message=Message(content=self._chat_response))])

    def transcribe(self, file, model: str = "saaras:v3") -> TranscribeResponse:
        self.last_transcribe_file = file
        return TranscribeResponse(transcript=self._transcribe_response)

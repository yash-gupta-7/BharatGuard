"""BharatGuard demo API server.

A thin FastAPI wrapper around PIIGuard for the React demo UI. The Sarvam
API key never leaves this process: the browser only ever sees entity
types/confidences, the protected text, the Sarvam response, and the
restored text -- never the raw API key, never the in-memory Session's
token->value mapping, never raw PII once masking has run.

Every endpoint here returns data computed from the real library/eval
code -- nothing is fabricated. /api/evaluation runs the actual evaluation
harness (evals/run_eval.py) once and caches the result; /api/detectors
reflects the real DEFAULT_POLICY; /api/protect runs the real pipeline.

Run: uvicorn server.main:app --reload --port 8000
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from bharatguard.core import PIIGuard
from bharatguard.detectors.contextual import IndianAddressDetector, SpacyPersonDetector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.merge import merge_entities
from bharatguard.integrations.sarvam import FakeSarvamClient, SarvamClient
from bharatguard.models import PIIEntity
from bharatguard.normalization.normalize import normalize
from bharatguard.policy.policy import DEFAULT_POLICY, PolicyConfig

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evals.run_eval import (  # noqa: E402
    CONTEXTUAL_DETECTORS as EVAL_CONTEXTUAL_DETECTORS,
    DATASET_PATH,
    evaluate_config,
    evaluate_leakage,
    load_dataset,
)

load_dotenv()

app = FastAPI(title="BharatGuard demo API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_CONTEXTUAL_DETECTORS = [SpacyPersonDetector(), IndianAddressDetector()]

# entity_type -> which layer detects it. Matches the real detector
# registry: DETERMINISTIC_DETECTORS covers the first six, contextual
# detectors cover PERSON/ADDRESS.
_DETECTOR_CATEGORY = {
    "AADHAAR": "deterministic", "PAN": "deterministic", "PHONE": "deterministic",
    "EMAIL": "deterministic", "UPI": "deterministic", "IFSC": "deterministic",
    "API_KEY": "deterministic", "CARD_NUMBER": "deterministic",
    "PERSON": "contextual", "ADDRESS": "contextual",
}

_VALID_ACTIONS = {"mask", "tokenize", "ignore"}


class ProtectRequest(BaseModel):
    text: str
    policy_overrides: dict[str, str] | None = None


class EntitySummary(BaseModel):
    entity_type: str
    confidence: float


class ProtectResponse(BaseModel):
    entities: list[EntitySummary]
    protected_text: str
    sarvam_request: str
    sarvam_response: str
    restored_response: str
    mocked: bool


class DetectorInfo(BaseModel):
    entity_type: str
    category: str
    default_action: str


class EvaluationResponse(BaseModel):
    dataset_size: int
    configs: dict[str, dict]
    leakage: dict
    computed_at: float


def _translate_entity(entity: PIIEntity, offset_map: list[int]) -> PIIEntity:
    """Same translation formula used throughout the project: maps an
    entity's span from normalized-text space back to original-text
    space (see src/bharatguard/core.py / evals/run_eval.py)."""
    if entity.end <= entity.start:
        orig_start = entity.start if entity.start >= len(offset_map) else offset_map[entity.start]
        return PIIEntity(entity.entity_type, orig_start, orig_start, entity.confidence, entity.source)
    orig_start = offset_map[entity.start]
    orig_end = offset_map[entity.end - 1] + 1
    return PIIEntity(entity.entity_type, orig_start, orig_end, entity.confidence, entity.source)


def _detect_entities(text: str) -> list[PIIEntity]:
    """Detection-only pipeline for display, mirroring core.py's internal
    sequence. protect() below still does its own independent detect+mask
    pass -- this is purely so the API response can show entity metadata."""
    normalized_text, offset_map = normalize(text)
    raw_entities: list[PIIEntity] = []
    for detector in DETERMINISTIC_DETECTORS + _CONTEXTUAL_DETECTORS:
        raw_entities.extend(detector.detect(normalized_text))
    translated = [_translate_entity(e, offset_map) for e in raw_entities]
    return merge_entities(translated)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/detectors", response_model=list[DetectorInfo])
def detectors() -> list[DetectorInfo]:
    return [
        DetectorInfo(
            entity_type=entity_type,
            category=_DETECTOR_CATEGORY[entity_type],
            default_action=DEFAULT_POLICY[entity_type],
        )
        for entity_type in DEFAULT_POLICY
    ]


_evaluation_cache: dict | None = None


@app.get("/api/evaluation", response_model=EvaluationResponse)
def evaluation() -> EvaluationResponse:
    """Runs the real evaluation harness once per process and caches the
    result -- these are the same numbers `python evals/run_eval.py`
    produces, not hardcoded/fabricated figures."""
    global _evaluation_cache
    if _evaluation_cache is None:
        rows = load_dataset(DATASET_PATH)
        config_a = evaluate_config(rows, DETERMINISTIC_DETECTORS)
        config_b = evaluate_config(rows, DETERMINISTIC_DETECTORS + EVAL_CONTEXTUAL_DETECTORS)
        leakage = evaluate_leakage(rows)
        _evaluation_cache = {
            "dataset_size": len(rows),
            "configs": {"deterministic": config_a, "deterministic_contextual": config_b},
            "leakage": leakage,
            "computed_at": time.time(),
        }
    return EvaluationResponse(**_evaluation_cache)


@app.post("/api/protect", response_model=ProtectResponse)
def protect(req: ProtectRequest) -> ProtectResponse:
    policy = None
    if req.policy_overrides:
        for action in req.policy_overrides.values():
            if action not in _VALID_ACTIONS:
                return ProtectResponse(
                    entities=[], protected_text="", sarvam_request="",
                    sarvam_response=f"Invalid policy action: {action!r}",
                    restored_response="", mocked=True,
                )
        policy = PolicyConfig(req.policy_overrides)

    guard = PIIGuard(policy=policy) if policy else PIIGuard()
    entities = _detect_entities(req.text)

    protected = guard.protect([{"role": "user", "content": req.text}])
    protected_content = protected.messages[0]["content"]

    api_key = os.environ.get("SARVAM_API_KEY")
    mocked = not bool(api_key)
    client = (
        SarvamClient()
        if api_key
        else FakeSarvamClient(
            chat_response="[MOCKED SARVAM RESPONSE] Thanks, I've noted <AADHAAR_1> for your request."
        )
    )

    response = client.chat(messages=protected.messages)
    response_content = response.choices[0].message.content
    restored = guard.restore(response_content, protected.session)

    return ProtectResponse(
        entities=[EntitySummary(entity_type=e.entity_type, confidence=e.confidence) for e in entities],
        protected_text=protected_content,
        sarvam_request=str(protected.messages),
        sarvam_response=response_content,
        restored_response=restored,
        mocked=mocked,
    )

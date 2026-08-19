"""BharatGuard Streamlit demo.

A single-page, single-file demo: pick (or type) an example, click Protect,
and watch it move through detection -> masking -> a Sarvam chat call ->
token restoration. Native Streamlit widgets only -- no custom CSS/theming.

Entity-list retrieval: PIIGuard.protect() does not expose the entities it
found (by design -- see core.py). To show them here we replicate the same
small normalize -> detect -> translate-offsets -> merge_entities sequence
that evals/run_eval.py already uses for exactly this purpose, rather than
adding a new method to core.py.
"""
from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv

from bharatguard.core import PIIGuard
from bharatguard.detectors.contextual import IndianAddressDetector, SpacyPersonDetector
from bharatguard.detectors.deterministic import DETERMINISTIC_DETECTORS
from bharatguard.detectors.merge import merge_entities
from bharatguard.integrations.sarvam import FakeSarvamClient, SarvamClient
from bharatguard.models import PIIEntity
from bharatguard.normalization.normalize import normalize

load_dotenv()

_CONTEXTUAL_DETECTORS = [SpacyPersonDetector(), IndianAddressDetector()]

EXAMPLES = {
    "English": "My Aadhaar number is 234123412346 and my phone is 9876543210.",
    "Hindi": "मेरा आधार नंबर 234123412346 है और फोन नंबर 9876543210 है।",
    "Hinglish": "mera aadhaar number hai 234123412346, aur PAN ABCPE1234F bhi hai",
    "Indic numerals": "मेरा आधार नंबर २३४१२३४१२३४६ है।",
}


def _translate_entity(entity: PIIEntity, offset_map: list[int]) -> PIIEntity:
    """Same translation formula as evals/run_eval.py: maps an entity's
    span from normalized-text space back to original-text space."""
    if entity.end <= entity.start:
        orig_start = entity.start if entity.start >= len(offset_map) else offset_map[entity.start]
        return PIIEntity(entity.entity_type, orig_start, orig_start, entity.confidence, entity.source)
    orig_start = offset_map[entity.start]
    orig_end = offset_map[entity.end - 1] + 1
    return PIIEntity(entity.entity_type, orig_start, orig_end, entity.confidence, entity.source)


def detect_entities(text: str) -> list[PIIEntity]:
    """Replicates core.py's detect-and-translate pipeline (deterministic +
    contextual detectors -> translate offsets -> merge) purely for display
    purposes. Does not affect what PIIGuard.protect() actually does."""
    normalized_text, offset_map = normalize(text)
    raw_entities: list[PIIEntity] = []
    for detector in DETERMINISTIC_DETECTORS + _CONTEXTUAL_DETECTORS:
        raw_entities.extend(detector.detect(normalized_text))
    translated = [_translate_entity(e, offset_map) for e in raw_entities]
    return merge_entities(translated)


st.title("BharatGuard Demo")

st.header("User Input")
example_name = st.selectbox("Example", list(EXAMPLES.keys()))
text = st.text_area("Text", value=EXAMPLES[example_name], height=100)
protect_clicked = st.button("Protect")

if protect_clicked:
    guard = PIIGuard()
    entities = detect_entities(text)

    st.header("Detected PII")
    if not entities:
        st.info("No PII detected.")
    else:
        for entity in entities:
            st.write(f"**{entity.entity_type}**")
            st.progress(entity.confidence)

    protected = guard.protect([{"role": "user", "content": text}])
    protected_content = protected.messages[0]["content"]

    st.header("Protected Text")
    st.code(protected_content)

    st.header("Sarvam Request")
    st.code(str(protected.messages))

    api_key = os.environ.get("SARVAM_API_KEY")
    if api_key:
        client = SarvamClient()
    else:
        st.info("No SARVAM_API_KEY found -- running in mocked mode with a canned response.")
        client = FakeSarvamClient(
            chat_response="[MOCKED SARVAM RESPONSE] Thanks, I've noted <AADHAAR_1> for your request."
        )

    response = client.chat(messages=protected.messages)
    response_content = response.choices[0].message.content

    st.header("Sarvam Response")
    st.code(response_content)

    st.header("Restored Response (optional token-restoration step)")
    st.code(guard.restore(response_content, protected.session))

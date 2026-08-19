import pytest

from bharatguard.policy.policy import PolicyConfig, DEFAULT_POLICY


def test_default_policy_mapping_exact():
    assert DEFAULT_POLICY == {
        "AADHAAR": "mask",
        "PAN": "mask",
        "IFSC": "mask",
        "PHONE": "tokenize",
        "EMAIL": "tokenize",
        "UPI": "tokenize",
        "PERSON": "tokenize",
        "ADDRESS": "mask",
    }


def test_policy_config_default_actions():
    policy = PolicyConfig()
    assert policy.action_for("AADHAAR") == "mask"
    assert policy.action_for("PHONE") == "tokenize"


def test_policy_config_override_single_type():
    policy = PolicyConfig(overrides={"PHONE": "ignore"})
    assert policy.action_for("PHONE") == "ignore"
    # everything else remains default
    assert policy.action_for("AADHAAR") == "mask"
    assert policy.action_for("PERSON") == "tokenize"


def test_policy_config_invalid_action_raises():
    with pytest.raises(ValueError):
        PolicyConfig(overrides={"PHONE": "delete"})


def test_policy_config_unknown_entity_type_defaults_to_mask_or_raises():
    # entity types outside the known set: action_for should not silently
    # return None. Default policy has no entry, so behavior must be defined.
    policy = PolicyConfig()
    with pytest.raises(KeyError):
        policy.action_for("UNKNOWN_TYPE")

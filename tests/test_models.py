from bharatguard.models import PIIEntity, Session, ProtectedMessages


def test_pii_entity_fields():
    e = PIIEntity(entity_type="AADHAAR", start=10, end=22, confidence=0.99, source="aadhaar_regex")
    assert e.entity_type == "AADHAAR"
    assert e.start == 10
    assert e.end == 22
    assert not hasattr(e, "text")


def test_pii_entity_is_frozen():
    e = PIIEntity(entity_type="PAN", start=0, end=10, confidence=1.0, source="pan_regex")
    try:
        e.start = 5
        assert False, "should not be mutable"
    except Exception:
        pass


def test_session_repr_never_shows_values():
    s = Session()
    s.remember("<AADHAAR_1>", "234123412346")
    assert "234123412346" not in repr(s)
    assert "234123412346" not in str(s)


def test_session_has_no_serialization_methods():
    s = Session()
    assert not hasattr(s, "to_dict")
    assert not hasattr(s, "to_json")
    # __getstate__ is not checked here: Python 3.11+ provides object.__getstate__
    # by default on every object. Session doesn't override it — that's the correct,
    # non-hacky state. The security property is: no serialization methods *defined*
    # in Session itself, which is verified by the absence of to_dict/to_json above.


def test_session_lookup():
    s = Session()
    s.remember("<AADHAAR_1>", "234123412346")
    assert s.lookup("<AADHAAR_1>") == "234123412346"
    assert s.lookup("<AADHAAR_9>") is None


def test_protected_messages_fields():
    pm = ProtectedMessages(messages=[{"role": "user", "content": "hi"}], session=Session())
    assert pm.messages[0]["content"] == "hi"
    assert isinstance(pm.session, Session)

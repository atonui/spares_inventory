import json
from uuid import uuid4


def test_security_event_writer_stores_allowlisted_global_event_without_raw_identifier():
    from backend.services.security_events import record_security_event

    class Capture:
        query = None
        params = None

        def execute(self, query, params):
            self.query, self.params = query, params

    conn = Capture()
    record_security_event(
        conn,
        event="login_failed",
        outcome="failure",
        actor_user_id=None,
        request_id=str(uuid4()),
        ip_address="203.0.113.5",
        user_agent="test-agent",
        details={"account_match": False, "email": "person@example.test", "password": "secret"},
    )

    assert "INSERT INTO platform_security_events" in conn.query
    payload = json.loads(conn.params[-1])
    assert payload == {"account_match": False}
    assert "person@example.test" not in str(conn.params)
    assert "secret" not in str(conn.params)


def test_security_event_writer_rejects_unknown_event():
    import pytest
    from backend.services.security_events import record_security_event

    with pytest.raises(ValueError, match="Unsupported security event"):
        record_security_event(object(), event="arbitrary", outcome="failure")


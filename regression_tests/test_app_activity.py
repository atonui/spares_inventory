import json
import asyncio
from contextlib import closing


class CapturingLogger:
    def __init__(self):
        self.infos = []
        self.errors = []
        self.exceptions = []

    def info(self, message):
        self.infos.append(message)

    def error(self, message, *args, **kwargs):
        self.errors.append(message)

    def exception(self, message, *args, **kwargs):
        self.exceptions.append(message)


def test_main_log_endpoint_uses_current_activity_callback_after_decoration(monkeypatch):
    import main

    calls = []

    class FakeConnection:
        def cursor(self):
            return self

        def execute(self, *args, **kwargs):
            return self

        def fetchone(self):
            return {"name": "Late User"}

        def close(self):
            pass

    monkeypatch.setattr(main, "get_db_connection", lambda: FakeConnection())

    @main.log_endpoint(action="view_late", resource_type="thing")
    async def handler(*, user_id):
        return {"id": 12, "password_hash": "hidden"}

    def current_activity(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(main, "log_authenticated_activity", current_activity)

    result = asyncio.run(handler(user_id=44))

    assert result == {"id": 12, "password_hash": "hidden"}
    assert calls == [
        {
            "user_id": 44,
            "session_token": None,
            "username": "Late User",
            "action": "view_late",
            "resource_type": "thing",
            "resource_id": 12,
            "details": {"id": 12},
            "status": "success",
            "error_message": None,
            "ip_address": None,
            "user_agent": None,
        }
    ]


def test_standalone_activity_on_postgres_logs_audit_line_without_failing(stock_database):
    """No company context: keep the audit line, never attempt a company activity row."""
    from backend.app_activity import log_activity

    audit_logger, error_logger = CapturingLogger(), CapturingLogger()
    log_activity(stock_database.connect, audit_logger, error_logger, user_id=0, username="unknown",
                 action="verify_reset_token_failed", details={"reason": "invalid_token"}, status="error")
    assert audit_logger.infos == ["USER=unknown(0) ACTION=verify_reset_token_failed RESOURCE=None/None STATUS=error"]
    assert error_logger.errors == []
    assert stock_database.db.execute("SELECT count(*) AS n FROM activity_logs").fetchone()["n"] == 0


def test_mutation_activity_on_postgres_is_company_scoped_and_strips_sensitive_fields(stock_database):
    from backend.app_activity import record_mutation_activity
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.tenant_context import set_tenant_context
    from regression_tests.postgres_app import ORG_A

    principal = AuthenticatedPrincipal(3, ORG_A, "engineer", False)
    with stock_database.connect() as conn, conn.transaction():
        set_tenant_context(conn, ORG_A)
        record_mutation_activity(conn, user_id=principal, action="create_part", resource_type="part",
                                 result={"id": 55, "name": "Created", "password_hash": "secret",
                                         "session_token": "token", "reset_token": "reset"}, request=None)
    row = stock_database.db.execute(
        "SELECT organization_id, user_id, username, resource_id, details FROM activity_logs").fetchone()
    assert (row["organization_id"], row["user_id"], row["username"], row["resource_id"]) == (ORG_A, 3, "Engineer", 55)
    assert json.loads(row["details"]) == {"id": 55, "name": "Created"}

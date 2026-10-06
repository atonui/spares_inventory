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


def initialized_database(tmp_path):
    from backend.database import connect_database, initialize_database

    path = tmp_path / "activity.db"
    initialize_database(path, defaults={})
    return path, lambda: connect_database(path)


def test_app_activity_log_activity_writes_row_commits_and_audits(tmp_path):
    from backend.app_activity import log_activity
    from backend.database import connect_database

    path, get_connection = initialized_database(tmp_path)
    audit_logger = CapturingLogger()
    error_logger = CapturingLogger()

    log_activity(
        get_connection,
        audit_logger,
        error_logger,
        user_id=0,
        username="System",
        action="startup",
        resource_type="system",
        resource_id=7,
        details={"ok": True},
        ip_address="127.0.0.1",
        user_agent="test-agent",
    )

    with closing(connect_database(path)) as conn:
        row = conn.execute(
            "SELECT user_id, username, action, resource_type, resource_id, "
            "details, ip_address, user_agent, status FROM activity_logs"
        ).fetchone()

    assert row["user_id"] is None
    assert row["username"] == "System"
    assert row["action"] == "startup"
    assert row["resource_type"] == "system"
    assert row["resource_id"] == 7
    assert json.loads(row["details"]) == {"ok": True}
    assert row["ip_address"] == "127.0.0.1"
    assert row["user_agent"] == "test-agent"
    assert row["status"] == "success"
    assert audit_logger.infos == [
        "USER=System(0) ACTION=startup RESOURCE=system/7 STATUS=success"
    ]
    assert error_logger.errors == []


def test_app_activity_mutation_activity_strips_sensitive_result_fields(tmp_path):
    from backend.app_activity import record_mutation_activity
    from backend.database import connect_database

    path, _ = initialized_database(tmp_path)

    with closing(connect_database(path)) as conn, conn:
        conn.execute(
            "INSERT INTO users(id, name, email, password_hash, role) "
            "VALUES(?,?,?,?,?)",
            (44, "Engineer", "engineer@example.test", "hash", "engineer"),
        )

    with closing(connect_database(path)) as conn, conn:
        record_mutation_activity(
            conn,
            user_id=44,
            action="create_user",
            resource_type="user",
            result={
                "id": 55,
                "name": "Created",
                "password_hash": "secret",
                "session_token": "token",
                "reset_token": "reset",
            },
            request=None,
        )
        row = conn.execute(
            "SELECT username, resource_id, details FROM activity_logs"
        ).fetchone()

    details = json.loads(row["details"])
    assert row["username"] == "Engineer"
    assert row["resource_id"] == 55
    assert details == {"id": 55, "name": "Created"}


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

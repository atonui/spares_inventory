"""Connection and transaction behavior for the PostgreSQL boundary."""

import psycopg
import pytest
from psycopg.rows import dict_row


def test_postgres_connector_uses_dictionary_rows_and_timeout(monkeypatch):
    from backend import postgres_database

    captured = {}
    fake = object()

    def connect(dsn, **kwargs):
        captured.update(dsn=dsn, **kwargs)
        return fake

    monkeypatch.setattr(postgres_database.psycopg, "connect", connect)

    result = postgres_database.connect_postgres("postgresql://user:secret@db/inventory_test")

    assert result is fake
    assert captured["row_factory"] is dict_row
    assert captured["connect_timeout"] > 0


def test_postgres_readonly_connector_sets_session_readonly(monkeypatch):
    from backend import postgres_database

    class FakeConnection:
        def __init__(self):
            self.statements = []
            self.commits = 0

        def execute(self, statement):
            self.statements.append(statement)

        def commit(self):
            self.commits += 1

    connection = FakeConnection()
    monkeypatch.setattr(postgres_database.psycopg, "connect", lambda *args, **kwargs: connection)

    assert postgres_database.connect_postgres("postgresql://user@db/inventory_test", readonly=True) is connection
    assert connection.statements == ["SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"]
    assert connection.commits == 1


@pytest.mark.parametrize("fails", [False, True])
def test_postgres_transaction_commits_or_rolls_back(fails):
    from backend.postgres_database import postgres_transaction

    class FakeConnection:
        commits = 0
        rollbacks = 0

        def commit(self):
            self.commits += 1

        def rollback(self):
            self.rollbacks += 1

    connection = FakeConnection()
    if fails:
        with pytest.raises(ValueError, match="boom"):
            with postgres_transaction(connection) as yielded:
                assert yielded is connection
                raise ValueError("boom")
        assert connection.commits == 0
        assert connection.rollbacks == 1
    else:
        with postgres_transaction(connection) as yielded:
            assert yielded is connection
        assert connection.commits == 1
        assert connection.rollbacks == 0


def test_postgres_connection_error_does_not_expose_dsn(monkeypatch):
    from backend import postgres_database

    dsn = "postgresql://private-user:private-password@private-host/inventory_test"
    monkeypatch.setattr(
        postgres_database.psycopg,
        "connect",
        lambda *args, **kwargs: (_ for _ in ()).throw(psycopg.OperationalError(f"failed: {dsn}")),
    )

    with pytest.raises(RuntimeError) as error:
        postgres_database.connect_postgres(dsn)

    assert "private-password" not in str(error.value)
    assert "private-host" not in str(error.value)


def test_app_database_selects_postgres_connector_for_postgres_url(monkeypatch):
    import backend.app_database as app_database

    calls = []
    sentinel = object()
    monkeypatch.setattr(app_database, "connect_postgres", lambda dsn: calls.append(dsn) or sentinel)

    assert app_database.open_application_database("postgresql://user@db/inventory_test") is sentinel
    assert calls == ["postgresql://user@db/inventory_test"]


def test_postgres_connection_returns_dictionary_rows():
    from backend.postgres_database import connect_postgres
    from regression_tests.postgres_fixtures import postgres_test_dsn

    with connect_postgres(postgres_test_dsn()) as connection:
        row = connection.execute("SELECT 17 AS answer").fetchone()

    assert row["answer"] == 17


def test_postgres_transaction_commits_and_rolls_back():
    from backend.postgres_database import connect_postgres, postgres_transaction
    from regression_tests.postgres_fixtures import postgres_test_dsn

    with connect_postgres(postgres_test_dsn()) as connection:
        with postgres_transaction(connection):
            connection.execute("CREATE TEMP TABLE tx_probe (value integer PRIMARY KEY)")
            connection.execute("INSERT INTO tx_probe VALUES (1)")

        with pytest.raises(psycopg.errors.UniqueViolation):
            with postgres_transaction(connection):
                connection.execute("INSERT INTO tx_probe VALUES (2)")
                connection.execute("INSERT INTO tx_probe VALUES (2)")

        assert connection.execute("SELECT value FROM tx_probe ORDER BY value").fetchall() == [
            {"value": 1}
        ]


def test_postgres_readonly_connection_rejects_write():
    from backend.postgres_database import connect_postgres
    from regression_tests.postgres_fixtures import postgres_test_dsn

    with connect_postgres(postgres_test_dsn(), readonly=True) as connection:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute("CREATE TEMP TABLE readonly_probe (value integer)")

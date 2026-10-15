"""Safety checks for PostgreSQL integration-test connections."""

import os

import psycopg
import pytest

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_postgres_test_dsn_rejects_unset_environment(monkeypatch):
    from regression_tests.postgres_fixtures import postgres_test_dsn

    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="TEST_DATABASE_URL"):
        postgres_test_dsn()


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://tester:secret@localhost/inventory",
        "host=localhost dbname=inventory user=tester",
    ],
)
def test_postgres_test_dsn_rejects_database_without_test_suffix(monkeypatch, dsn):
    from regression_tests.postgres_fixtures import postgres_test_dsn

    monkeypatch.setenv("TEST_DATABASE_URL", dsn)

    with pytest.raises(ValueError, match="_test"):
        postgres_test_dsn()


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://tester:secret@localhost/inventory_test",
        "host=localhost dbname=inventory_test user=tester",
    ],
)
def test_postgres_test_dsn_accepts_disposable_database(monkeypatch, dsn):
    from regression_tests.postgres_fixtures import postgres_test_dsn

    monkeypatch.setenv("TEST_DATABASE_URL", dsn)

    assert postgres_test_dsn() == dsn


def test_postgres_connection_and_schema_fixture_use_disposable_database(postgres_schema):
    connection, schema_name = postgres_schema

    assert isinstance(connection, psycopg.Connection)
    assert schema_name.startswith("test_")
    assert connection.execute("SELECT current_schema() AS name").fetchone()["name"] == schema_name
    connection.execute("CREATE TABLE fixture_probe (id integer PRIMARY KEY)")
    connection.execute("INSERT INTO fixture_probe VALUES (1)")
    assert connection.execute("SELECT id FROM fixture_probe").fetchone()["id"] == 1

"""Platform-admin database work never creates implicit company context."""

import pytest
from fastapi import HTTPException

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture(autouse=True)
def migrated_platform_schema(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    apply_postgres_migrations(postgres_schema[0])


def test_platform_transaction_allows_platform_only_principal_without_tenant_context(postgres_schema):
    import psycopg

    from backend.services.platform_transactions import authenticated_platform_transaction
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    _org_id, user_id, token = seed_user(
        connection, platform_admin=True, membership=False
    )
    connection.commit()

    def get_connection():
        conn = psycopg.connect(
            __import__("os").environ["TEST_DATABASE_URL"],
            row_factory=psycopg.rows.dict_row,
            connect_timeout=5,
        )
        conn.execute("SET search_path TO \"" + schema + "\"")
        conn.commit()
        return conn

    with authenticated_platform_transaction(
        get_connection, session_token=token, expected_user_id=user_id
    ) as (platform_connection, principal):
        assert principal.is_platform_admin is True
        assert principal.organization_id is None
        assert platform_connection.execute(
            "SELECT current_setting('app.organization_id', true) AS value"
        ).fetchone()["value"] in (None, "")


def test_platform_transaction_rejects_non_platform_user(postgres_schema):
    import psycopg

    from backend.services.platform_transactions import authenticated_platform_transaction
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    _org_id, _user_id, token = seed_user(connection)
    connection.commit()

    def get_connection():
        conn = psycopg.connect(
            __import__("os").environ["TEST_DATABASE_URL"],
            row_factory=psycopg.rows.dict_row,
            connect_timeout=5,
        )
        conn.execute("SET search_path TO \"" + schema + "\"")
        conn.commit()
        return conn

    with pytest.raises(HTTPException) as error:
        with authenticated_platform_transaction(get_connection, session_token=token):
            pytest.fail("non-platform users must not enter a platform transaction")
    assert error.value.status_code == 403


def test_platform_only_principal_cannot_start_company_transaction(postgres_schema):
    import psycopg

    from backend.services.tenant_context import authenticated_tenant_transaction
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    _org_id, _user_id, token = seed_user(
        connection, platform_admin=True, membership=False
    )
    connection.commit()

    def get_connection():
        conn = psycopg.connect(
            __import__("os").environ["TEST_DATABASE_URL"],
            row_factory=psycopg.rows.dict_row,
            connect_timeout=5,
        )
        conn.execute("SET search_path TO \"" + schema + "\"")
        conn.commit()
        return conn

    with pytest.raises(HTTPException) as error:
        with authenticated_tenant_transaction(get_connection, session_token=token):
            pytest.fail("platform-only users must not enter a company transaction")
    assert error.value.status_code == 403

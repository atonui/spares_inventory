"""PostgreSQL integration checks for isolated web and mail database roles."""

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.errors import InsufficientPrivilege

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def mail_worker_role_db(postgres_schema):
    from cryptography.fernet import Fernet

    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.mail_payloads import encrypt_mail_payload

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    organization_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Worker Tenant',%s) RETURNING id",
        ("mail-worker-" + uuid4().hex,),
    ).fetchone()["id"]
    key = Fernet.generate_key().decode()
    for suffix, attempt_count in (("sent", 0), ("failed", 5)):
        admin.execute(
            """INSERT INTO mail_outbox
               (organization_id, message_type, recipient_email, encrypted_payload,
                idempotency_key, attempt_count)
               VALUES (%s, 'organization_invitation', %s, %s, %s, %s)""",
            (
                organization_id,
                f"{suffix}@example.test",
                encrypt_mail_payload({"invitation_url": "https://example.test/invite"}, key),
                f"worker-{suffix}-{uuid4().hex}",
                attempt_count,
            ),
        )
    role = "mail_worker_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    admin.execute(sql.SQL(
        "GRANT SELECT (id, organization_id, message_type, recipient_email, encrypted_payload, "
        "status, attempt_count, available_at, lease_expires_at, claim_token, "
        "provider_message_id, delivery_status, delivery_event_at) ON mail_outbox TO {}"
    ).format(sql.Identifier(role)))
    admin.execute(sql.SQL(
        "GRANT UPDATE (status, claim_token, lease_expires_at, attempt_count, updated_at, sent_at, "
        "last_error_code, available_at, provider_message_id, delivery_status, delivery_event_at, "
        "delivered_at, bounced_at, complained_at) ON mail_outbox TO {}"
    ).format(sql.Identifier(role)))
    admin.execute(sql.SQL(
        "GRANT SELECT, INSERT, UPDATE ON resend_webhook_events TO {}"
    ).format(sql.Identifier(role)))
    admin.commit()

    def connect_as_worker():
        connection = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        connection.commit()
        return connection

    yield {"admin": admin, "connect": connect_as_worker, "key": key}
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    admin.commit()


def test_worker_role_delivers_and_marks_sent_or_terminally_failed(mail_worker_role_db):
    from backend.mail_worker import claim_and_deliver_once

    class Response:
        status_code = 202

        def raise_for_status(self):
            return None

    class Transport:
        def __init__(self, fail=False):
            self.fail = fail

        def post(self, *_args, **_kwargs):
            if self.fail:
                raise RuntimeError("provider failure")
            return Response()

    connection = mail_worker_role_db["connect"]()
    try:
        assert claim_and_deliver_once(
            connection,
            encryption_key=mail_worker_role_db["key"],
            api_key="test-provider-key",
            from_address="SparesFlow <mail@example.test>",
            http_transport=Transport(),
        )
        assert claim_and_deliver_once(
            connection,
            encryption_key=mail_worker_role_db["key"],
            api_key="test-provider-key",
            from_address="SparesFlow <mail@example.test>",
            http_transport=Transport(fail=True),
        )
    finally:
        connection.close()

    statuses = mail_worker_role_db["admin"].execute(
        "SELECT status, attempt_count, last_error_code FROM mail_outbox ORDER BY recipient_email"
    ).fetchall()
    assert statuses == [
        {"status": "failed", "attempt_count": 6, "last_error_code": "provider_unavailable"},
        {"status": "sent", "attempt_count": 1, "last_error_code": None},
    ]


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM users",
        "SELECT * FROM sessions",
        "SELECT * FROM organization_invitations",
        "SELECT * FROM platform_admins",
        "SELECT * FROM inventory",
        "INSERT INTO mail_outbox (message_type, recipient_email, encrypted_payload, idempotency_key) "
        "VALUES ('organization_invitation', 'x@example.test', 'cipher', 'forbidden')",
        "DELETE FROM mail_outbox",
    ],
)
def test_worker_role_cannot_access_unrelated_tables_or_mutate_queue_membership(mail_worker_role_db, query):
    connection = mail_worker_role_db["connect"]()
    try:
        with pytest.raises(InsufficientPrivilege):
            connection.execute(query)
    finally:
        connection.close()

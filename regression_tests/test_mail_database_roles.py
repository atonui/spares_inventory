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


def test_runtime_role_reads_curated_invitation_view_without_outbox_read_access(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    organization_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('View Tenant',%s) RETURNING id",
        ("view-tenant-" + uuid4().hex,),
    ).fetchone()["id"]
    admin.execute(
        "INSERT INTO mail_outbox (organization_id,message_type,recipient_email,encrypted_payload,idempotency_key) "
        "VALUES (%s,'organization_invitation','view@example.test','cipher','view-" + uuid4().hex + "')",
        (organization_id,),
    )
    role = "platform_mail_view_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT ON platform_invitation_delivery_history TO {}").format(sql.Identifier(role)))
    admin.commit()
    conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
    try:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        conn.commit()
        rows = conn.execute("SELECT recipient_email, status FROM platform_invitation_delivery_history").fetchall()
        assert rows == [{"recipient_email": "view@example.test", "status": "pending"}]
        with pytest.raises(InsufficientPrivilege):
            conn.execute("SELECT recipient_email FROM mail_outbox")
    finally:
        conn.close()
        admin.rollback()
        admin.execute("RESET ROLE")
        admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.commit()


def test_runtime_role_reads_curated_invitation_history_without_invitation_table_access(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    organization_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Lifecycle View Tenant',%s) RETURNING id",
        ("lifecycle-view-" + uuid4().hex,),
    ).fetchone()["id"]
    inviter_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Inviter','x') RETURNING id",
        (f"inviter-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    accepted_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Accepted Owner','x') RETURNING id",
        (f"accepted-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    admin.execute(
        """INSERT INTO organization_invitations
           (organization_id,email_normalized,company_role,token_hash,invited_by,expires_at,accepted_at,accepted_by)
           VALUES (%s,'owner@example.test','owner','secret-invitation-token-hash',%s,
                   '2099-01-01T00:00:00Z','2026-11-14T10:00:00Z',%s)""",
        (organization_id, inviter_id, accepted_id),
    )
    role = "platform_invitation_history_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
    admin.execute(sql.SQL(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON platform_invitation_history TO {}"
    ).format(sql.Identifier(role)))
    admin.execute(sql.SQL(
        "REVOKE ALL PRIVILEGES ON TABLE platform_invitation_history FROM {}"
    ).format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT ON platform_invitation_history TO {}").format(sql.Identifier(role)))
    admin.commit()
    conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
    try:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        conn.commit()
        privileges = conn.execute(
            """SELECT has_table_privilege(current_user, 'platform_invitation_history', 'SELECT') AS can_select,
                      has_table_privilege(current_user, 'platform_invitation_history', 'INSERT') AS can_insert,
                      has_table_privilege(current_user, 'platform_invitation_history', 'UPDATE') AS can_update,
                      has_table_privilege(current_user, 'platform_invitation_history', 'DELETE') AS can_delete"""
        ).fetchone()
        assert privileges == {
            "can_select": True, "can_insert": False, "can_update": False, "can_delete": False,
        }
        rows = conn.execute(
            """SELECT recipient_email, company_role, accepted_at, accepted_account_name
               FROM platform_invitation_history"""
        ).fetchall()
        assert rows == [{
            "recipient_email": "owner@example.test", "company_role": "owner",
            "accepted_at": "2026-11-14T10:00:00Z", "accepted_account_name": "Accepted Owner",
        }]
        with pytest.raises(InsufficientPrivilege):
            conn.execute("SELECT token_hash FROM organization_invitations")
    finally:
        conn.close()
        admin.rollback()
        admin.execute("RESET ROLE")
        admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.commit()


def test_v0030_grants_support_inbox_to_the_worker_role_found_by_capability(postgres_schema, monkeypatch):
    """Production's roles are not named like the runbook's placeholders; v0030 must not depend on names."""
    from cryptography.fernet import Fernet

    from backend.postgres_migrations import registry
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.platform_support_inbox import store_inbound_message

    admin, schema = postgres_schema
    worker, web = "spares_mail_" + uuid4().hex[:8], "spares_web_" + uuid4().hex[:8]
    key = Fernet.generate_key().decode()
    message = {
        "from": "Customer <customer@example.test>", "to": ["support@sparestracker.com"],
        "subject": "Help", "text": "The scanner will not sync.", "created_at": "2026-11-21T13:46:12.106Z",
        "headers": {"Message-ID": "<first@example.test>"}, "attachments": [], "message_id": "<first@example.test>",
    }

    def save_as(role, event_id):
        connection = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        try:
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
            connection.commit()
            with connection.transaction():
                return store_inbound_message(connection, event_id=event_id, provider_email_id="re_received_1",
                                             message=message, support_address="support@sparestracker.com",
                                             encryption_key=key)
        finally:
            connection.close()

    migrations = registry.MIGRATIONS
    try:
        monkeypatch.setattr(registry, "MIGRATIONS", migrations[:29])
        apply_postgres_migrations(admin)
        for role in (worker, web):
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        # The runbook's mail_outbox grants: the worker claims mail, the web app enqueues it.
        admin.execute(sql.SQL("GRANT SELECT (id, status, claim_token) ON mail_outbox TO {}").format(sql.Identifier(worker)))
        admin.execute(sql.SQL("GRANT UPDATE (status, claim_token, lease_expires_at) ON mail_outbox TO {}").format(sql.Identifier(worker)))
        admin.execute(sql.SQL(
            "GRANT INSERT (organization_id, message_type, recipient_email, encrypted_payload, idempotency_key) ON mail_outbox TO {}"
        ).format(sql.Identifier(web)))
        admin.execute(sql.SQL("GRANT UPDATE (idempotency_key) ON mail_outbox TO {}").format(sql.Identifier(web)))
        admin.commit()

        with pytest.raises(InsufficientPrivilege):
            save_as(worker, "msg-before-fix")

        monkeypatch.setattr(registry, "MIGRATIONS", migrations)
        assert apply_postgres_migrations(admin).current_version == len(migrations)
        assert save_as(worker, "msg-after-fix") is True
        assert save_as(worker, "msg-retry") is False  # same provider email: no duplicate
        stored = admin.execute(
            "SELECT c.is_read, c.status, count(m.id) AS messages FROM platform_support_conversations c "
            "JOIN platform_support_messages m ON m.conversation_id=c.id GROUP BY c.id"
        ).fetchall()
        assert [dict(row) for row in stored] == [{"is_read": False, "status": "open", "messages": 1}]

        def can(role, table, privilege):
            return admin.execute("SELECT has_table_privilege(%s, %s, %s) AS ok", (role, table, privilege)).fetchone()["ok"]

        assert can(worker, "resend_webhook_events", "INSERT")
        assert not can(web, "platform_support_webhook_events", "INSERT")
        assert not can(web, "resend_webhook_events", "INSERT")
    finally:
        admin.rollback()
        for role in (worker, web):
            if admin.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        admin.commit()

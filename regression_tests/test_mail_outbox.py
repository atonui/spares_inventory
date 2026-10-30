"""Transactional outbox leases, retries, and idempotency."""

from datetime import timedelta
from uuid import uuid4

import psycopg
import pytest

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def migrated_outbox(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)
    organization_id = connection.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Outbox Tenant',%s) RETURNING id",
        ("outbox-" + uuid4().hex,),
    ).fetchone()["id"]
    connection.commit()
    return connection, schema, organization_id


def _enqueue(connection, organization_id, suffix="a"):
    from backend.services.mail_outbox import enqueue_mail

    return enqueue_mail(
        connection,
        organization_id=organization_id,
        message_type="organization_invitation",
        recipient_email="invite@example.test",
        encrypted_payload="ciphertext-" + suffix,
        idempotency_key="invite-" + suffix,
    )


def test_enqueue_and_claim_mail_preserves_payload_ciphertext(migrated_outbox):
    from backend.services.mail_outbox import claim_pending_mail
    from backend.temporal import utc_now

    connection, _schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id)
    with connection.transaction():
        message = claim_pending_mail(connection, now=utc_now())
    assert message["encrypted_payload"] == "ciphertext-a"
    assert message["organization_id"] == organization_id
    assert message["status"] == "claimed"


def test_concurrent_workers_claim_distinct_messages(migrated_outbox):
    from backend.services.mail_outbox import claim_pending_mail
    from backend.temporal import utc_now

    connection, schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id, "a")
    _enqueue(connection, organization_id, "b")
    connection.commit()
    second = psycopg.connect(
        __import__("os").environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row
    )
    second.execute('SET search_path TO "' + schema + '"')
    second.commit()
    try:
        with connection.transaction():
            first = claim_pending_mail(connection, now=utc_now())
            with second.transaction():
                another = claim_pending_mail(second, now=utc_now())
            assert first["id"] != another["id"]
    finally:
        second.close()


def test_expired_claim_can_be_reclaimed(migrated_outbox):
    from backend.services.mail_outbox import claim_pending_mail
    from backend.temporal import utc_now

    connection, _schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id)
    now = utc_now()
    with connection.transaction():
        first = claim_pending_mail(connection, now=now, lease_seconds=1)
    later = now + timedelta(seconds=2)
    with connection.transaction():
        second = claim_pending_mail(connection, now=later, lease_seconds=1)
    assert second["id"] == first["id"]
    assert second["claim_token"] != first["claim_token"]


def test_provider_failure_retries_then_marks_terminal_after_six_attempts(migrated_outbox):
    from backend.services.mail_outbox import claim_pending_mail, mark_mail_failed
    from backend.temporal import utc_now

    connection, _schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id)
    now = utc_now()
    delays = (60, 300, 1200, 3600, 14400)
    for attempt in range(1, 7):
        with connection.transaction():
            message = claim_pending_mail(connection, now=now)
            assert message is not None
            retry_at = now + timedelta(seconds=delays[attempt - 1]) if attempt <= 5 else now
            terminal = mark_mail_failed(
                connection,
                mail_id=message["id"],
                claim_token=message["claim_token"],
                retry_at=retry_at,
                error_code="resend_unavailable",
            )
        assert terminal is (attempt == 6)
        if attempt <= 5:
            now = retry_at
    row = connection.execute(
        "SELECT status,attempt_count,last_error_code FROM mail_outbox"
    ).fetchone()
    assert row == {"status": "failed", "attempt_count": 6, "last_error_code": "resend_unavailable"}


def test_resend_events_are_idempotent_and_update_delivery_status(migrated_outbox):
    from backend.services.mail_outbox import (
        claim_pending_mail, mark_mail_sent, record_resend_webhook_event,
    )
    from backend.temporal import serialize_instant, utc_now

    connection, _schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id)
    with connection.transaction():
        message = claim_pending_mail(connection, now=utc_now())
        mark_mail_sent(
            connection, mail_id=message["id"], claim_token=str(message["claim_token"]),
            provider_message_id="resend-message-001",
        )
        created = record_resend_webhook_event(
            connection, event_id="evt-delivered-001",
            provider_message_id="resend-message-001", event_type="email.delivered",
            occurred_at=serialize_instant(utc_now()),
        )
        duplicate = record_resend_webhook_event(
            connection, event_id="evt-delivered-001",
            provider_message_id="resend-message-001", event_type="email.delivered",
            occurred_at=serialize_instant(utc_now()),
        )

    row = connection.execute(
        "SELECT delivery_status, delivered_at FROM mail_outbox WHERE id = %s",
        (message["id"],),
    ).fetchone()
    event_count = connection.execute(
        "SELECT count(*) AS count FROM resend_webhook_events"
    ).fetchone()["count"]
    assert created is True
    assert duplicate is False
    assert row["delivery_status"] == "delivered"
    assert row["delivered_at"] is not None
    assert event_count == 1


def test_resend_event_received_before_provider_id_is_applied_when_send_completes(migrated_outbox):
    from backend.services.mail_outbox import (
        apply_pending_resend_events, claim_pending_mail, mark_mail_sent,
        record_resend_webhook_event,
    )
    from backend.temporal import serialize_instant, utc_now

    connection, _schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id)
    event_time = serialize_instant(utc_now())
    with connection.transaction():
        record_resend_webhook_event(
            connection, event_id="evt-race-001",
            provider_message_id="resend-message-race", event_type="email.bounced",
            occurred_at=event_time,
        )
    pending = connection.execute(
        "SELECT processed_at FROM resend_webhook_events WHERE event_id = %s",
        ("evt-race-001",),
    ).fetchone()
    assert pending["processed_at"] is None

    with connection.transaction():
        message = claim_pending_mail(connection, now=utc_now())
        mark_mail_sent(
            connection, mail_id=message["id"], claim_token=str(message["claim_token"]),
            provider_message_id="resend-message-race",
        )
    row = connection.execute(
        "SELECT delivery_status, bounced_at FROM mail_outbox WHERE id = %s",
        (message["id"],),
    ).fetchone()
    pending = connection.execute(
        "SELECT processed_at FROM resend_webhook_events WHERE event_id = %s",
        ("evt-race-001",),
    ).fetchone()
    assert row["delivery_status"] == "bounced"
    assert row["bounced_at"] == event_time
    assert pending["processed_at"] is not None


def test_stale_resend_event_does_not_downgrade_status_and_is_processed(migrated_outbox):
    from backend.services.mail_outbox import (
        claim_pending_mail, mark_mail_sent, record_resend_webhook_event,
    )
    from backend.temporal import serialize_instant, utc_now

    connection, _schema, organization_id = migrated_outbox
    _enqueue(connection, organization_id)
    now = utc_now()
    with connection.transaction():
        message = claim_pending_mail(connection, now=now)
        mark_mail_sent(
            connection, mail_id=message["id"], claim_token=str(message["claim_token"]),
            provider_message_id="resend-message-ordering",
        )
        record_resend_webhook_event(
            connection, event_id="evt-delivered-newer",
            provider_message_id="resend-message-ordering", event_type="email.delivered",
            occurred_at=serialize_instant(now + timedelta(seconds=2)),
        )
        record_resend_webhook_event(
            connection, event_id="evt-sent-older",
            provider_message_id="resend-message-ordering", event_type="email.sent",
            occurred_at=serialize_instant(now + timedelta(seconds=1)),
        )

    status = connection.execute(
        "SELECT delivery_status FROM mail_outbox WHERE id = %s", (message["id"],)
    ).fetchone()["delivery_status"]
    processed_events = connection.execute(
        "SELECT count(*) AS count FROM resend_webhook_events WHERE processed_at IS NOT NULL"
    ).fetchone()["count"]
    assert status == "delivered"
    assert processed_events == 2

"""Store activity notices use the active assigned user and encrypted outbox."""

from uuid import uuid4

import pytest

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def notification_store(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    conn, schema = postgres_schema
    apply_postgres_migrations(conn)
    organization_id = conn.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Mail Tenant', %s) RETURNING id",
        ("mail-notice-" + uuid4().hex,),
    ).fetchone()["id"]
    actor_id = conn.execute(
        "INSERT INTO users(email, name, password_hash) VALUES (%s, 'Actor', 'unused') RETURNING id",
        ("actor-" + uuid4().hex + "@example.test",),
    ).fetchone()["id"]
    recipient_id = conn.execute(
        "INSERT INTO users(email, name, password_hash) VALUES (%s, 'Store Assignee', 'unused') RETURNING id",
        ("assignee-" + uuid4().hex + "@example.test",),
    ).fetchone()["id"]
    conn.execute(
        "INSERT INTO organization_memberships(organization_id, user_id, company_role) "
        "VALUES (%s, %s, 'engineer'), (%s, %s, 'engineer')",
        (organization_id, actor_id, organization_id, recipient_id),
    )
    store_id = conn.execute(
        "INSERT INTO stores(organization_id, name, type, assigned_user_id) "
        "VALUES (%s, 'Nairobi Main', 'car', %s) RETURNING id",
        (organization_id, recipient_id),
    ).fetchone()["id"]
    inventory_id = conn.execute(
        "INSERT INTO parts(organization_id, part_number, description) "
        "VALUES (%s, 'VALVE-1', 'Valve') RETURNING id",
        (organization_id,),
    ).fetchone()["id"]
    item_id = conn.execute(
        "INSERT INTO inventory(organization_id, store_id, part_id, quantity) "
        "VALUES (%s, %s, %s, 4) RETURNING id",
        (organization_id, store_id, inventory_id),
    ).fetchone()["id"]
    conn.commit()
    return conn, schema, organization_id, actor_id, recipient_id, store_id, item_id


def test_stock_added_notice_targets_store_assignee_and_encrypts_details(notification_store):
    from cryptography.fernet import Fernet

    from backend.services.mail_payloads import decrypt_mail_payload
    from backend.services.store_email_notifications import enqueue_store_notification

    conn, _schema, organization_id, actor_id, recipient_id, store_id, inventory_id = notification_store
    encryption_key = Fernet.generate_key().decode()
    with conn.transaction():
        conn.execute(
            "SELECT set_config('app.organization_id', %s, true)", (str(organization_id),)
        )
        queued = enqueue_store_notification(
            conn,
            event_type="stock_added",
            organization_id=organization_id,
            store_id=store_id,
            actor_user_id=actor_id,
            event_id=71,
            payload={
                "store_id": store_id,
                "inventory_id": inventory_id,
                "store_name": "Nairobi Main",
                "part_number": "VALVE-1",
                "quantity": 4,
            },
            frontend_url="https://www.sparestracker.com/static",
            encryption_key=encryption_key,
        )

    row = conn.execute(
        "SELECT organization_id, message_type, recipient_email, encrypted_payload "
        "FROM mail_outbox WHERE idempotency_key = %s",
        (f"store-notice-stock_added-71-{recipient_id}",),
    ).fetchone()
    payload = decrypt_mail_payload(row["encrypted_payload"], encryption_key)
    assert queued is True
    assert row["organization_id"] == organization_id
    assert row["message_type"] == "stock_added_notice"
    assert row["recipient_email"].startswith("assignee-")
    assert "Nairobi Main" not in row["encrypted_payload"]
    assert payload["inventory_url"] == (
        f"https://www.sparestracker.com/static/index.html?store_id={store_id}&inventory_id={inventory_id}"
    )


def test_store_activity_does_not_email_actor_or_inactive_assignee(notification_store):
    from cryptography.fernet import Fernet

    from backend.services.store_email_notifications import enqueue_store_notification

    conn, _schema, organization_id, actor_id, recipient_id, store_id, inventory_id = notification_store
    conn.execute(
        "UPDATE stores SET assigned_user_id = %s WHERE id = %s", (actor_id, store_id)
    )
    conn.commit()
    encryption_key = Fernet.generate_key().decode()
    with conn.transaction():
        conn.execute(
            "SELECT set_config('app.organization_id', %s, true)", (str(organization_id),)
        )
        queued = enqueue_store_notification(
            conn,
            event_type="stock_added",
            organization_id=organization_id,
            store_id=store_id,
            actor_user_id=actor_id,
            event_id=72,
            payload={
                "store_id": store_id,
                "inventory_id": inventory_id,
                "store_name": "Nairobi Main",
                "part_number": "VALVE-1",
                "quantity": 4,
            },
            frontend_url="https://www.sparestracker.com/static",
            encryption_key=encryption_key,
        )

    count = conn.execute(
        "SELECT count(*) AS count FROM mail_outbox WHERE idempotency_key LIKE %s",
        ("store-notice-stock_added-72-%",),
    ).fetchone()["count"]
    assert queued is False
    assert count == 0

    conn.execute(
        "UPDATE stores SET assigned_user_id = %s WHERE id = %s", (recipient_id, store_id)
    )
    conn.execute(
        "UPDATE organization_memberships SET is_active = FALSE WHERE user_id = %s", (recipient_id,)
    )
    conn.commit()
    with conn.transaction():
        conn.execute(
            "SELECT set_config('app.organization_id', %s, true)", (str(organization_id),)
        )
        queued = enqueue_store_notification(
            conn,
            event_type="stock_added",
            organization_id=organization_id,
            store_id=store_id,
            actor_user_id=actor_id,
            event_id=73,
            payload={
                "store_id": store_id,
                "inventory_id": inventory_id,
                "store_name": "Nairobi Main",
                "part_number": "VALVE-1",
                "quantity": 4,
            },
            frontend_url="https://www.sparestracker.com/static",
            encryption_key=encryption_key,
        )
    assert queued is False

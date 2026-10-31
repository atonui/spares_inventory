"""Single-use, email-bound tenant invitations and atomic provisioning."""

from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def invitation_db(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    conn, _schema = postgres_schema
    apply_postgres_migrations(conn)
    org_id = conn.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Invite Tenant',%s) RETURNING id",
        ("invite-" + uuid4().hex,),
    ).fetchone()["id"]
    actor_id = conn.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('actor@example.test','Actor','hash') RETURNING id"
    ).fetchone()["id"]
    conn.execute("INSERT INTO organization_settings(organization_id) VALUES (%s)", (org_id,))
    conn.commit()
    return conn, org_id, actor_id, Fernet.generate_key().decode()


def _create(conn, org_id, actor_id, key, email="new@example.test", role="engineer"):
    from backend.services.invitations import create_invitation

    with conn.transaction():
        return create_invitation(
            conn, organization_id=org_id, invited_by=actor_id, email=email,
            company_role=role, frontend_url="https://inventory.example.test",
            encryption_key=key,
        )


def _token_from_outbox(conn, key):
    from backend.services.mail_payloads import decrypt_mail_payload

    row = conn.execute("SELECT encrypted_payload FROM mail_outbox ORDER BY id DESC LIMIT 1").fetchone()
    payload = decrypt_mail_payload(row["encrypted_payload"], key)
    return parse_qs(urlsplit(payload["invitation_url"]).query)["token"][0]


def test_invitation_stores_only_hash_and_enqueues_encrypted_link(invitation_db):
    conn, org_id, actor_id, key = invitation_db
    invitation = _create(conn, org_id, actor_id, key, "  Person@Example.Test ")
    token = _token_from_outbox(conn, key)
    stored = conn.execute(
        "SELECT token_hash, email_normalized FROM organization_invitations WHERE id=%s",
        (invitation["id"],),
    ).fetchone()
    queued = conn.execute("SELECT encrypted_payload FROM mail_outbox").fetchone()["encrypted_payload"]
    assert stored["email_normalized"] == "person@example.test"
    assert stored["token_hash"] != token
    assert token not in stored["token_hash"]
    assert token not in queued
    assert "person@example.test" == invitation["email"]


def test_invitation_acceptance_is_single_use_and_email_bound(invitation_db):
    from backend.services.invitations import accept_invitation
    from backend.services.tenant_context import set_tenant_context

    conn, org_id, actor_id, key = invitation_db
    invitation = _create(conn, org_id, actor_id, key, role="manager")
    token = _token_from_outbox(conn, key)
    with conn.transaction():
        set_tenant_context(conn, org_id)
        result = accept_invitation(
            conn, organization_id=org_id, token=token, name="New Person", password="long-secret",
            password_hash=lambda value: "hash:" + value,
            password_verify=lambda plain, hashed: hashed == "hash:" + plain,
        )
    assert result["organization_id"] == str(org_id)
    member = conn.execute(
        "SELECT company_role FROM organization_memberships WHERE user_id=%s", (result["user_id"],)
    ).fetchone()
    assert member["company_role"] == "manager"
    with pytest.raises(HTTPException) as error:
        with conn.transaction():
            set_tenant_context(conn, org_id)
            accept_invitation(
                conn, organization_id=org_id, token=token, name="Other", password="long-secret",
                password_hash=lambda value: value, password_verify=lambda *_: True,
            )
    assert error.value.detail == "Invitation is invalid or expired"


def test_invitation_wrong_organization_scope_uses_generic_error(invitation_db):
    from backend.services.invitations import accept_invitation
    from backend.services.tenant_context import set_tenant_context

    conn, org_id, actor_id, key = invitation_db
    _create(conn, org_id, actor_id, key)
    token = _token_from_outbox(conn, key)
    other_org = conn.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Other Tenant',%s) RETURNING id",
        ("other-" + uuid4().hex,),
    ).fetchone()["id"]
    with pytest.raises(HTTPException) as error:
        with conn.transaction():
            set_tenant_context(conn, other_org)
            accept_invitation(
                conn, organization_id=other_org, token=token, name="Nope", password="long-secret",
                password_hash=lambda value: value, password_verify=lambda *_: True,
            )
    assert error.value.status_code == 400
    assert error.value.detail == "Invitation is invalid or expired"


def test_existing_identity_must_prove_password(invitation_db):
    from backend.services.invitations import accept_invitation
    from backend.services.tenant_context import set_tenant_context

    conn, org_id, actor_id, key = invitation_db
    existing = conn.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('new@example.test','Existing','stored') RETURNING id"
    ).fetchone()["id"]
    _create(conn, org_id, actor_id, key)
    token = _token_from_outbox(conn, key)
    with pytest.raises(HTTPException):
        with conn.transaction():
            set_tenant_context(conn, org_id)
            accept_invitation(
                conn, organization_id=org_id, token=token, name="Existing", password="wrong",
                password_hash=lambda value: value, password_verify=lambda plain, hashed: False,
            )
    assert conn.execute(
        "SELECT 1 FROM organization_memberships WHERE user_id=%s", (existing,)
    ).fetchone() is None


def test_platform_admin_identity_cannot_be_invited_to_a_tenant(invitation_db):
    conn, org_id, actor_id, key = invitation_db
    platform_id = conn.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('platform-invite@example.test','Platform','hash') RETURNING id"
    ).fetchone()["id"]
    conn.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (platform_id,))

    with pytest.raises(HTTPException) as error:
        _create(conn, org_id, actor_id, key, email="platform-invite@example.test")

    assert error.value.status_code == 409
    assert "platform administrator" in error.value.detail.lower()


def test_pending_invitation_cannot_create_membership_for_platform_admin(invitation_db):
    from backend.services.invitations import accept_invitation
    from backend.services.tenant_context import set_tenant_context

    conn, org_id, actor_id, key = invitation_db
    _create(conn, org_id, actor_id, key, email="late-platform@example.test")
    token = _token_from_outbox(conn, key)
    platform_id = conn.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('late-platform@example.test','Platform','hash:password') RETURNING id"
    ).fetchone()["id"]
    conn.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (platform_id,))

    with pytest.raises(HTTPException) as error:
        with conn.transaction():
            set_tenant_context(conn, org_id)
            accept_invitation(
                conn, organization_id=org_id, token=token, name="Platform", password="password",
                password_hash=lambda value: "hash:" + value,
                password_verify=lambda plain, hashed: hashed == "hash:" + plain,
            )

    assert error.value.detail == "Invitation is invalid or expired"
    assert conn.execute(
        "SELECT 1 FROM organization_memberships WHERE user_id=%s", (platform_id,)
    ).fetchone() is None


def test_platform_provisioning_rolls_back_if_mail_cannot_be_encrypted(invitation_db):
    from backend.services.invitations import create_organization_with_owner_invitation

    conn, _org_id, actor_id, _key = invitation_db
    slug = "rollback-" + uuid4().hex
    with pytest.raises(ValueError):
        with conn.transaction():
            create_organization_with_owner_invitation(
                conn, name="Rollback Tenant", slug=slug, owner_email="owner@example.test",
                actor_user_id=actor_id, frontend_url="https://inventory.example.test",
                encryption_key="invalid",
            )
    assert conn.execute("SELECT 1 FROM organizations WHERE slug=%s", (slug,)).fetchone() is None

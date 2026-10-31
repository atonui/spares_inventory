"""PostgreSQL route integration tests for verified email changes."""

from datetime import timedelta
import os
import logging
from uuid import uuid4

import psycopg
import pytest
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.testclient import TestClient
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


class NoLimiter:
    def limit(self, _rule):
        return lambda function: function


@pytest.fixture
def email_change_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.auth import create_auth_router
    from backend.routes.users import create_users_router
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.session_credentials import get_request_credential, hash_session_credential
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.authenticated_account_transactions import authenticated_account_transaction
    from backend.temporal import serialize_instant, utc_now

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    organization_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Email Tenant',%s) RETURNING id",
        ("email-change-" + uuid4().hex,),
    ).fetchone()["id"]
    identities = {}
    for email, role in (("first@example.com", "owner"), ("second@example.com", "engineer"),
                        ("third@example.com", "admin"), ("fourth@example.com", "admin2")):
        user_id = admin.execute(
            "INSERT INTO users(email,name,password_hash) VALUES (%s,%s,'hash') RETURNING id",
            (email, role),
        ).fetchone()["id"]
        admin.execute(
            "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
            (organization_id, user_id, "admin" if role == "admin2" else role),
        )
        token = "email-session-" + uuid4().hex
        admin.execute(
            "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
            (user_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
        )
        identities[role] = (user_id, token)
    platform_user_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('platform@example.com','Platform','hash') RETURNING id"
    ).fetchone()["id"]
    admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (platform_user_id,))
    platform_token = "email-session-" + uuid4().hex
    admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (platform_user_id, hash_session_credential(platform_token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    identities["platform"] = (platform_user_id, platform_token)
    admin.commit()

    runtime_role = "email_change_runtime_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(runtime_role)
    ))
    for table in ("users", "sessions", "organization_memberships", "organizations", "platform_admins"):
        admin.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(
            sql.Identifier(table), sql.Identifier(runtime_role)
        ))
    admin.execute(sql.SQL("GRANT UPDATE (email) ON users TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT UPDATE (company_role, is_active) ON organization_memberships TO {}").format(
        sql.Identifier(runtime_role)
    ))
    admin.execute(sql.SQL(
        "GRANT SELECT (id, user_id, proposed_email, token_hash, delivery_suppressed, created_at, expires_at, consumed_at, canceled_at), "
        "INSERT (user_id, proposed_email, token_hash, delivery_suppressed, expires_at), "
        "UPDATE (consumed_at, canceled_at) ON email_change_requests TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT INSERT (organization_id, message_type, recipient_email, encrypted_payload, idempotency_key), "
        "SELECT (id, idempotency_key), UPDATE (idempotency_key) ON mail_outbox TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT ON platform_mail_outbox_counts TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE email_change_requests_id_seq, mail_outbox_id_seq TO {}").format(
        sql.Identifier(runtime_role)
    ))
    admin.commit()

    def get_connection():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        conn.commit()
        return conn

    principals = {
        role: AuthenticatedPrincipal(user_id, organization_id, "admin" if role == "admin2" else role, False)
        for role, (user_id, _token) in identities.items()
    }
    principals["platform"] = AuthenticatedPrincipal(platform_user_id, None, None, True)

    def current_user(request: Request):
        credential = get_request_credential(request)
        for role, (_user_id, token) in identities.items():
            if credential.value == token:
                return principals[role]
        raise HTTPException(status_code=401, detail="Not authenticated")

    async def csrf(request: Request, _user=Depends(current_user), x_csrf_token: str | None = Header(None)):
        if get_request_credential(request).transport == "bearer":
            return True
        if x_csrf_token != "csrf-fixture":
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
        return True

    async def public_csrf(x_csrf_token: str | None = Header(None)):
        if x_csrf_token != "csrf-fixture":
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
        return True

    key = Fernet.generate_key().decode("ascii")
    activity_records = []
    router = create_auth_router(
        get_connection=get_connection,
        authenticated_writer=lambda principal, token: authenticated_write_transaction(
            get_connection, user_id=principal, session_token=token
        ),
        authenticated_account_writer=lambda principal, token: authenticated_account_transaction(
            get_connection, principal_or_user=principal, session_token=token
        ),
        stock_writer=lambda: None,
        current_user=current_user,
        csrf_dependency=public_csrf,
        authenticated_csrf_dependency=csrf,
        csrf_token_factory=lambda: "csrf-fixture",
        password_hash=lambda value: "hash:" + value,
        password_verify=lambda plain, hashed: hashed == "hash:" + plain,
        security_config=lambda: {},
        reset_email=lambda *_args: None,
        queue_reset_email=lambda *_args: None,
        activity_log=lambda **_kwargs: None,
        endpoint_log=lambda **_kwargs: lambda function: function,
        mutation_activity=lambda *args: activity_records.append(args),
        limiter=NoLimiter(),
        logger=logging.getLogger("email-change-test"),
        cookie_secure=lambda: True,
        native_refresh_encryption_key=key,
        mail_payload_encryption_key=key,
        frontend_url="https://inventory.example.test",
    )
    app = FastAPI()
    app.include_router(router)
    app.include_router(create_users_router(
        get_connection=get_connection,
        authenticated_writer=lambda principal, token: authenticated_write_transaction(
            get_connection, user_id=principal, session_token=token
        ),
        current_user=current_user,
        csrf_dependency=csrf,
        user_management_guard=lambda *_args, **_kwargs: None,
        archive_admin_guard=lambda *_args, **_kwargs: None,
        archive_service=lambda *_args, **_kwargs: None,
        password_hash=lambda value: "hash:" + value,
        endpoint_log=lambda **_kwargs: lambda function: function,
        mutation_activity=lambda *args: activity_records.append(args),
        mail_payload_encryption_key=key,
        frontend_url="https://inventory.example.test",
        limiter=NoLimiter(),
    ))
    client = TestClient(app)

    yield {
        "admin": admin,
        "client": client,
        "identities": identities,
        "principals": principals,
        "key": key,
        "runtime_connection": get_connection,
        "runtime_role": runtime_role,
        "activity_records": activity_records,
    }
    client.close()
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
    admin.commit()


def _cookie(api, role="owner"):
    return {"session_token": api["identities"][role][1]}


def _request_member_change(api, target_role="engineer", email="new-member@example.com", actor="owner"):
    target_id = api["identities"][target_role][0]
    return api["client"].post(
        f"/api/users/{target_id}/email-change-requests",
        json={"email": email},
        cookies=_cookie(api, actor),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )


def test_saas_users_cannot_start_read_or_cancel_self_service_email_changes(email_change_api):
    api = email_change_api
    client = api["client"]
    headers = {"X-CSRF-Token": "csrf-fixture"}
    assert client.post("/api/profile/email-change-requests", json={"email": "new@example.com"},
                       cookies=_cookie(api, "engineer"), headers=headers).status_code == 403
    assert client.get("/api/profile/email-change-request", cookies=_cookie(api, "engineer")).status_code == 403
    assert client.delete("/api/profile/email-change-request", cookies=_cookie(api, "engineer"),
                         headers=headers).status_code == 403
    assert api["admin"].execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 0


def test_owner_requests_email_change_for_member_and_status_is_masked(email_change_api):
    api = email_change_api
    response = _request_member_change(api)
    target_id = api["identities"]["engineer"][0]
    assert response.status_code == 202, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["success"] is True
    assert "token" not in response.text.lower()
    assert api["admin"].execute("SELECT email FROM users WHERE id=%s", (target_id,)).fetchone()["email"] == "second@example.com"
    status = api["client"].get(f"/api/users/{target_id}/email-change-request", cookies=_cookie(api))
    assert status.status_code == 200
    assert status.json()["status"] == "pending"
    assert status.json()["proposed_email"] == "n***@example.com"
    assert status.headers["cache-control"] == "no-store"
    assert api["admin"].execute(
        "SELECT recipient_email FROM mail_outbox WHERE message_type='email_change_verification'"
    ).fetchone()["recipient_email"] == "new-member@example.com"


def test_company_member_cannot_request_email_change_for_self_or_others(email_change_api):
    api = email_change_api
    own = api["client"].post(
        f"/api/users/{api['identities']['engineer'][0]}/email-change-requests",
        json={"email": "new-member@example.com"}, cookies=_cookie(api, "engineer"),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    other = api["client"].post(
        f"/api/users/{api['identities']['owner'][0]}/email-change-requests",
        json={"email": "new-member@example.com"}, cookies=_cookie(api, "engineer"),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert own.status_code == 403
    assert other.status_code == 403


def test_owner_email_must_be_changed_by_sparestracker_support(email_change_api):
    api = email_change_api
    response = api["client"].post(
        f"/api/users/{api['identities']['owner'][0]}/email-change-requests",
        json={"email": "owner-new@example.com"}, cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 403
    assert "support" in response.json()["detail"].lower()
    assert api["admin"].execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 0


def test_only_owner_can_change_an_administrators_email(email_change_api):
    api = email_change_api
    admin_id = api["identities"]["admin"][0]
    other_admin_id = api["identities"]["admin2"][0]
    owner_change = api["client"].post(
        f"/api/users/{admin_id}/email-change-requests", json={"email": "new-admin@example.com"},
        cookies=_cookie(api), headers={"X-CSRF-Token": "csrf-fixture"},
    )
    admin_change = api["client"].post(
        f"/api/users/{other_admin_id}/email-change-requests", json={"email": "other@example.com"},
        cookies=_cookie(api, "admin"), headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert owner_change.status_code == 202
    assert admin_change.status_code == 403


def test_pending_member_email_change_can_be_canceled_by_company_admin(email_change_api):
    api = email_change_api
    target_id = api["identities"]["engineer"][0]
    _request_member_change(api)
    response = api["client"].delete(
        f"/api/users/{target_id}/email-change-request", cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True
    status = api["client"].get(f"/api/users/{target_id}/email-change-request", cookies=_cookie(api))
    assert status.json() == {"status": "none"}


def test_public_confirmation_updates_member_and_notifies_old_address(email_change_api):
    from urllib.parse import parse_qs, urlsplit
    from backend.services.mail_payloads import decrypt_mail_payload

    api = email_change_api
    target_id = api["identities"]["engineer"][0]
    assert _request_member_change(api, email="verified@example.com").status_code == 202
    queued = api["admin"].execute(
        "SELECT encrypted_payload FROM mail_outbox WHERE message_type='email_change_verification'"
    ).fetchone()
    payload = decrypt_mail_payload(queued["encrypted_payload"], api["key"])
    token = parse_qs(urlsplit(payload["verification_url"]).fragment)["token"][0]
    assert api["client"].get("/api/auth/email-change/confirm").status_code == 405
    response = api["client"].post("/api/auth/email-change/confirm", json={"token": token})
    assert response.status_code == 403
    response = api["client"].post("/api/auth/email-change/confirm", json={"token": token},
                                   headers={"X-CSRF-Token": "csrf-fixture"})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert api["admin"].execute("SELECT email FROM users WHERE id=%s", (target_id,)).fetchone()["email"] == "verified@example.com"
    notices = api["admin"].execute(
        "SELECT message_type, recipient_email, encrypted_payload FROM mail_outbox ORDER BY id"
    ).fetchall()
    assert [row["message_type"] for row in notices] == ["email_change_verification", "email_changed_notice"]
    assert notices[1]["recipient_email"] == "second@example.com"
    assert token not in notices[1]["encrypted_payload"]
    confirm_audit = next(record for record in api["activity_records"] if record[2] == "confirm_email_change")
    assert confirm_audit[1].user_id == target_id
    assert confirm_audit[4] == {"id": target_id}
    replay = api["client"].post("/api/auth/email-change/confirm", json={"token": token},
                                headers={"X-CSRF-Token": "csrf-fixture"})
    assert replay.status_code == 400


def test_malformed_confirmation_never_echoes_token_material(email_change_api):
    response = email_change_api["client"].post(
        "/api/auth/email-change/confirm", json={"token": {"secret": "should-not-be-echoed"}},
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "The confirmation link is invalid or expired."}
    assert "should-not-be-echoed" not in response.text


def test_native_self_service_email_change_routes_are_removed(email_change_api):
    api = email_change_api
    client = api["client"]
    cookie = client.post("/api/v1/me/email-change-requests", json={"email": "native@example.com"},
                         cookies=_cookie(api), headers={"X-CSRF-Token": "csrf-fixture"})
    bearer = client.post("/api/v1/me/email-change-requests", json={"email": "native@example.com"},
                         headers={"Authorization": "Bearer " + api["identities"]["owner"][1]})
    assert cookie.status_code == 404
    assert bearer.status_code == 404


def test_profile_email_update_cannot_bypass_admin_flow_in_saas(email_change_api):
    api = email_change_api
    response = api["client"].put(
        "/api/profile", json={"email": "bypass@example.com"}, cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 403
    assert api["admin"].execute(
        "SELECT email FROM users WHERE id=%s", (api["identities"]["owner"][0],)
    ).fetchone()["email"] == "first@example.com"


def test_platform_admin_cannot_self_serve_email_change(email_change_api):
    api = email_change_api
    response = api["client"].post(
        "/api/profile/email-change-requests", json={"email": "platform-new@example.com"},
        cookies=_cookie(api, "platform"), headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 403
    assert api["admin"].execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 0

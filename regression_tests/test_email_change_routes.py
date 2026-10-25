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
    for email, role in (("first@example.com", "owner"), ("second@example.com", "engineer")):
        user_id = admin.execute(
            "INSERT INTO users(email,name,password_hash) VALUES (%s,%s,'hash') RETURNING id",
            (email, role),
        ).fetchone()["id"]
        admin.execute(
            "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
            (organization_id, user_id, role),
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
        role: AuthenticatedPrincipal(user_id, organization_id, role, False)
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

    key = Fernet.generate_key().decode("ascii")
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
        csrf_dependency=csrf,
        authenticated_csrf_dependency=csrf,
        csrf_token_factory=lambda: "csrf-fixture",
        password_hash=lambda value: "hash:" + value,
        password_verify=lambda plain, hashed: hashed == "hash:" + plain,
        security_config=lambda: {},
        reset_email=lambda *_args: None,
        queue_reset_email=lambda *_args: None,
        activity_log=lambda **_kwargs: None,
        endpoint_log=lambda **_kwargs: lambda function: function,
        mutation_activity=lambda *_args: None,
        limiter=NoLimiter(),
        logger=logging.getLogger("email-change-test"),
        cookie_secure=lambda: True,
        native_refresh_encryption_key=key,
        mail_payload_encryption_key=key,
        frontend_url="https://inventory.example.test",
    )
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    yield {
        "admin": admin,
        "client": client,
        "identities": identities,
        "principals": principals,
        "key": key,
        "runtime_connection": get_connection,
        "runtime_role": runtime_role,
    }
    client.close()
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
    admin.commit()


def _cookie(api, role="owner"):
    return {"session_token": api["identities"][role][1]}


def test_browser_email_change_requires_csrf_and_keeps_active_address(email_change_api):
    api = email_change_api
    client = api["client"]
    headers = {"Content-Type": "application/json"}
    response = client.post(
        "/api/profile/email-change-requests",
        json={"email": "new@example.com"},
        cookies=_cookie(api),
        headers=headers,
    )
    assert response.status_code == 403
    assert api["admin"].execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 0

    response = client.post(
        "/api/profile/email-change-requests",
        json={"email": "new@example.com"},
        cookies=_cookie(api),
        headers={**headers, "X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 202, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["success"] is True
    assert "token" not in response.text.lower()
    user_id = api["identities"]["owner"][0]
    assert api["admin"].execute("SELECT email FROM users WHERE id=%s", (user_id,)).fetchone()["email"] == "first@example.com"
    stored = api["admin"].execute("SELECT proposed_email, token_hash FROM email_change_requests").fetchone()
    assert stored["proposed_email"] == "new@example.com"
    assert len(stored["token_hash"]) == 64


def test_status_is_user_scoped_and_only_returns_masked_pending_email(email_change_api):
    api = email_change_api
    client = api["client"]
    client.post(
        "/api/profile/email-change-requests",
        json={"email": "first-new@example.com"},
        cookies=_cookie(api, "owner"),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    own = client.get("/api/profile/email-change-request", cookies=_cookie(api, "owner"))
    foreign = client.get("/api/profile/email-change-request", cookies=_cookie(api, "engineer"))
    assert own.status_code == 200 and own.json()["proposed_email"] == "f***@example.com"
    assert foreign.status_code == 200 and foreign.json() == {"status": "none"}
    assert own.headers["cache-control"] == "no-store"
    wrong_user_cancel = client.delete(
        "/api/profile/email-change-request",
        cookies=_cookie(api, "engineer"),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert wrong_user_cancel.status_code == 200
    assert client.get("/api/profile/email-change-request", cookies=_cookie(api, "owner")).json()["status"] == "pending"
    connection = api["runtime_connection"]()
    try:
        assert connection.execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 0
        connection.execute("SELECT set_config('app.email_change_user_id', %s, true)", (str(api["identities"]["owner"][0]),))
        assert connection.execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 1
    finally:
        connection.rollback()
        connection.close()


def test_registered_target_has_same_pending_status_without_sending_mail(email_change_api):
    api = email_change_api
    client = api["client"]
    response = client.post(
        "/api/profile/email-change-requests",
        json={"email": "second@example.com"},
        cookies=_cookie(api, "owner"),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 202, response.text
    status = client.get("/api/profile/email-change-request", cookies=_cookie(api, "owner"))
    assert status.status_code == 200
    assert status.json()["status"] == "pending"
    assert status.json()["proposed_email"] == "s***@example.com"
    assert api["admin"].execute("SELECT count(*) AS n FROM mail_outbox").fetchone()["n"] == 0
    assert api["admin"].execute("SELECT email FROM users WHERE id=%s", (api["identities"]["owner"][0],)).fetchone()["email"] == "first@example.com"


def test_public_confirmation_uses_fragment_token_capability_and_notifies_old_address(email_change_api):
    from urllib.parse import parse_qs, urlsplit
    from backend.services.mail_payloads import decrypt_mail_payload

    api = email_change_api
    client = api["client"]
    requested = client.post(
        "/api/profile/email-change-requests",
        json={"email": "verified@example.com"},
        cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert requested.status_code == 202, requested.text
    queued = api["admin"].execute("SELECT encrypted_payload FROM mail_outbox").fetchone()
    payload = decrypt_mail_payload(queued["encrypted_payload"], api["key"])
    confirmation_url = urlsplit(payload["verification_url"])
    token = parse_qs(confirmation_url.fragment)["token"][0]
    # A page GET cannot submit or consume the capability.
    assert client.get("/api/auth/email-change/confirm").status_code == 405
    response = client.post("/api/auth/email-change/confirm", json={"token": token})
    assert response.status_code == 200, response.text
    assert response.json()["success"] is True
    assert response.headers["cache-control"] == "no-store"
    assert api["admin"].execute("SELECT email FROM users WHERE id=%s", (api["identities"]["owner"][0],)).fetchone()["email"] == "verified@example.com"
    notices = api["admin"].execute(
        "SELECT message_type, recipient_email, encrypted_payload FROM mail_outbox ORDER BY id"
    ).fetchall()
    assert [row["message_type"] for row in notices] == ["email_change_verification", "email_changed_notice"]
    assert notices[1]["recipient_email"] == "first@example.com"
    assert token not in notices[1]["encrypted_payload"]
    replay = client.post("/api/auth/email-change/confirm", json={"token": token})
    assert replay.status_code == 400


def test_malformed_confirmation_never_echoes_token_material(email_change_api):
    api = email_change_api
    response = api["client"].post(
        "/api/auth/email-change/confirm",
        json={"token": {"secret": "should-not-be-echoed"}},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "The confirmation link is invalid or expired."}
    assert "should-not-be-echoed" not in response.text


def test_native_email_change_routes_reject_cookie_only_and_accept_bearer(email_change_api):
    api = email_change_api
    client = api["client"]
    cookie_only = client.post(
        "/api/v1/me/email-change-requests",
        json={"email": "native@example.com"},
        cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert cookie_only.status_code == 401
    bearer = client.post(
        "/api/v1/me/email-change-requests",
        json={"email": "native@example.com"},
        headers={"Authorization": "Bearer " + api["identities"]["owner"][1]},
    )
    assert bearer.status_code == 202, bearer.text


def test_email_change_request_rejects_client_supplied_scope(email_change_api):
    api = email_change_api
    response = api["client"].post(
        "/api/profile/email-change-requests",
        json={"email": "new@example.com", "user_id": api["identities"]["engineer"][0], "organization_id": "foreign"},
        cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 422
    assert api["admin"].execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 0


def test_postgres_legacy_profile_cannot_bypass_email_verification(email_change_api):
    api = email_change_api
    response = api["client"].put(
        "/api/profile",
        json={"email": "bypass@example.com"},
        cookies=_cookie(api),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 409
    assert api["admin"].execute(
        "SELECT email FROM users WHERE id=%s", (api["identities"]["owner"][0],)
    ).fetchone()["email"] == "first@example.com"


def test_platform_admin_can_change_own_email_without_company_scope(email_change_api):
    api = email_change_api
    response = api["client"].post(
        "/api/profile/email-change-requests",
        json={"email": "platform-new@example.com"},
        cookies=_cookie(api, "platform"),
        headers={"X-CSRF-Token": "csrf-fixture"},
    )
    assert response.status_code == 202, response.text
    assert api["admin"].execute(
        "SELECT email FROM users WHERE id=%s", (api["identities"]["platform"][0],)
    ).fetchone()["email"] == "platform@example.com"
    assert api["admin"].execute("SELECT count(*) AS n FROM email_change_requests").fetchone()["n"] == 1

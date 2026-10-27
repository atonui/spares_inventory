"""Invitation-only onboarding services for tenant and platform workflows."""

import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

from fastapi import HTTPException

from backend.services.mail_outbox import enqueue_mail
from backend.services.mail_payloads import encrypt_mail_payload
from backend.services.platform_audit import record_platform_audit_event
from backend.temporal import serialize_instant, utc_now

INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60
COMPANY_ROLES = {"owner", "admin", "manager", "engineer"}


def normalize_email(email: str) -> str:
    value = email.strip().lower() if isinstance(email, str) else ""
    if len(value) > 320 or value.count("@") != 1 or any(ch.isspace() for ch in value):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    local, domain = value.split("@")
    if not local or not domain or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return value


def _invitation_link(base_url: str, organization_id, token: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Invitation base URL must be an absolute HTTP URL")
    base_path = parsed.path.rstrip("/")
    path = (base_path + "/accept_invitation.html") if base_path.endswith("/static") else (
        base_path + "/static/accept_invitation.html"
    )
    return urlunsplit((parsed.scheme, parsed.netloc, path,
                       urlencode({"organization_id": str(organization_id), "token": token}), ""))


def create_invitation(
    conn, *, organization_id, invited_by: int, email: str, company_role: str,
    frontend_url: str, encryption_key: str,
) -> dict:
    normalized = normalize_email(email)
    if company_role not in COMPANY_ROLES:
        raise HTTPException(status_code=422, detail="Invalid company role")
    existing_user = conn.execute(
        "SELECT id FROM users WHERE lower(btrim(email)) = %s AND archived_at IS NULL",
        (normalized,),
    ).fetchone()
    if existing_user:
        existing_membership = conn.execute(
            "SELECT 1 FROM organization_memberships WHERE user_id = %s", (existing_user["id"],)
        ).fetchone()
        if existing_membership:
            raise HTTPException(status_code=409, detail="This email cannot be invited to another company")
    current = utc_now()
    current_stamp = serialize_instant(current)
    conn.execute(
        """UPDATE organization_invitations SET canceled_at = %s
           WHERE organization_id = %s AND email_normalized = %s
             AND accepted_at IS NULL AND canceled_at IS NULL AND expires_at <= %s""",
        (current_stamp, organization_id, normalized, current_stamp),
    )
    pending = conn.execute(
        """SELECT 1 FROM organization_invitations
           WHERE organization_id = %s AND email_normalized = %s
             AND accepted_at IS NULL AND canceled_at IS NULL""",
        (organization_id, normalized),
    ).fetchone()
    if pending:
        raise HTTPException(status_code=409, detail="An invitation is already pending for this email")
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires = current + timedelta(seconds=INVITATION_TTL_SECONDS)
    row = conn.execute(
        """INSERT INTO organization_invitations
           (organization_id, email_normalized, company_role, token_hash, invited_by, expires_at)
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id, created_at""",
        (organization_id, normalized, company_role, token_hash, invited_by, serialize_instant(expires)),
    ).fetchone()
    url = _invitation_link(frontend_url, organization_id, token)
    encrypted = encrypt_mail_payload({"invitation_url": url}, encryption_key)
    enqueue_mail(
        conn,
        organization_id=organization_id,
        message_type="organization_invitation",
        recipient_email=normalized,
        encrypted_payload=encrypted,
        idempotency_key="invitation-" + uuid4().hex,
    )
    return {
        "id": row["id"], "email": normalized, "role": company_role,
        "created_at": row["created_at"], "expires_at": serialize_instant(expires),
    }


def cancel_invitation(conn, *, organization_id, invitation_id: int) -> None:
    row = conn.execute(
        """UPDATE organization_invitations SET canceled_at = %s
           WHERE id = %s AND organization_id = %s AND accepted_at IS NULL
             AND canceled_at IS NULL
           RETURNING id""",
        (serialize_instant(utc_now()), invitation_id, organization_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Invitation not found")


def accept_invitation(
    conn, *, organization_id, token: str, name: str | None, password: str,
    password_hash, password_verify,
) -> dict:
    """Accept only a valid, unexpired token within the candidate tenant RLS scope."""
    generic = HTTPException(status_code=400, detail="Invitation is invalid or expired")
    if not isinstance(token, str) or not token or len(token) > 256:
        raise generic
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = conn.execute(
        """SELECT id, email_normalized, company_role, expires_at, accepted_at, canceled_at
           FROM organization_invitations
           WHERE organization_id = %s AND token_hash = %s FOR UPDATE""",
        (organization_id, token_hash),
    ).fetchone()
    if row is None or row["accepted_at"] is not None or row["canceled_at"] is not None:
        raise generic
    if row["expires_at"] <= serialize_instant(utc_now()):
        raise generic
    if not isinstance(password, str) or len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")

    user = conn.execute(
        "SELECT id, email, password_hash FROM users WHERE lower(btrim(email)) = %s AND archived_at IS NULL FOR UPDATE",
        (row["email_normalized"],),
    ).fetchone()
    if user:
        if not password_verify(password, user["password_hash"]):
            raise generic
        if user["email"].strip().lower() != row["email_normalized"]:
            raise generic
        if conn.execute("SELECT 1 FROM organization_memberships WHERE user_id = %s", (user["id"],)).fetchone():
            raise generic
        user_id = user["id"]
    else:
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 200:
            raise HTTPException(status_code=422, detail="Name is required")
        user_id = conn.execute(
            """INSERT INTO users (email, name, password_hash)
               VALUES (%s, %s, %s) RETURNING id""",
            (row["email_normalized"], name.strip(), password_hash(password)),
        ).fetchone()["id"]

    conn.execute(
        """INSERT INTO organization_memberships (organization_id, user_id, company_role)
           VALUES (%s, %s, %s)""",
        (organization_id, user_id, row["company_role"]),
    )
    accepted = conn.execute(
        """UPDATE organization_invitations SET accepted_at = %s, accepted_by = %s
           WHERE id = %s AND accepted_at IS NULL AND canceled_at IS NULL""",
        (serialize_instant(utc_now()), user_id, row["id"]),
    )
    if accepted.rowcount != 1:
        raise generic
    return {"success": True, "user_id": user_id, "organization_id": str(organization_id)}


def create_organization_with_owner_invitation(
    conn, *, name: str, slug: str, owner_email: str, actor_user_id: int,
    frontend_url: str, encryption_key: str,
) -> dict:
    normalized_slug = slug.strip().lower()
    if not name.strip() or len(name.strip()) > 200:
        raise HTTPException(status_code=422, detail="Organization name is required")
    if not normalized_slug or len(normalized_slug) > 63 or not all(
        char.islower() or char.isdigit() or char == "-" for char in normalized_slug
    ) or normalized_slug[0] == "-" or normalized_slug[-1] == "-":
        raise HTTPException(status_code=422, detail="Use a lowercase URL-safe organization slug")
    organization = conn.execute(
        "INSERT INTO organizations (name, slug) VALUES (%s, %s) RETURNING id, name, slug",
        (name.strip(), normalized_slug),
    ).fetchone()
    conn.execute("SELECT set_config('app.organization_id', %s, true)", (str(organization["id"]),))
    conn.execute("INSERT INTO organization_settings (organization_id) VALUES (%s)", (organization["id"],))
    invitation = create_invitation(
        conn, organization_id=organization["id"], invited_by=actor_user_id,
        email=owner_email, company_role="owner", frontend_url=frontend_url,
        encryption_key=encryption_key,
    )
    record_platform_audit_event(
        conn, actor_user_id, "organization_created", "success", organization["id"],
        {"invitation_created": True},
    )
    return {"id": str(organization["id"]), "name": organization["name"],
            "slug": organization["slug"], "owner_invitation": invitation}

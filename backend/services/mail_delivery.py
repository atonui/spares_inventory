"""Provider boundary for transactional mail; provider details never escape."""

from html import escape
from email.utils import formataddr, parseaddr
import json
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

RESEND_ENDPOINT = "https://api.resend.com/emails"
_PROVIDER_ERROR_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _provider_error_metadata(error: HTTPError) -> tuple[str, str, str]:
    """Return bounded diagnostics; never retain provider text or response content."""
    headers = error.headers
    try:
        content_type = headers.get_content_type().lower()
    except Exception:
        content_type = ""
    response_format = (
        "json" if content_type == "application/json"
        else "html" if content_type == "text/html"
        else "text" if content_type.startswith("text/")
        else "other"
    )
    try:
        server = headers.get("server", "").lower()
    except Exception:
        server = ""
    edge = "cloudflare" if "cloudflare" in server else "other"
    try:
        raw_body = error.read(8192)
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        payload = None
    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, str):
            lowered = message.lower()
            if "api key" in lowered and ("permission" in lowered or "restricted" in lowered):
                return "api_key_permission_denied", response_format, edge
            if "domain" in lowered and ("verify" in lowered or "verified" in lowered):
                return "domain_verification", response_format, edge
            if ("testing" in lowered or "test mode" in lowered) and ("recipient" in lowered or "email" in lowered):
                return "testing_recipient_restriction", response_format, edge
        for key in ("name", "code", "type"):
            value = payload.get(key)
            if isinstance(value, str):
                candidate = value.strip().lower()
                if _PROVIDER_ERROR_NAME.fullmatch(candidate):
                    return candidate, response_format, edge
        return "json_error_unclassified", response_format, edge
    return "non_json_error_response", response_format, edge

class MailDeliveryError(Exception):
    def __init__(
        self, code: str, *, provider_status: int | None = None,
        provider_error_category: str | None = None,
        provider_response_format: str | None = None, provider_edge: str | None = None,
    ):
        self.code = code
        self.provider_status = provider_status
        self.provider_error_category = provider_error_category
        self.provider_response_format = provider_response_format
        self.provider_edge = provider_edge
        super().__init__(code)


class _StatusResponse:
    def __init__(
        self, status_code: int, provider_error_category: str | None = None,
        provider_response_format: str | None = None, provider_edge: str | None = None,
        provider_message_id: str | None = None,
    ):
        self.status_code = status_code
        self.provider_error_category = provider_error_category
        self.provider_response_format = provider_response_format
        self.provider_edge = provider_edge
        self.provider_message_id = provider_message_id

    def raise_for_status(self):
        if self.status_code < 200 or self.status_code >= 300:
            raise RuntimeError("mail provider returned a non-success status")


class _UrllibTransport:
    def post(self, url, *, json, headers, timeout):
        import json as json_module

        request = Request(
            url,
            data=json_module.dumps(json).encode("utf-8"),
            headers={
                **headers,
                "Content-Type": "application/json",
                "User-Agent": "SparesTracker-MailWorker/1.0",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                try:
                    payload = json.loads(response.read(65536).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    payload = None
                message_id = payload.get("id") if isinstance(payload, dict) else None
                if not isinstance(message_id, str) or not message_id.strip() or len(message_id) > 255:
                    message_id = None
                return _StatusResponse(response.status, provider_message_id=message_id)
        except HTTPError as exc:
            category, response_format, edge = _provider_error_metadata(exc)
            return _StatusResponse(exc.code, category, response_format, edge)


def _render_branded_email(
    *, eyebrow: str, heading: str, copy: str, link: str | None = None,
    link_label: str | None = None, detail: str | None = None,
) -> tuple[str, str]:
    """Render accessible HTML and plain-text versions using the product brand."""
    safe_link = escape(link, quote=True) if link is not None else ""
    detail_html = (
        f'<p style="margin:0 0 20px;font-size:15px;line-height:1.5;color:#334155;">{escape(detail)}</p>'
        if detail else ""
    )
    action_html = (
        f'<p style="margin:0 0 20px;"><a href="{safe_link}" '
        'style="display:inline-block;padding:12px 18px;background:#E9A23B;color:#15263B;'
        'font-weight:700;text-decoration:none;border-radius:6px;">'
        f'{escape(link_label or "Continue")}</a></p>'
        f'<p style="margin:0;color:#64748B;font-size:13px;line-height:1.5;">'
        f'If the button does not work, copy this link into your browser:<br><a href="{safe_link}" '
        f'style="color:#15263B;word-break:break-all;">{safe_link}</a></p>'
        if link is not None else ""
    )
    html = (
        '<div style="margin:0;padding:32px 16px;background:#F5F7FA;'
        'font-family:Arial,Helvetica,sans-serif;color:#15263B;">'
        '<div style="max-width:560px;margin:0 auto;background:#FFFFFF;'
        'border:1px solid #E2E8F0;border-radius:12px;overflow:hidden;">'
        '<div style="padding:22px 28px;border-bottom:1px solid #E2E8F0;'
        'font-size:16px;font-weight:700;letter-spacing:.02em;color:#15263B;">'
        'Spares Tracker</div><div style="padding:28px;">'
        f'<p style="margin:0 0 8px;color:#64748B;font-size:12px;font-weight:700;'
        f'letter-spacing:.08em;">{escape(eyebrow.upper())}</p>'
        f'<h1 style="margin:0 0 12px;font-size:24px;line-height:1.25;color:#15263B;">'
        f'{escape(heading)}</h1>'
        f'<p style="margin:0 0 24px;font-size:16px;line-height:1.5;color:#334155;">'
        f'{escape(copy)}</p>{detail_html}{action_html}'
        '<p style="margin:28px 0 0;color:#64748B;font-size:12px;line-height:1.5;">'
        'Spares Tracker</p></div></div></div>'
    )
    text_parts = ["Spares Tracker", eyebrow.upper(), heading, copy]
    if detail:
        text_parts.append(detail)
    if link is not None:
        text_parts.extend([f"{link_label or 'Continue'}: {link}", "If the button does not work, copy the link into your browser."])
    text_parts.append("Spares Tracker")
    return html, "\n\n".join(text_parts)


def send_mail(message: dict, *, api_key: str, from_address: str, http_transport=None) -> str | None:
    if not api_key or not from_address:
        raise MailDeliveryError("mail_configuration_missing")
    message_type = message.get("message_type")
    recipient = message.get("recipient_email")
    payload = message.get("payload")
    if not isinstance(payload, dict):
        raise MailDeliveryError("invalid_mail_message")
    if message_type == "organization_invitation":
        link = payload.get("invitation_url")
        subject = "You’re invited to join Spares Tracker"
        eyebrow = "Invitation"
        heading = "Join your inventory team"
        copy = "You’ve been invited to join your team on Spares Tracker. Accept the invitation to set up your account."
        detail = None
        link_label = "Accept invitation"
        invalid_code = "invalid_invitation_message"
    elif message_type == "password_reset":
        link = payload.get("reset_url")
        subject = "Reset your Spares Tracker password"
        eyebrow = "Password reset"
        heading = "Reset your password"
        copy = "We received a request to reset the password for your Spares Tracker account."
        detail = "If you did not request this, you can ignore this email. Your password will not change."
        link_label = "Reset password"
        invalid_code = "invalid_password_reset_message"
    elif message_type == "email_change_verification":
        link = payload.get("verification_url")
        subject = "Verify your new Spares Tracker email address"
        eyebrow = "Email address"
        heading = "Confirm your new email address"
        copy = "Confirm this email address to finish updating your Spares Tracker account."
        detail = None
        link_label = "Verify email address"
        invalid_code = "invalid_email_change_message"
    elif message_type == "email_changed_notice":
        new_email = payload.get("new_email")
        if not isinstance(new_email, str) or "@" not in new_email:
            raise MailDeliveryError("invalid_email_changed_notice")
        subject = "Your Spares Tracker email address changed"
        eyebrow = "Account security"
        heading = "Your email address changed"
        copy = "The email address on your Spares Tracker account was changed."
        detail = (
            f"New address: {new_email}. "
            "If you did not make this change, contact your company administrator."
        )
        link = None
        link_label = None
        invalid_code = "invalid_email_changed_notice"
    else:
        raise MailDeliveryError("unsupported_message_type")
    if not isinstance(recipient, str) or "@" not in recipient:
        raise MailDeliveryError(invalid_code)
    if link is not None:
        parsed = urlsplit(link) if isinstance(link, str) else None
        if parsed is None or parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise MailDeliveryError(invalid_code)
    sender_address = parseaddr(from_address)[1]
    if not sender_address:
        raise MailDeliveryError("mail_configuration_missing")
    html, text_body = _render_branded_email(
        eyebrow=eyebrow, heading=heading, copy=copy, detail=detail,
        link=link, link_label=link_label,
    )
    body = {
        "from": formataddr(("Spares Tracker", sender_address)),
        "to": [recipient],
        "subject": subject,
        "html": html,
        "text": text_body,
    }
    transport = http_transport or _UrllibTransport()
    provider_status = None
    provider_error_category = None
    provider_response_format = None
    provider_edge = None
    try:
        response = transport.post(
            RESEND_ENDPOINT,
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and not isinstance(status_code, bool) and 100 <= status_code <= 599:
            provider_status = status_code
        category = getattr(response, "provider_error_category", None)
        if isinstance(category, str) and _PROVIDER_ERROR_NAME.fullmatch(category):
            provider_error_category = category
        response_format = getattr(response, "provider_response_format", None)
        if response_format in {"json", "html", "text", "other"}:
            provider_response_format = response_format
        edge = getattr(response, "provider_edge", None)
        if edge in {"cloudflare", "other"}:
            provider_edge = edge
        response.raise_for_status()
        message_id = getattr(response, "provider_message_id", None)
        return message_id if isinstance(message_id, str) and message_id.strip() else None
    except Exception:
        # Keep provider response bodies and exception messages private. Only a
        # bounded machine-readable category and numeric status can escape.
        raise MailDeliveryError(
            "provider_unavailable",
            provider_status=provider_status,
            provider_error_category=provider_error_category,
            provider_response_format=provider_response_format,
            provider_edge=provider_edge,
        ) from None

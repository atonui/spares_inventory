"""Provider boundary for transactional mail; provider details never escape."""

from html import escape
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
    ):
        self.status_code = status_code
        self.provider_error_category = provider_error_category
        self.provider_response_format = provider_response_format
        self.provider_edge = provider_edge

    def raise_for_status(self):
        if self.status_code < 200 or self.status_code >= 300:
            raise RuntimeError("mail provider returned a non-success status")


class _UrllibTransport:
    def post(self, url, *, json, headers, timeout):
        import json as json_module

        request = Request(
            url,
            data=json_module.dumps(json).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                return _StatusResponse(response.status)
        except HTTPError as exc:
            category, response_format, edge = _provider_error_metadata(exc)
            return _StatusResponse(exc.code, category, response_format, edge)


def send_mail(message: dict, *, api_key: str, from_address: str, http_transport=None) -> None:
    if not api_key or not from_address:
        raise MailDeliveryError("mail_configuration_missing")
    message_type = message.get("message_type")
    recipient = message.get("recipient_email")
    payload = message.get("payload")
    if not isinstance(payload, dict):
        raise MailDeliveryError("invalid_mail_message")
    if message_type == "organization_invitation":
        link = payload.get("invitation_url")
        subject = "You are invited to Inventory"
        html = "<p>You have been invited to Inventory.</p>"
        link_label = "Accept invitation"
        invalid_code = "invalid_invitation_message"
    elif message_type == "password_reset":
        link = payload.get("reset_url")
        subject = "Password reset request - Inventory System"
        html = "<p>You requested to reset your Inventory account password.</p>"
        link_label = "Reset password"
        invalid_code = "invalid_password_reset_message"
    elif message_type == "email_change_verification":
        link = payload.get("verification_url")
        subject = "Verify your new Spares Tracker email address"
        html = "<p>Confirm this email address for your Spares Tracker account.</p>"
        link_label = "Verify email address"
        invalid_code = "invalid_email_change_message"
    elif message_type == "email_changed_notice":
        new_email = payload.get("new_email")
        if not isinstance(new_email, str) or "@" not in new_email:
            raise MailDeliveryError("invalid_email_changed_notice")
        subject = "Your Spares Tracker email address changed"
        html = (
            "<p>The email address on your Spares Tracker account was changed.</p>"
            f"<p>New address: {escape(new_email)}</p>"
            "<p>If you did not make this change, contact your company administrator.</p>"
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
        if (parsed is None or parsed.scheme not in ("https", "http") or not parsed.netloc):
            raise MailDeliveryError(invalid_code)
    body = {
        "from": from_address,
        "to": [recipient],
        "subject": subject,
        "html": html + (
            f'<p><a href="{escape(link, quote=True)}">{link_label}</a></p>'
            if link is not None else ""
        ),
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

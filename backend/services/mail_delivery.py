"""Provider boundary for transactional mail; provider details never escape."""

from html import escape
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

RESEND_ENDPOINT = "https://api.resend.com/emails"


class MailDeliveryError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _StatusResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code

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
            return _StatusResponse(exc.code)


def send_mail(message: dict, *, api_key: str, from_address: str, http_transport=None) -> None:
    if not api_key or not from_address:
        raise MailDeliveryError("mail_configuration_missing")
    message_type = message.get("message_type")
    recipient = message.get("recipient_email")
    payload = message.get("payload")
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
    else:
        raise MailDeliveryError("unsupported_message_type")
    if not isinstance(recipient, str) or "@" not in recipient or not isinstance(payload, dict):
        raise MailDeliveryError(invalid_code)
    parsed = urlsplit(link) if isinstance(link, str) else None
    if (parsed is None or parsed.scheme not in ("https", "http") or not parsed.netloc):
        raise MailDeliveryError(invalid_code)
    body = {
        "from": from_address,
        "to": [recipient],
        "subject": subject,
        "html": html + f'<p><a href="{escape(link, quote=True)}">{link_label}</a></p>',
    }
    transport = http_transport or _UrllibTransport()
    try:
        response = transport.post(
            RESEND_ENDPOINT,
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        response.raise_for_status()
    except Exception:
        # Never persist or log provider response bodies or exception messages.
        raise MailDeliveryError("provider_unavailable") from None

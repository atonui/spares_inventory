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
    if message.get("message_type") != "organization_invitation":
        raise MailDeliveryError("unsupported_message_type")
    recipient = message.get("recipient_email")
    payload = message.get("payload")
    invitation_url = payload.get("invitation_url") if isinstance(payload, dict) else None
    parsed = urlsplit(invitation_url) if isinstance(invitation_url, str) else None
    if (not isinstance(recipient, str) or "@" not in recipient or parsed is None
            or parsed.scheme not in ("https", "http") or not parsed.netloc):
        raise MailDeliveryError("invalid_invitation_message")
    body = {
        "from": from_address,
        "to": [recipient],
        "subject": "You are invited to Inventory",
        "html": "<p>You have been invited to Inventory.</p>"
                f'<p><a href="{escape(invitation_url, quote=True)}">Accept invitation</a></p>',
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

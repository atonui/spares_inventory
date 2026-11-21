"""Provider boundary for transactional mail; provider details never escape."""

from html import escape
from email.utils import formataddr, parseaddr
import json
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

RESEND_ENDPOINT = "https://api.resend.com/emails"
# Resend's API is behind Cloudflare, which rejects the default Python-urllib
# user agent with error 1010 (HTTP 403). Every Resend request must send this.
RESEND_USER_AGENT = "SparesTracker-MailWorker/1.0"
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
                "User-Agent": RESEND_USER_AGENT,
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                try:
                    payload = json_module.loads(response.read(65536).decode("utf-8"))
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
    sections: list[tuple[str, str]] | None = None,
    preheader: str | None = None,
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
        f'If the button does not work, copy this link into your browser:<br>'
        f'<span style="color:#15263B;word-break:break-all;">{safe_link}</span></p>'
        if link is not None else ""
    )
    sections_html = ""
    text_sections = []
    if sections:
        section_items = []
        for index, (section_heading, section_copy) in enumerate(sections, start=1):
            section_items.append(
                '<li style="margin:0 0 14px;padding-left:4px;">'
                f'<h2 style="margin:0 0 4px;font-size:16px;line-height:1.4;color:#15263B;">'
                f'{escape(section_heading)}</h2>'
                f'<p style="margin:0;font-size:15px;line-height:1.5;color:#334155;">'
                f'{escape(section_copy)}</p></li>'
            )
            text_sections.append(f"{index}. {section_heading}\n{section_copy}")
        sections_html = '<ol style="margin:0 0 24px;padding-left:22px;">' + "".join(section_items) + "</ol>"
    preheader_html = (
        f'<span style="display:none!important;visibility:hidden;opacity:0;color:transparent;'
        f'height:0;width:0;overflow:hidden;mso-hide:all;">{escape(preheader)}</span>'
        if preheader else ""
    )
    html = (
        '<div lang="en" dir="ltr" style="margin:0;padding:32px 16px;background:#F5F7FA;'
        'font-family:Arial,Helvetica,sans-serif;color:#15263B;">'
        f'{preheader_html}'
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
        f'{escape(copy)}</p>{sections_html}{detail_html}{action_html}'
        '<p style="margin:28px 0 0;color:#64748B;font-size:12px;line-height:1.5;">'
        'Spares Tracker</p></div></div></div>'
    )
    text_parts = ["Spares Tracker", eyebrow.upper(), heading, copy]
    text_parts.extend(text_sections)
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
    if not isinstance(recipient, str) or "@" not in recipient or any(ord(char) < 32 for char in recipient):
        raise MailDeliveryError("invalid_mail_message")
    preheader = None
    if message_type == "organization_invitation":
        link = payload.get("invitation_url")
        subject = "You’re invited to join Spares Tracker"
        eyebrow = "Invitation"
        heading = "Join your inventory team"
        copy = "You’ve been invited to join your team on Spares Tracker. Accept the invitation to set up your account."
        detail = None
        link_label = "Accept invitation"
        invalid_code = "invalid_invitation_message"
        sections = None
    elif message_type == "owner_welcome":
        owner_name = payload.get("owner_name")
        organization_name = payload.get("organization_name")
        link = payload.get("sign_in_url")
        if not all(isinstance(value, str) and value.strip() for value in (owner_name, organization_name, link)):
            raise MailDeliveryError("invalid_owner_welcome_message")
        subject = f"Welcome to {' '.join(organization_name.split())} — start with these steps"
        preheader = "Set up your stores, parts, opening stock and team in Spares Tracker."
        eyebrow = "Getting started"
        heading = f"Welcome to {organization_name}"
        copy = f"Hi {owner_name}, welcome to Spares Tracker. Your {organization_name} workspace is ready. Use this short checklist to get your team up and running."
        sections = [
            ("Check your organisation timezone", "Open Profile → Timezones and confirm the organisation timezone. It sets the calendar dates used by reports and business activity across your organisation."),
            ("Set up your stores", "Open Manage stores and add the locations where stock is kept, such as a main store or workshop. Choose the store type and names your team will recognise."),
            ("Build your parts catalogue", "Open Manage parts to add parts or import your catalogue. Check part numbers and descriptions so everyone works from the same list."),
            ("Enter your opening stock", "Choose the correct store, then add stock or import its balances. CSV balance import sets the quantities for included parts; it does not add them to existing balances. Review the store and quantities before importing."),
            ("Invite your team", "Open Manage users and invite each colleague with their own email address. Choose the role they need, and give Admin access only to people who manage users and settings."),
        ]
        detail = "For everyday work, record stock consumption against its work order number. For transfers, the receiving store should confirm receipt when the stock arrives."
        link_label = f"Sign in to {organization_name}"
        invalid_code = "invalid_owner_welcome_message"
    elif message_type == "password_reset":
        link = payload.get("reset_url")
        subject = "Reset your Spares Tracker password"
        eyebrow = "Password reset"
        heading = "Reset your password"
        copy = "We received a request to reset the password for your Spares Tracker account."
        detail = "If you did not request this, you can ignore this email. Your password will not change."
        link_label = "Reset password"
        invalid_code = "invalid_password_reset_message"
        sections = None
    elif message_type == "email_change_verification":
        link = payload.get("verification_url")
        subject = "Verify your new Spares Tracker email address"
        eyebrow = "Email address"
        heading = "Confirm your new email address"
        copy = "Confirm this email address to finish updating your Spares Tracker account."
        detail = None
        link_label = "Verify email address"
        invalid_code = "invalid_email_change_message"
        sections = None
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
        sections = None
    elif message_type == "stock_added_notice":
        store_name = payload.get("store_name")
        part_number = payload.get("part_number")
        quantity = payload.get("quantity")
        if not all(isinstance(value, str) and value.strip() for value in (store_name, part_number)):
            raise MailDeliveryError("invalid_stock_added_notice")
        if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
            raise MailDeliveryError("invalid_stock_added_notice")
        link = payload.get("inventory_url")
        subject = "Stock was added to your store"
        eyebrow = "Stock update"
        heading = f"Stock added to {store_name}"
        copy = f"{quantity} × {part_number} was added to {store_name}."
        detail = None
        link_label = "View store inventory"
        invalid_code = "invalid_stock_added_notice"
        sections = None
    elif message_type == "transfer_dispatched_notice":
        transfer_id = payload.get("transfer_id")
        part_number = payload.get("part_number")
        quantity = payload.get("quantity")
        source_store = payload.get("source_store_name")
        destination_store = payload.get("destination_store_name")
        if (
            not isinstance(transfer_id, int) or isinstance(transfer_id, bool) or transfer_id <= 0
            or not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0
            or not all(isinstance(value, str) and value.strip() for value in
                       (part_number, source_store, destination_store))
        ):
            raise MailDeliveryError("invalid_transfer_dispatched_notice")
        link = payload.get("transfer_url")
        subject = "Stock transfer awaiting receipt"
        eyebrow = "Stock transfer"
        heading = f"Transfer #{transfer_id} is awaiting receipt"
        copy = (
            f"{quantity} × {part_number} was sent from {source_store} to "
            f"{destination_store}. Confirm the physical receipt when it arrives."
        )
        detail = None
        link_label = "View transfer"
        invalid_code = "invalid_transfer_dispatched_notice"
        sections = None
    elif message_type == "transfer_completed_notice":
        transfer_id = payload.get("transfer_id")
        action = payload.get("action")
        part_number = payload.get("part_number")
        quantity = payload.get("quantity")
        source_store = payload.get("source_store_name")
        destination_store = payload.get("destination_store_name")
        if (
            not isinstance(transfer_id, int) or isinstance(transfer_id, bool) or transfer_id <= 0
            or action not in {"received", "returned"}
            or not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0
            or not all(isinstance(value, str) and value.strip() for value in
                       (part_number, source_store, destination_store))
        ):
            raise MailDeliveryError("invalid_transfer_completed_notice")
        link = payload.get("store_url")
        completed_label = "received" if action == "received" else "returned to the source store"
        subject = "Stock transfer completed"
        eyebrow = "Stock transfer"
        heading = f"Transfer #{transfer_id} {completed_label}"
        copy = (
            f"{quantity} × {part_number} moved from {source_store} to "
            f"{destination_store} was {completed_label}."
        )
        detail = None
        link_label = "View source store"
        invalid_code = "invalid_transfer_completed_notice"
        sections = None
    elif message_type == "support_reply":
        text = payload.get("text")
        subject_value = payload.get("subject")
        reply_headers = payload.get("headers", {})
        if (not isinstance(text, str) or not text.strip() or len(text) > 20000
                or not isinstance(subject_value, str) or not subject_value.strip()
                or len(subject_value) > 998 or not isinstance(reply_headers, dict)):
            raise MailDeliveryError("invalid_support_reply")
        allowed_headers = {"In-Reply-To", "References"}
        if any(key not in allowed_headers or not isinstance(value, str) or len(value) > 2000
               or any(ord(char) < 32 and char != "\t" for char in value)
               for key, value in reply_headers.items()):
            raise MailDeliveryError("invalid_support_reply")
        subject = " ".join(subject_value.split())
        if not subject:
            raise MailDeliveryError("invalid_support_reply")
        sender_address = parseaddr(from_address)[1]
        if not sender_address or any(ord(char) < 32 for char in sender_address):
            raise MailDeliveryError("mail_configuration_missing")
        html = f'<div style="white-space:pre-wrap">{escape(text)}</div>'
        text_body = text
        link = None
        link_label = None
        invalid_code = "invalid_support_reply"
        body = {
            "from": formataddr(("Spares Tracker Support", sender_address)),
            "to": [recipient], "subject": subject, "html": html, "text": text_body,
            "tags": [{"name": "app", "value": "spares_tracker"}],
        }
        if reply_headers:
            body["headers"] = reply_headers
        return _send_resend(body, api_key=api_key, message=message, http_transport=http_transport)
    else:
        raise MailDeliveryError("unsupported_message_type")
    if link is not None:
        parsed = urlsplit(link) if isinstance(link, str) else None
        if parsed is None or parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise MailDeliveryError(invalid_code)
    sender_address = parseaddr(from_address)[1]
    if not sender_address:
        raise MailDeliveryError("mail_configuration_missing")
    html, text_body = _render_branded_email(
        eyebrow=eyebrow, heading=heading, copy=copy, detail=detail,
        link=link, link_label=link_label, sections=sections, preheader=preheader,
    )
    body = {
        "from": formataddr(("Spares Tracker", sender_address)),
        "to": [recipient],
        "subject": subject,
        "html": html,
        "text": text_body,
        "tags": [{"name": "app", "value": "spares_tracker"}],
    }
    return _send_resend(body, api_key=api_key, message=message, http_transport=http_transport)


def _send_resend(body: dict, *, api_key: str, message: dict, http_transport=None) -> str | None:
    transport = http_transport or _UrllibTransport()
    headers = {"Authorization": f"Bearer {api_key}"}
    message_id = message.get("id")
    if isinstance(message_id, int) and not isinstance(message_id, bool) and message_id > 0:
        headers["Idempotency-Key"] = f"spares-tracker-mail-{message_id}"
    provider_status = None
    provider_error_category = None
    provider_response_format = None
    provider_edge = None
    try:
        response = transport.post(
            RESEND_ENDPOINT,
            json=body,
            headers=headers,
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

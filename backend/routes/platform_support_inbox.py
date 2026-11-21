"""Platform-admin-only support inbox API."""

from uuid import UUID
import asyncio
import json
import re
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request as UrlRequest, build_opener, urlopen

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from backend.services.mail_delivery import RESEND_USER_AGENT
from backend.services.mail_outbox import enqueue_mail
from backend.services.mail_payloads import encrypt_mail_payload
from backend.services.platform_audit import record_platform_audit_event
from backend.services.platform_support_inbox import decrypt_support_payload, encrypt_support_payload
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.session_credentials import get_request_credential
from backend.temporal import serialize_instant, utc_now


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SupportReply(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    idempotency_key: UUID


def create_platform_support_inbox_router(*, get_connection, current_user, csrf_dependency,
                                         encryption_key: str | None, resend_support_from_email: str | None,
                                         resend_api_key: str | None):
    router = APIRouter(prefix="/api/platform/support-inbox", tags=["platform"])

    def tx(request, actor, readonly=True):
        return authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor), readonly=readonly,
        )

    def require_key():
        if not encryption_key:
            raise HTTPException(status_code=503, detail="Support inbox is not configured")

    def fetch_attachment(email_id: str, attachment_id: str) -> tuple[bytes, str, str]:
        if not resend_api_key:
            raise HTTPException(status_code=503, detail="Attachment service is not configured")
        request = UrlRequest(f"https://api.resend.com/emails/receiving/{email_id}/attachments",
            headers={"Authorization": f"Bearer {resend_api_key}", "Accept": "application/json",
                     "User-Agent": RESEND_USER_AGENT})
        try:
            with urlopen(request, timeout=10) as provider_response:
                data = json.loads(provider_response.read(1_000_001).decode("utf-8"))
            attachments = data.get("data", []) if isinstance(data, dict) else []
            item = next((entry for entry in attachments if isinstance(entry, dict) and entry.get("id") == attachment_id), None)
            if item is None or not isinstance(item.get("download_url"), str):
                raise ValueError("Attachment unavailable")
            parsed = urlsplit(item["download_url"])
            host = (parsed.hostname or "").lower()
            if (parsed.scheme != "https" or parsed.username or parsed.password
                    or parsed.port not in (None, 443)
                    or not (host.endswith(".amazonaws.com") or host.endswith(".resend.com"))):
                raise ValueError("Attachment host rejected")
            no_redirect = build_opener(_NoRedirect)
            with no_redirect.open(UrlRequest(item["download_url"], headers={"Accept": "application/octet-stream", "User-Agent": RESEND_USER_AGENT}), timeout=15) as file_response:
                content = file_response.read(10_000_001)
                content_type = file_response.headers.get_content_type()
            if len(content) > 10_000_000:
                raise ValueError("Attachment too large")
            filename = item.get("filename")
            if not isinstance(filename, str):
                filename = "attachment"
            filename = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:120] or "attachment"
            return content, content_type, filename
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=502, detail="Attachment is temporarily unavailable") from None

    @router.get("")
    async def list_conversations(request: Request, status: str = "open", limit: int = 25,
                                 offset: int = 0, actor=Depends(current_user)):
        require_key()
        if status not in {"open", "closed", "all"} or not 1 <= limit <= 50 or not 0 <= offset <= 100000:
            raise HTTPException(status_code=422, detail="Invalid inbox filter")
        with tx(request, actor, readonly=False) as (conn, principal):
            clauses, params = [], []
            if status != "all":
                clauses.append("c.status=%s")
                params.append(status)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            rows = conn.execute(
                """SELECT c.id,c.status,c.is_read,c.latest_message_at,
                          m.encrypted_payload,m.direction,m.delivery_status,s.encrypted_payload AS sender_payload
                   FROM platform_support_conversations c
                   JOIN LATERAL (SELECT encrypted_payload,direction,delivery_status
                     FROM platform_support_messages WHERE conversation_id=c.id
                     ORDER BY id DESC LIMIT 1) m ON TRUE
                   JOIN LATERAL (SELECT encrypted_payload FROM platform_support_messages
                     WHERE conversation_id=c.id AND direction='inbound' ORDER BY id LIMIT 1) s ON TRUE""" + where +
                " ORDER BY c.latest_message_at DESC,c.id DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            ).fetchall()
            total = conn.execute("SELECT count(*) AS total FROM platform_support_conversations c" + where, params).fetchone()["total"]
            items = []
            for row in rows:
                payload = decrypt_support_payload(bytes(row["encrypted_payload"]), encryption_key)
                sender_payload = decrypt_support_payload(bytes(row["sender_payload"]), encryption_key)
                items.append({"id": row["id"], "status": row["status"], "is_read": row["is_read"],
                              "latest_message_at": row["latest_message_at"], "sender": sender_payload.get("sender"),
                              "subject": payload.get("subject"), "preview": payload.get("text", "")[:180],
                              "direction": row["direction"], "delivery_status": row["delivery_status"]})
            record_platform_audit_event(conn, principal.user_id, "platform_support_inbox_read", "success",
                details={"limit": limit, "offset": offset, "result_count": len(items)})
            return {"items": items, "total": total, "limit": limit, "offset": offset}

    @router.get("/{conversation_id}")
    async def get_conversation(conversation_id: int, request: Request, actor=Depends(current_user)):
        require_key()
        with tx(request, actor, readonly=False) as (conn, principal):
            conversation = conn.execute(
                "SELECT id,status,is_read,created_at,updated_at FROM platform_support_conversations WHERE id=%s",
                (conversation_id,),
            ).fetchone()
            if conversation is None:
                raise HTTPException(status_code=404, detail="Conversation not found")
            rows = conn.execute(
                "SELECT id,direction,encrypted_payload,delivery_status,attachment_count,created_at FROM platform_support_messages WHERE conversation_id=%s ORDER BY id",
                (conversation_id,),
            ).fetchall()
            record_platform_audit_event(conn, principal.user_id, "platform_support_conversation_read", "success",
                                        details={"conversation_id": conversation_id})
            messages = [{"id": row["id"], "direction": row["direction"],
                         "payload": decrypt_support_payload(bytes(row["encrypted_payload"]), encryption_key),
                         "delivery_status": row["delivery_status"], "attachment_count": row["attachment_count"],
                         "created_at": row["created_at"]} for row in rows]
            return {"conversation": dict(conversation), "messages": messages}

    @router.patch("/{conversation_id}/state")
    async def update_state(conversation_id: int, request: Request, body: dict,
                           actor=Depends(current_user), _csrf=Depends(csrf_dependency)):
        state = body if isinstance(body, dict) else {}
        status = state.get("status")
        is_read = state.get("is_read")
        if status is not None and (not isinstance(status, str) or status not in {"open", "closed"}):
            raise HTTPException(status_code=422, detail="Invalid status")
        if is_read is not None and not isinstance(is_read, bool):
            raise HTTPException(status_code=422, detail="Invalid read state")
        if status is None and is_read is None:
            raise HTTPException(status_code=422, detail="No state change supplied")
        with tx(request, actor, readonly=False) as (conn, principal):
            row = conn.execute(
                """UPDATE platform_support_conversations SET status=COALESCE(%s,status),
                     is_read=COALESCE(%s,is_read),updated_at=%s WHERE id=%s RETURNING id""",
                (status, is_read, serialize_instant(utc_now()), conversation_id),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Conversation not found")
            record_platform_audit_event(conn, principal.user_id, "platform_support_state_changed", "success",
                details={"conversation_id": conversation_id, "status": status, "is_read": is_read})
            return {"id": conversation_id, "status": status, "is_read": is_read}

    @router.get("/{conversation_id}/messages/{message_id}/attachments/{attachment_id}")
    async def download_attachment(conversation_id: int, message_id: int, attachment_id: str,
                                  request: Request, actor=Depends(current_user)):
        require_key()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", attachment_id):
            raise HTTPException(status_code=404, detail="Attachment not found")
        with tx(request, actor, readonly=False) as (conn, principal):
            row = conn.execute(
                """SELECT provider_email_id,encrypted_payload FROM platform_support_messages
                   WHERE id=%s AND conversation_id=%s AND direction='inbound'""",
                (message_id, conversation_id),
            ).fetchone()
            if row is None or not row["provider_email_id"]:
                raise HTTPException(status_code=404, detail="Attachment not found")
            payload = decrypt_support_payload(bytes(row["encrypted_payload"]), encryption_key)
            metadata = payload.get("attachments", [])
            if not any(isinstance(item, dict) and item.get("id") == attachment_id for item in metadata):
                raise HTTPException(status_code=404, detail="Attachment not found")
            record_platform_audit_event(conn, principal.user_id, "platform_support_attachment_downloaded", "success",
                details={"conversation_id": conversation_id, "message_id": message_id})
            email_id = row["provider_email_id"]
        content, content_type, filename = await asyncio.to_thread(fetch_attachment, email_id, attachment_id)
        return Response(content=content, media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"',
                     "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @router.post("/{conversation_id}/reply", status_code=202)
    async def reply(conversation_id: int, body: SupportReply, request: Request,
                    actor=Depends(current_user), _csrf=Depends(csrf_dependency)):
        require_key()
        if not resend_support_from_email:
            raise HTTPException(status_code=503, detail="Support replies are not configured")
        clean_text = body.text.strip()
        if not clean_text:
            raise HTTPException(status_code=422, detail="Reply cannot be blank")
        with tx(request, actor, readonly=False) as (conn, principal):
            conversation = conn.execute("SELECT id FROM platform_support_conversations WHERE id=%s FOR UPDATE", (conversation_id,)).fetchone()
            if conversation is None:
                raise HTTPException(status_code=404, detail="Conversation not found")
            inbound = conn.execute(
                "SELECT encrypted_payload FROM platform_support_messages WHERE conversation_id=%s AND direction='inbound' ORDER BY id DESC LIMIT 1",
                (conversation_id,),
            ).fetchone()
            if inbound is None:
                raise HTTPException(status_code=409, detail="No inbound message to reply to")
            original = decrypt_support_payload(bytes(inbound["encrypted_payload"]), encryption_key)
            recipient = original.get("sender")
            if not isinstance(recipient, str):
                raise HTTPException(status_code=409, detail="Conversation sender is unavailable")
            source_headers = original.get("headers") if isinstance(original.get("headers"), dict) else {}
            reply_headers = {}
            message_id_header = source_headers.get("message-id")
            if isinstance(message_id_header, str) and message_id_header.strip():
                reply_headers["In-Reply-To"] = message_id_header[:2000]
                references = source_headers.get("references")
                reference_chain = (references + " " + message_id_header) if isinstance(references, str) else message_id_header
                reply_headers["References"] = reference_chain[-2000:]
            outbound = {"sender": resend_support_from_email, "recipient": recipient,
                        "subject": "Re: " + str(original.get("subject") or "Support request")[:900],
                        "text": clean_text, "headers": reply_headers, "attachments": []}
            encrypted = encrypt_support_payload(outbound, encryption_key)
            stamp = serialize_instant(utc_now())
            key = f"support-reply-{body.idempotency_key}"
            msg = conn.execute(
                """INSERT INTO platform_support_messages
                   (conversation_id,direction,encrypted_payload,delivery_status,idempotency_key,created_at)
                   VALUES (%s,'outbound',%s,'queued',%s,%s)
                   ON CONFLICT (idempotency_key) DO NOTHING RETURNING id""",
                (conversation_id, encrypted, key, stamp),
            ).fetchone()
            if msg is None:
                existing = conn.execute(
                    "SELECT id,conversation_id FROM platform_support_messages WHERE idempotency_key=%s",
                    (key,),
                ).fetchone()
                if existing is None or existing["conversation_id"] != conversation_id:
                    raise HTTPException(status_code=409, detail="Reply request conflicts with another conversation")
                return {"message_id": existing["id"], "delivery_status": "queued"}
            outbox_payload = {"conversation_id": conversation_id, "support_message_id": msg["id"],
                              "text": clean_text, "subject": outbound["subject"], "headers": reply_headers}
            outbox_id = enqueue_mail(conn, organization_id=None, message_type="support_reply",
                recipient_email=recipient, encrypted_payload=encrypt_mail_payload(outbox_payload, encryption_key),
                idempotency_key=key)
            conn.execute("UPDATE platform_support_conversations SET is_read=TRUE,updated_at=%s,latest_message_at=%s WHERE id=%s",
                         (stamp, stamp, conversation_id))
            record_platform_audit_event(conn, principal.user_id, "platform_support_reply_queued", "success",
                details={"conversation_id": conversation_id, "message_id": msg["id"]})
            return {"message_id": msg["id"], "delivery_status": "queued", "outbox_id": outbox_id}

    return router

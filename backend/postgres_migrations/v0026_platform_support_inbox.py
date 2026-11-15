"""Version 26: encrypted platform support conversations and messages."""

VERSION = 26
NAME = "platform_support_inbox"

SQL = (
    "ALTER TABLE resend_webhook_events ADD COLUMN provider_rfc_message_id TEXT",
    "ALTER TABLE mail_outbox DROP CONSTRAINT mail_outbox_message_type_check",
    """ALTER TABLE mail_outbox ADD CONSTRAINT mail_outbox_message_type_check
       CHECK (message_type IN (
           'organization_invitation', 'owner_welcome', 'password_reset',
           'email_change_verification', 'email_changed_notice',
           'stock_added_notice', 'transfer_dispatched_notice',
           'transfer_completed_notice', 'support_reply'
       ))""",
    """CREATE TABLE platform_support_conversations (
        id BIGSERIAL PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
        is_read BOOLEAN NOT NULL DEFAULT FALSE,
        original_sender_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        latest_message_at TEXT NOT NULL
    )""",
    "CREATE INDEX idx_platform_support_conversations_activity ON platform_support_conversations (status, latest_message_at DESC, id DESC)",
    "CREATE INDEX idx_platform_support_conversations_sender ON platform_support_conversations (original_sender_hash)",
    """CREATE TABLE platform_support_messages (
        id BIGSERIAL PRIMARY KEY,
        conversation_id BIGINT NOT NULL REFERENCES platform_support_conversations(id) ON DELETE CASCADE,
        direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
        encrypted_payload BYTEA NOT NULL,
        provider_email_id TEXT UNIQUE,
        provider_message_id TEXT,
        delivery_status TEXT NOT NULL DEFAULT 'unknown' CHECK (delivery_status IN ('unknown','queued','sent','delayed','delivered','bounced','complained','failed','suppressed')),
        attachment_count INTEGER NOT NULL DEFAULT 0 CHECK (attachment_count BETWEEN 0 AND 50),
        idempotency_key TEXT UNIQUE,
        created_at TEXT NOT NULL
    )""",
    "CREATE INDEX idx_platform_support_messages_conversation ON platform_support_messages (conversation_id, id)",
    "CREATE INDEX idx_platform_support_messages_provider_message ON platform_support_messages (provider_message_id) WHERE provider_message_id IS NOT NULL",
    """CREATE TABLE platform_support_webhook_events (
        event_id TEXT PRIMARY KEY CHECK (length(event_id) BETWEEN 1 AND 255),
        provider_email_id TEXT NOT NULL CHECK (length(provider_email_id) BETWEEN 1 AND 255),
        received_at TEXT NOT NULL,
        processed_at TEXT
    )""",
    "REVOKE ALL PRIVILEGES ON TABLE platform_support_conversations, platform_support_messages, platform_support_webhook_events FROM PUBLIC",
    "REVOKE ALL PRIVILEGES ON SEQUENCE platform_support_conversations_id_seq, platform_support_messages_id_seq FROM PUBLIC",
    """DO $$ BEGIN
         IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='web_runtime_role') THEN
           REVOKE ALL PRIVILEGES ON TABLE platform_support_conversations, platform_support_messages, platform_support_webhook_events FROM web_runtime_role;
           REVOKE ALL PRIVILEGES ON SEQUENCE platform_support_conversations_id_seq, platform_support_messages_id_seq FROM web_runtime_role;
         END IF;
         IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mail_worker_role') THEN
           REVOKE ALL PRIVILEGES ON TABLE platform_support_conversations, platform_support_messages, platform_support_webhook_events FROM mail_worker_role;
           REVOKE ALL PRIVILEGES ON SEQUENCE platform_support_conversations_id_seq, platform_support_messages_id_seq FROM mail_worker_role;
         END IF;
       END; $$""",
)

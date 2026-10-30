"""Version 16: persist Resend message IDs and verified delivery events."""

VERSION = 16
NAME = "resend_delivery_webhooks"

SQL = (
    "ALTER TABLE mail_outbox ADD COLUMN provider_message_id TEXT UNIQUE",
    """ALTER TABLE mail_outbox ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'unknown'
       CHECK (delivery_status IN (
           'unknown', 'sent', 'delayed', 'delivered', 'bounced',
           'complained', 'failed', 'suppressed'
       ))""",
    "ALTER TABLE mail_outbox ADD COLUMN delivery_event_at TEXT",
    "ALTER TABLE mail_outbox ADD COLUMN delivered_at TEXT",
    "ALTER TABLE mail_outbox ADD COLUMN bounced_at TEXT",
    "ALTER TABLE mail_outbox ADD COLUMN complained_at TEXT",
    """CREATE TABLE resend_webhook_events (
        event_id TEXT PRIMARY KEY CHECK (length(event_id) BETWEEN 1 AND 255),
        provider_message_id TEXT NOT NULL CHECK (length(provider_message_id) BETWEEN 1 AND 255),
        event_type TEXT NOT NULL CHECK (event_type IN (
            'email.sent', 'email.delivered', 'email.delivery_delayed',
            'email.bounced', 'email.complained', 'email.failed',
            'email.suppressed'
        )),
        occurred_at TEXT NOT NULL,
        received_at TEXT NOT NULL DEFAULT to_char(timezone('UTC', now()), 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
        processed_at TEXT
    )""",
    """CREATE INDEX idx_resend_webhook_events_pending
       ON resend_webhook_events (provider_message_id, occurred_at, event_id)
       WHERE processed_at IS NULL""",
)

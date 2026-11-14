"""Version 24: expose curated invitation delivery metadata to platform routes."""

VERSION = 24
NAME = "platform_invitation_delivery_history"

SQL = (
    """CREATE VIEW platform_invitation_delivery_history AS
       SELECT mail.id,
              mail.organization_id,
              organization.name AS organization_name,
              organization.slug AS organization_slug,
              mail.recipient_email,
              mail.status,
              mail.delivery_status,
              mail.attempt_count,
              mail.created_at,
              mail.updated_at,
              mail.sent_at,
              mail.last_error_code
       FROM mail_outbox AS mail
       JOIN organizations AS organization ON organization.id = mail.organization_id
       WHERE mail.message_type = 'organization_invitation'
         AND mail.organization_id IS NOT NULL""",
    """CREATE INDEX idx_mail_outbox_invitation_history_created
       ON mail_outbox (created_at DESC, id DESC)
       WHERE message_type = 'organization_invitation'
         AND organization_id IS NOT NULL""",
    "REVOKE ALL ON platform_invitation_delivery_history FROM PUBLIC",
)

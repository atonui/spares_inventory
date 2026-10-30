"""Version 17: allow transactional stock and transfer notifications."""

VERSION = 17
NAME = "store_activity_emails"

SQL = (
    "ALTER TABLE mail_outbox DROP CONSTRAINT mail_outbox_message_type_check",
    """ALTER TABLE mail_outbox ADD CONSTRAINT mail_outbox_message_type_check
       CHECK (message_type IN (
           'organization_invitation', 'password_reset',
           'email_change_verification', 'email_changed_notice',
           'stock_added_notice', 'transfer_dispatched_notice',
           'transfer_completed_notice'
       ))""",
)

"""Version 23: allow the post-acceptance first-owner welcome message."""

VERSION = 23
NAME = "owner_welcome_mail"

SQL = (
    "ALTER TABLE mail_outbox DROP CONSTRAINT mail_outbox_message_type_check",
    """ALTER TABLE mail_outbox ADD CONSTRAINT mail_outbox_message_type_check
       CHECK (message_type IN (
           'organization_invitation', 'owner_welcome', 'password_reset',
           'email_change_verification', 'email_changed_notice',
           'stock_added_notice', 'transfer_dispatched_notice',
           'transfer_completed_notice'
       ))""",
)

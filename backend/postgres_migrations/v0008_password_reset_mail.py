"""Version 8: allow password-reset messages in the transactional mail outbox."""

VERSION = 8
NAME = "password_reset_mail"
SQL = (
    "ALTER TABLE mail_outbox DROP CONSTRAINT mail_outbox_message_type_check",
    """ALTER TABLE mail_outbox ADD CONSTRAINT mail_outbox_message_type_check
       CHECK (message_type IN ('organization_invitation', 'password_reset'))""",
)

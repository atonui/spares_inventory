"""Version 14: expose only per-organization invitation-mail aggregates."""

VERSION = 14
NAME = "organization_invitation_mail_counts"

SQL = (
    "CREATE INDEX idx_mail_outbox_invitation_org_status ON mail_outbox(organization_id, status) WHERE message_type = 'organization_invitation'",
    """CREATE VIEW platform_organization_invitation_mail_counts AS
       SELECT organization_id,
              count(*) FILTER (WHERE status = 'pending')::INTEGER AS pending,
              count(*) FILTER (WHERE status = 'failed')::INTEGER AS failed
       FROM mail_outbox
       WHERE message_type = 'organization_invitation' AND organization_id IS NOT NULL
       GROUP BY organization_id""",
    "REVOKE ALL ON platform_organization_invitation_mail_counts FROM PUBLIC",
)

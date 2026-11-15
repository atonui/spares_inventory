"""Version 25: expose curated organization invitation lifecycle metadata."""

VERSION = 25
NAME = "platform_invitation_history"

SQL = (
    """CREATE VIEW platform_invitation_history AS
       SELECT invitation.id AS invitation_id,
              invitation.organization_id,
              organization.name AS organization_name,
              organization.slug AS organization_slug,
              invitation.email_normalized AS recipient_email,
              invitation.company_role,
              invitation.created_at AS invited_at,
              invitation.expires_at,
              invitation.accepted_at,
              invitation.accepted_by,
              accepted_user.name AS accepted_account_name,
              invitation.canceled_at AS cancelled_at
       FROM organization_invitations AS invitation
       JOIN organizations AS organization ON organization.id = invitation.organization_id
       LEFT JOIN users AS accepted_user ON accepted_user.id = invitation.accepted_by""",
    """CREATE INDEX idx_platform_invitation_history_created
       ON organization_invitations (created_at DESC, id DESC)""",
    "REVOKE ALL ON platform_invitation_history FROM PUBLIC",
)

"""Version 7: expose aggregate mail queue health without message contents."""

VERSION = 7
NAME = "mail_outbox_counts"
SQL = (
    """CREATE VIEW platform_mail_outbox_counts AS
       SELECT count(*) FILTER (WHERE status = 'pending')::INTEGER AS pending,
              count(*) FILTER (WHERE status = 'failed')::INTEGER AS failed
       FROM mail_outbox""",
    "REVOKE ALL ON platform_mail_outbox_counts FROM PUBLIC",
)

"""Version 30: grant the support inbox to the mail worker role, whatever it is named.

Version 29 granted only to a role literally named `mail_worker_role`, but the
runbook uses that name as a placeholder and production's roles have their own
names. v0029 therefore matched nothing and did nothing, and the worker still
could not save inbound support mail.

This migration finds the worker role by what it already does: it can claim
queued mail (UPDATE of `mail_outbox.claim_token`) but cannot enqueue it (no
INSERT on `mail_outbox`), which separates it from the web role. Superusers and
the table owner are skipped. Each worker role gets the support inbox grants and
the `resend_webhook_events` grant the runbook gives the worker. A database
without such a role (local or test) is left unchanged.
"""

VERSION = 30
NAME = "mail_worker_grants_by_capability"

SQL = (
    """DO $$
       DECLARE
         worker TEXT;
       BEGIN
         FOR worker IN
           SELECT r.rolname
           FROM pg_roles AS r
           WHERE NOT r.rolsuper
             AND r.rolname NOT LIKE 'pg\\_%'
             AND r.oid <> (SELECT relowner FROM pg_class WHERE oid = 'mail_outbox'::regclass)
             AND has_column_privilege(r.oid, 'mail_outbox'::regclass, 'claim_token', 'UPDATE')
             AND NOT has_any_column_privilege(r.oid, 'mail_outbox'::regclass, 'INSERT')
         LOOP
           EXECUTE format('GRANT SELECT ON TABLE platform_support_conversations TO %I', worker);
           EXECUTE format('GRANT INSERT (status, is_read, original_sender_hash, created_at, updated_at, latest_message_at) ON TABLE platform_support_conversations TO %I', worker);
           EXECUTE format('GRANT UPDATE (status, is_read, latest_message_at, updated_at) ON TABLE platform_support_conversations TO %I', worker);
           EXECUTE format('GRANT SELECT ON TABLE platform_support_messages TO %I', worker);
           EXECUTE format('GRANT INSERT (conversation_id, direction, encrypted_payload, provider_email_id, provider_message_id, delivery_status, attachment_count, created_at) ON TABLE platform_support_messages TO %I', worker);
           EXECUTE format('GRANT UPDATE (provider_message_id, provider_email_id, delivery_status) ON TABLE platform_support_messages TO %I', worker);
           EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE platform_support_webhook_events TO %I', worker);
           EXECUTE format('GRANT USAGE ON SEQUENCE platform_support_conversations_id_seq, platform_support_messages_id_seq TO %I', worker);
           EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE resend_webhook_events TO %I', worker);
           RAISE NOTICE 'support inbox grants applied to mail worker role %', worker;
         END LOOP;
       END; $$""",
)

"""Version 29: database grants for the platform support inbox.

Version 26 created the support inbox tables and revoked every privilege from
the runtime roles; the grants lived only in the cutover runbook as a manual
step. The runbook also left out `is_read`, which the mail worker sets when a
new message arrives, so saving inbound mail failed with InsufficientPrivilege.
The grants now live here so they apply on deploy. Each block runs only when
the role exists, so local and test databases without these roles are fine.
"""

VERSION = 29
NAME = "support_inbox_role_grants"

SQL = (
    """DO $$ BEGIN
         IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='web_runtime_role') THEN
           GRANT SELECT ON TABLE platform_support_conversations TO web_runtime_role;
           GRANT UPDATE (status, is_read, updated_at)
             ON TABLE platform_support_conversations TO web_runtime_role;
           GRANT SELECT ON TABLE platform_support_messages TO web_runtime_role;
           GRANT INSERT (conversation_id, direction, encrypted_payload, delivery_status,
                         idempotency_key, created_at)
             ON TABLE platform_support_messages TO web_runtime_role;
           GRANT USAGE ON SEQUENCE platform_support_conversations_id_seq,
             platform_support_messages_id_seq TO web_runtime_role;
         END IF;
         IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mail_worker_role') THEN
           GRANT SELECT ON TABLE platform_support_conversations TO mail_worker_role;
           GRANT INSERT (status, is_read, original_sender_hash, created_at, updated_at,
                         latest_message_at)
             ON TABLE platform_support_conversations TO mail_worker_role;
           GRANT UPDATE (status, is_read, latest_message_at, updated_at)
             ON TABLE platform_support_conversations TO mail_worker_role;
           GRANT SELECT ON TABLE platform_support_messages TO mail_worker_role;
           GRANT INSERT (conversation_id, direction, encrypted_payload, provider_email_id,
                         provider_message_id, delivery_status, attachment_count, created_at)
             ON TABLE platform_support_messages TO mail_worker_role;
           GRANT UPDATE (provider_message_id, provider_email_id, delivery_status)
             ON TABLE platform_support_messages TO mail_worker_role;
           GRANT SELECT, INSERT, UPDATE ON TABLE platform_support_webhook_events TO mail_worker_role;
           GRANT USAGE ON SEQUENCE platform_support_conversations_id_seq,
             platform_support_messages_id_seq TO mail_worker_role;
         END IF;
       END; $$""",
)

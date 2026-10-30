# Environment configuration

Production reads these Railway service variables: DATABASE_URL, SECRET_KEY, CSRF_SECRET, SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, FRONTEND_URL. Keep DATABASE_URL=/data/inventory.db on the mounted volume.

For local development, copy .env.example to .env and fill the placeholders. Generate independent application keys with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Real environment files must remain untracked.

The previously committed .env remains in Git history. Replace exposed SECRET_KEY and CSRF_SECRET in Railway and revoke/reissue the exposed SMTP credential with the email provider. Application-key changes can require users to sign in again or refresh forms. This does not change user passwords or stock data.

Removing a file in a new commit does not erase old commits, clones, or forks. History cleanup must be coordinated separately; credential replacement is required even after history cleanup.

## SaaS PostgreSQL settings

The legacy Railway service continues to use its mounted SQLite path until a
separately reviewed cutover. For a SaaS PostgreSQL environment, `DATABASE_URL`
must use PostgreSQL 17 and connect as the restricted web runtime role.
`MAIL_WORKER_DATABASE_URL` connects to the same database as a distinct role
limited to processing the global mail outbox. `MIGRATION_DATABASE_URL` is the
separate schema migration identity and is used only for application startup
migrations; never use it for API or worker queries. The web and worker roles
must not own application tables, be superusers, or have `BYPASSRLS`.

The web role has no table-level `SELECT`, `UPDATE`, or `DELETE` on
`mail_outbox`. Its only outbox access is column-level `INSERT` on
`organization_id`, `message_type`, `recipient_email`, `encrypted_payload`, and
`idempotency_key`; column-level `SELECT` on `id` and `idempotency_key`;
column-level `UPDATE` on `idempotency_key`; required sequence `USAGE`; and
`SELECT` on `platform_mail_outbox_counts`, which exposes only pending and failed
integer counts, and `SELECT` on `platform_organization_invitation_mail_counts`,
which exposes only pending and failed invitation-mail totals grouped by
organization for platform-authorized directory requests. The worker role has
schema `USAGE`, column-level `SELECT` on
`id`, `organization_id`, `message_type`, `recipient_email`,
`encrypted_payload`, `status`, `attempt_count`, `available_at`,
`lease_expires_at`, and `claim_token`, and column-level `UPDATE` on `status`,
`claim_token`, `lease_expires_at`, `attempt_count`, `updated_at`, `sent_at`,
`last_error_code`, and `available_at`. It has no access to other application
tables and no outbox `INSERT`, `DELETE`, or DDL privileges.

PostgreSQL SaaS password-reset and invitation delivery require
`MAIL_PAYLOAD_ENCRYPTION_KEY`, `RESEND_API_KEY`, and `RESEND_FROM_EMAIL`.
Invitation delivery also requires `INVITATION_BASE_URL`. Store these as service
secrets. Generate the encryption key with the application's Fernet key
generator, keep it separate from `SECRET_KEY`, and retain a protected recovery
copy. Password-reset delivery uses `FRONTEND_URL`; legacy SQLite mode retains
the synchronous SMTP password-reset path.

The mail worker requires `MAIL_WORKER_DATABASE_URL`; it does not fall back to
`DATABASE_URL`. It also hosts the signed Resend webhook receiver at
`/webhooks/resend` and requires `RESEND_WEBHOOK_SECRET`. Add a Railway public
domain to the `spares_mail_worker` service, then configure that URL in Resend.
Subscribe to `email.sent`, `email.delivered`, `email.delivery_delayed`,
`email.bounced`, `email.complained`, `email.failed`, and
`email.suppressed`. Resend supplies the webhook signing secret when the
endpoint is created; set it as `RESEND_WEBHOOK_SECRET` on the mail-worker
service. The receiver stores event IDs, message IDs, event types, and timestamps
only; it does not retain the webhook payload or recipient details.

Run the service with:

```bash
python -m backend.mail_worker
```

Do not set production values or start the worker as part of a migration
rehearsal. The SaaS cutover runbook defines role setup and readiness gates.

# Environment configuration

Production reads these Railway service variables: DATABASE_URL, SECRET_KEY, CSRF_SECRET, SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, FRONTEND_URL. Keep DATABASE_URL=/data/inventory.db on the mounted volume.

For local development, copy .env.example to .env and fill the placeholders. Generate independent application keys with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Real environment files must remain untracked.

The previously committed .env remains in Git history. Replace exposed SECRET_KEY and CSRF_SECRET in Railway and revoke/reissue the exposed SMTP credential with the email provider. Application-key changes can require users to sign in again or refresh forms. This does not change user passwords or stock data.

Removing a file in a new commit does not erase old commits, clones, or forks. History cleanup must be coordinated separately; credential replacement is required even after history cleanup.

## SaaS PostgreSQL settings

The legacy Railway service continues to use its mounted SQLite path until a
separately reviewed cutover. For a SaaS PostgreSQL environment, `DATABASE_URL`
must use PostgreSQL 17 and connect as the restricted runtime role. Set
`MIGRATION_DATABASE_URL` to a separate migration role for schema startup; never
use the migration role for API queries. The runtime role must not own tenant
tables, be a superuser, or have `BYPASSRLS`.

Invitation delivery also requires `MAIL_PAYLOAD_ENCRYPTION_KEY`, `RESEND_API_KEY`,
`RESEND_FROM_EMAIL`, and `INVITATION_BASE_URL`. Store these as service secrets.
Generate the encryption key with the application's Fernet key generator,
keep it separate from `SECRET_KEY`, and retain a protected recovery copy. The
mail worker runs the same application release with the restricted
`DATABASE_URL`:

```bash
python -m backend.mail_worker
```

Do not set production values or start the worker as part of a migration
rehearsal. The SaaS cutover runbook defines role setup and readiness gates.

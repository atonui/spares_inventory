# SaaS PostgreSQL cutover runbook

This runbook describes preparation and a future cutover from the existing
single-company SQLite installation to the invitation-only SaaS on shared
PostgreSQL. It is not authorization to provision production resources, change
Railway variables, import customer data, or switch traffic. Each production
cutover requires a separately reviewed change window and explicit go/no-go
approval.

Native mobile work stays deferred until the SaaS API and cutover are stable.
The pilot uses one PostgreSQL database with tenant IDs, transaction-local
tenant context, and row-level security. Separate databases per company are a
later migration project, not a runtime toggle.

## Required release and environment

- Use a PostgreSQL 17 server and the exact reviewed application release.
- Keep the current Railway SQLite service and volume unchanged until cutover.
- `DATABASE_URL` connects as the restricted web runtime role.
- `MAIL_WORKER_DATABASE_URL` connects as a separate mail-worker role to the
  same PostgreSQL database. The worker requires this setting and never falls
  back to `DATABASE_URL`.
- `MIGRATION_DATABASE_URL` connects as the migration owner and is used only
  during application startup migrations. API requests use `DATABASE_URL`;
  mail delivery uses `MAIL_WORKER_DATABASE_URL`.
- Configure independent `SECRET_KEY` and `CSRF_SECRET` values, plus
  `MAIL_PAYLOAD_ENCRYPTION_KEY`, `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, and
  `INVITATION_BASE_URL` as service secrets. Do not reuse another product's
  mail credentials or encryption keys.
- PostgreSQL password-reset messages use the encrypted transactional outbox
  and Resend worker; `FRONTEND_URL` supplies the reset-link origin. Legacy
  SQLite mode continues to use its existing SMTP path.
- Verify the invitation sender domain, HTTPS origin, cookie security, exact
  CORS origins, database network access, and worker health before inviting
  customers.

CI provides its own PostgreSQL 17 service container for integration tests. A
developer does not need to install PostgreSQL locally. Before production
planning, require the PostgreSQL test workflow and the frontend suite to pass
on the exact release commit.

Before applying the email-change migration to any shared SaaS database, check
for existing case-insensitive email collisions. The migration adds a unique
index on `lower(btrim(email))` and does not rewrite existing addresses:

```sql
SELECT lower(btrim(email)) AS normalized_email, count(*) AS account_count,
       array_agg(id ORDER BY id) AS user_ids
FROM users
GROUP BY lower(btrim(email))
HAVING count(*) > 1;
```

If this returns any rows, stop and review a separate data-remediation change;
do not apply the migration until the duplicates are resolved.

## Database roles

Provision three distinct login identities through environment provisioning:
web runtime, mail worker, and migration owner. Role creation, passwords, and
connection credentials are not performed by application migrations. The
migration identity owns the application schema and runs the append-only
PostgreSQL migration chain. Web and worker roles are not table owners,
superusers, or `BYPASSRLS` roles. Revoke public schema creation, grant only
required schema usage and table privileges, and apply matching default
privileges for tables and sequences created by the migration identity.
The runtime role must have `DELETE` on `organization_memberships` for the
owner-authorized company-member removal operation.
Do not grant database ownership or DDL rights to the runtime login.

The web role needs access to global identity/session and platform tables as
well as tenant tables. RLS policies and server-derived transaction-local
organization context are the tenant boundary; SQL grants do not replace those
policies. After migrations, grant the web role table access to the application
tables below. The migration ledger stays migration-owner-only:

```sql
GRANT USAGE ON SCHEMA public TO web_runtime_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  users, sessions, parts, stores, store_types, work_orders, inventory,
  movements, stock_transfers, equipment, equipment_history, activity_logs,
  system_logs, system_settings, platform_admins, platform_audit_events,
  platform_announcements, organizations, organization_memberships,
  organization_settings, company_announcements, announcement_dismissals,
  organization_invitations, session_refresh_credentials,
  mobile_pairing_requests, mobile_device_sessions
TO web_runtime_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO web_runtime_role;
```

Set matching defaults for ordinary application tables and sequences created
later by the migration owner. Run these as the migration owner, replacing
`migration_owner` with its actual role name:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE migration_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO web_runtime_role;
ALTER DEFAULT PRIVILEGES FOR ROLE migration_owner IN SCHEMA public
  GRANT USAGE ON SEQUENCES TO web_runtime_role;
```

A migration that creates a restricted table must revoke the web role's default
table grant in that same migration, then grant only its required columns. In
particular, the mail and email-change restrictions below must be re-applied
after any future migration that changes those tables. Do not grant the web
role privileges on `postgres_schema_migrations`.

Verify the web role with the restricted-role PostgreSQL tests, including
missing context, wrong-tenant context, and connection reuse after rollback.

For `mail_outbox`, revoke any prior broad grants from the web role, then grant
only the permissions needed for transactional enqueueing and aggregate health
counts. Substitute the provisioned role names for `web_runtime_role` and
`mail_worker_role`; these are SQL grant examples, not role-creation or secret
commands:

```sql
REVOKE ALL PRIVILEGES ON TABLE mail_outbox FROM web_runtime_role;
GRANT INSERT (organization_id, message_type, recipient_email, encrypted_payload, idempotency_key)
  ON TABLE mail_outbox TO web_runtime_role;
GRANT SELECT (id, idempotency_key) ON TABLE mail_outbox TO web_runtime_role;
GRANT UPDATE (idempotency_key) ON TABLE mail_outbox TO web_runtime_role;
GRANT USAGE ON SEQUENCE mail_outbox_id_seq TO web_runtime_role;
GRANT SELECT ON platform_mail_outbox_counts TO web_runtime_role;
GRANT SELECT ON platform_organization_invitation_mail_counts TO web_runtime_role;

REVOKE ALL PRIVILEGES ON TABLE email_change_requests FROM web_runtime_role;
GRANT SELECT (id, user_id, proposed_email, token_hash, delivery_suppressed,
              created_at, expires_at, consumed_at, canceled_at)
  ON TABLE email_change_requests TO web_runtime_role;
GRANT INSERT (user_id, proposed_email, token_hash, delivery_suppressed, expires_at)
  ON TABLE email_change_requests TO web_runtime_role;
GRANT UPDATE (consumed_at, canceled_at)
  ON TABLE email_change_requests TO web_runtime_role;
GRANT USAGE ON SEQUENCE email_change_requests_id_seq TO web_runtime_role;
GRANT UPDATE (email) ON TABLE users TO web_runtime_role;

GRANT USAGE ON SCHEMA public TO mail_worker_role;
GRANT SELECT (id, organization_id, message_type, recipient_email, encrypted_payload,
              status, attempt_count, available_at, lease_expires_at, claim_token)
  ON TABLE mail_outbox TO mail_worker_role;
GRANT UPDATE (status, claim_token, lease_expires_at, attempt_count, updated_at,
              sent_at, last_error_code, available_at)
  ON TABLE mail_outbox TO mail_worker_role;
```

The worker receives no rights on identity, sessions, invitations, platform, or
inventory tables, and no outbox `INSERT`, `DELETE`, ownership, or DDL rights.
The API process receives the migration identity only for startup migrations;
request handling uses the web runtime identity. The worker must not receive
the migration identity.
The `platform_mail_outbox_counts` view returns exactly one row containing only
integer `pending` and `failed` counts; the view is not a per-message API.
The `platform_organization_invitation_mail_counts` view exposes only pending
and failed invitation-mail totals grouped by organization for the platform
directory. Query it only through platform-authorized application routes; it
does not expose message rows, recipients, or payloads.

## Rehearsal

1. Take a fresh SQLite backup using the current application's supported
   backup procedure. Store it encrypted in an access-controlled location.
2. Verify the backup by restoring it to a temporary SQLite file and running
   the SQLite migration `check` command. Do not rehearse against the live file.
3. Create a disposable PostgreSQL database with the same PostgreSQL version,
   extensions, schema privileges, and role separation intended for cutover.
   Start the reviewed application once with the migration login so its
   PostgreSQL migrations are current, then verify runtime access separately.
4. Export the migration-role DSN as `MIGRATION_DATABASE_URL` without placing
   credentials in shell history, command arguments, terminal recordings, or
   CI artifacts. The runtime `DATABASE_URL` role does not own the imported
   tables and must not be used for import.
5. Run the importer first without `--apply`. It opens the SQLite source
   read-only, creates a private staging copy, applies the reviewed SQLite
   migrations to that copy, and rolls back all PostgreSQL writes after
   reconciliation. Review the sanitized report.
6. Reset only the disposable rehearsal target, then repeat with `--apply`.
   Confirm the committed report matches the rollback-only rehearsal.
7. Validate the first company, owner and platform-admin mapping; test login,
   inventory balances, stock transfers, settings, historical movements,
   equipment history, activity history, invitation delivery, acceptance,
   tenant isolation, and tenant-scoped exports. Confirm every old session and
   reset token was invalidated.
8. Restore a PostgreSQL backup into a second disposable database and repeat
   the health and tenant smoke tests. A backup is not verified until restore
   and validation succeed.

Example commands (the `MIGRATION_DATABASE_URL` value is supplied out of band):

```bash
python -m backend.migration_import import-sqlite \
  --source /secure/snapshots/inventory.db \
  --target-dsn-env MIGRATION_DATABASE_URL \
  --organization-name 'First Company' \
  --platform-admin-email admin@example.com

# Reset the disposable target to its migrated, empty state, then commit:
python -m backend.migration_import import-sqlite \
  --source /secure/snapshots/inventory.db \
  --target-dsn-env MIGRATION_DATABASE_URL \
  --organization-name 'First Company' \
  --platform-admin-email admin@example.com \
  --apply
```

The importer rejects nonempty targets and unknown source roles, duplicate
normalized email addresses, invalid references, unsupported schemas, and a
platform-admin email that does not identify a legacy superadmin. It maps the
selected account to first-company owner and platform admin; any other legacy
superadmins become company admins. It preserves application record IDs where
tables support them and advances PostgreSQL identity sequences after import.
It does not copy session rows and clears the identity session and reset-token
fields. Do not change these rules ad hoc during a cutover.

Reconcile the printed row counts, store/part/work-order inventory balances,
transfer states, memberships, foreign keys, and revoked-session count against
independently captured source values. Any discrepancy is a no-go. Correct the
cause and repeat the entire rehearsal with a fresh disposable target.

## Cutover window

### Go/no-go checks

- The reviewed code commit, PostgreSQL test workflow, frontend suite, importer
  report, and restored-backup smoke test are all green.
- A recent SQLite backup is independently restorable and its checksum is
  recorded outside the application host.
- The importer rehearsal has passed on a production-like disposable target.
- Migration and runtime roles are distinct, least-privileged, and tested.
- Mail delivery and the outbox worker have passed provider-independent tests
  and one controlled end-to-end message test.
- The maintenance window, decision owner, communications, rollback owner, and
  recovery point are recorded.
- The service owner gives explicit go/no-go approval immediately before
  production execution.

### Execution

1. Announce the window and stop or place the legacy service in a verified
   read-only state. Confirm no old process, scheduled job, or operator can
   write to the SQLite database after the final snapshot.
2. Take and verify the final SQLite snapshot. Record its checksum and time.
3. Create or reset the empty production PostgreSQL target. Apply the reviewed
   migrations with the migration role. Do not point the public service at it
   yet.
4. Run the importer with `--apply` against the final snapshot. Preserve the
   sanitized report and compare every reconciliation gate to the rehearsal.
5. Start the API with web `DATABASE_URL` and migration-only
   `MIGRATION_DATABASE_URL`; configure the mail worker separately with
   `MAIL_WORKER_DATABASE_URL`. Verify migration status, web and worker role
   access, readiness, first-owner login, platform-admin separation, invitation
   delivery/acceptance, and tenant isolation.
6. Switch traffic only after every check passes. Keep the old SQLite snapshot
   and old service stopped and read-only for the agreed rollback window.
7. Do not dual-write. After PostgreSQL accepts new writes, the SQLite snapshot
   is stale and cannot be restored as a clean rollback without first
   preserving and reconciling all PostgreSQL changes.

## Monitoring and routine operations

- Monitor application readiness, database connection failures, PostgreSQL
  storage/connections, migration status, tenant authorization failures, and
  mail outbox age and failed-message counts.
- The platform dashboard reports organizations, identities, platform admins,
  and pending/failed mail only. It intentionally does not total tenant stock.
- Run one mail worker process per deployment group; database row locking
  safely coordinates claims if worker replicas are required. Alert on failed
  messages and repeated retry exhaustion. Never print encrypted or decrypted
  invitation payloads or provider response bodies.
- Take scheduled encrypted PostgreSQL backups with retention and access
  controls appropriate to customer inventory and personal data. Regularly
  restore one into an isolated database and record the validation result.
- Apply schema changes through a reviewed immutable migration. Verify the
  migration ledger after startup; never edit ledger rows or run one-off
  production SQL to repair a failed migration.
- Keep database credentials, Fernet keys, provider keys, source snapshots,
  and reports with sensitive row values out of logs and CI artifacts.

## Rollback and incident response

Before PostgreSQL receives writes, stop the new service, preserve its logs,
leave the target isolated, and restart the legacy service on its original
SQLite volume. Record the failed gate and investigate before another attempt.

After PostgreSQL receives writes, do not simply point the application back to
the SQLite snapshot. Stop writes, take a fresh PostgreSQL backup, and produce
an explicit reconciliation plan for changes since cutover. Resume only after
the recovery point and data-loss tradeoff are approved. Schema migrations have
no automatic downgrade; use compatible code or restore a verified backup into
a compatible application release.

For suspected cross-tenant access, immediately disable affected sessions or
the service, retain database and application audit evidence, preserve
customer data, and follow the incident notification process. Do not query or
export another tenant's data while investigating. Restore service only after
the authorization path, RLS context, and restricted database role have been
verified with the isolation matrix.

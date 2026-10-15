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
- `DATABASE_URL` connects as the restricted runtime role.
- `MIGRATION_DATABASE_URL` connects as the migration owner and is used only
  during application startup migrations. The API uses `DATABASE_URL` for
  requests and the mail worker.
- Configure independent `SECRET_KEY` and `CSRF_SECRET` values, plus
  `MAIL_PAYLOAD_ENCRYPTION_KEY`, `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, and
  `INVITATION_BASE_URL` as service secrets. Do not reuse another product's
  mail credentials or encryption keys.
- Verify the invitation sender domain, HTTPS origin, cookie security, exact
  CORS origins, database network access, and worker health before inviting
  customers.

CI provides its own PostgreSQL 17 service container for integration tests. A
developer does not need to install PostgreSQL locally. Before production
planning, require the PostgreSQL test workflow and the frontend suite to pass
on the exact release commit.

## Database roles

Create two distinct login roles using the hosting provider's secret manager.
The migration login owns the application schema and runs the append-only
PostgreSQL migration chain. The runtime login is not a table owner, superuser,
or `BYPASSRLS` role. Revoke public schema creation, grant the runtime login
schema usage, the required table DML rights, and sequence usage. Apply matching
default privileges for tables and sequences created by the migration login.
Do not grant database ownership or DDL rights to the runtime login.

The runtime role needs access to global identity/session and platform tables
as well as tenant tables. RLS policies and server-derived transaction-local
organization context are the tenant boundary; broad SQL grants do not bypass
those policies. Verify the role with the restricted-role PostgreSQL tests,
including missing context, wrong-tenant context, and connection reuse after
rollback. Keep migration credentials unavailable to workers that only need
to send mail.

## Rehearsal

1. Take a fresh SQLite backup using the current application's supported
   backup procedure. Store it encrypted in an access-controlled location.
2. Verify the backup by restoring it to a temporary SQLite file and running
   the SQLite migration `check` command. Do not rehearse against the live file.
3. Create a disposable PostgreSQL database with the same PostgreSQL version,
   extensions, schema privileges, and role separation intended for cutover.
   Start the reviewed application once with the migration login so its
   PostgreSQL migrations are current, then verify runtime access separately.
4. Export its DSN into an environment variable without placing credentials in
   shell history, command arguments, terminal recordings, or CI artifacts.
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

Example commands (the `DATABASE_URL` value is supplied out of band):

```bash
python -m backend.migration_import import-sqlite \
  --source /secure/snapshots/inventory.db \
  --target-dsn-env DATABASE_URL \
  --organization-name 'First Company' \
  --platform-admin-email admin@example.com

# Reset the disposable target to its migrated, empty state, then commit:
python -m backend.migration_import import-sqlite \
  --source /secure/snapshots/inventory.db \
  --target-dsn-env DATABASE_URL \
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
5. Start the application with runtime `DATABASE_URL` and the separate
   `MIGRATION_DATABASE_URL`. Verify migration status, runtime role access,
   readiness, first-owner login, platform-admin separation, invitation
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

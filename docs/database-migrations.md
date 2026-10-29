# Database migrations

The app still uses SQLite and Railway's existing database volume/path. Startup applies pending migrations before serving requests; the `uvicorn main:app` command is unchanged. No new production dependencies or environment variables are required.

## Recorded versions

| Version | Name | Changes |
|---|---|---|
| 1 | core_schema | Existing core tables/indexes and known optional authentication/reset/movement-note columns; historical equipment/store-type indexes retained and standardised |
| 2 | transfer_lifecycle | Transfer status table/index; old transfer movements remain completed history |
| 3 | archiving_integrity | Archive columns, stock identity indexes, documented legacy anonymous audit-user repair |
| 4 | timezone_preferences | Singleton organisation business timezone/revision/audit metadata and nullable personal display timezone; existing timestamp values are unchanged |

`schema_migrations` records each version, stable name, source checksum and UTC application time. Shipped migration files must remain immutable; future fixes use another numbered migration. Unknown/newer versions, missing history, changed checksums, conflicting schemas and invalid foreign references stop startup. Duplicate stock keys are rejected rather than consolidated.

Existing unversioned databases are inspected before adoption. Supported older authentication fields, movement notes, transfer/archive additions and auxiliary tables can be added without recreating core tables. Existing stock, movements, allocations, users, transfer states, configured settings and audit text are preserved. The sole historic data repair is converting anonymous audit user 0 to NULL when no such user exists. Bootstrap creates default settings/store types only under the previous application's insertion rules; it never creates a default user.

All pending migrations, ledger entries and bootstrap defaults commit together under a SQLite write lock. An error rolls the upgrade back. Lock acquisition waits up to 10 seconds; if another operation holds the write lock longer, startup fails and logs the reason. Resolve the contention and restart instead of editing the ledger or retrying arbitrary SQL. Read/write connections enforce foreign keys.

## Operator commands

Run from the project root, using the application's Python environment:

```bash
python -m backend.migrations status --database /data/inventory.db
python -m backend.migrations check --database /data/inventory.db
python -m backend.migrations upgrade --database /data/inventory.db
```

`status` and `check` are read-only and never create a missing file. Status lists current/target/pending versions. Check exits 0 only for a compatible current database; pending upgrades or errors return 1. Upgrade applies the pending batch to an existing file. Creating a new database requires an explicit flag:

```bash
python -m backend.migrations upgrade --database ./new_inventory.db --create
```

Default settings match the existing application (calibration reminder 30 days; maximum login attempts 5; lockout 15 minutes; session 24 hours; remember-me 30 days). Existing configured values always win. Commands import no web app, SMTP setup or credentials. Invalid usage returns 2; validation/upgrade errors return 1. Diagnostics identify the path and failing version/reason without dumping records.

## Restore and deployment

Restore first validates the live database without changing it, then upgrades only the temporary upload through the same runner. Integrity, schema compatibility, the requesting superadmin's identity, and forbidden schema-object checks still apply. Compatible columns may appear in a different order after an older upgrade; types/defaults/nullability, keys, constraints and index definitions must remain compatible. Newer/incompatible backups fail before live stock or sessions change. Successful restore acquires a SQLite write lock before validating the live state and taking its pre-restore snapshot, then replaces records in one transaction while retaining the validated live schema. The lock spans the snapshot and final commit, preventing other writers from committing in that gap. Session/reset-token revocation, restore evidence, migration history and autoincrement counters are preserved. A failure rolls back every live record change. Lock contention returns HTTP 409 with a retry message; reads may continue, and other writes wait or receive SQLite’s normal busy response.

SQLite migration v10 replaces stored session bearer credentials with SHA-256 hashes and clears the obsolete user-level session token fields. Existing browser credentials continue to validate against their hashes, while new SQLite sessions store only hashes. The application also upgrades legacy bcrypt password hashes after a successful login to a format that covers the full password instead of silently truncating at 72 bytes.

Startup adopts supported existing databases and applies the numbered changes above. Confirm deployment/startup logs show successful initialization. A migration failure means the service is not ready; the existing database's schema/data/ledger remain unchanged. Never manually stamp a version to bypass a failure.

There is no automatic downgrade. Reverting application code may be incompatible with a recorded newer schema. Use compatible code or deliberately restore a compatible snapshot through the existing safeguards. Backend route extraction follows in separate PRs after migrations are stable.

Version 4 seeds `Africa/Nairobi` only when organisation settings are missing during
upgrade. Existing zones/preferences are preserved. Invalid saved zones, revisions
or settings timestamps fail validation rather than falling back. An already
versioned database missing its singleton settings row is rejected; startup does
not silently reset it. Older backups are upgraded through the restore runner;
their absent business/display settings receive Nairobi/null defaults. Current
backups preserve settings and personal preferences. Code predating version 4 is
not a supported rollback against the new migration ledger/schema.

## Version 5: canonical UTC storage

Version 5 (`canonical_instants`) normalises every manifest instant to
`YYYY-MM-DDTHH:MM:SS.ffffffZ`. Verified naive UTC and explicit-offset values retain
the same instant. Nulls, calendar dates, numeric settings, stock quantities,
identities, allocation relationships and autoincrement counters are preserved.
Announcement JSON changes only its `set_at` value; other fields remain intact.
Unknown naive `users.session_expires` values and malformed instants block startup
with a field-only diagnostic. No provenance policy is weakened.

The migration rebuilds tables whose defaults used `CURRENT_TIMESTAMP`, retaining
columns, keys, constraints and indexes. SQLite defaults and explicit SQL updates
use `strftime('%Y-%m-%dT%H:%M:%f000Z','now')`; SQLite supplies milliseconds and the
remaining zeros are padding. Python writes preserve their actual microseconds.
Migration 5 freezes its reviewed field inventory, provenance policies and JSON
selectors for conversion and intermediate validation; future manifest additions
cannot change this historical migration. Final current-schema validation still
uses the application manifest. Migrations 1–4 and their checksums remain
unchanged. Both legacy and canonical
schema references are validated against their applicable version.

For this rebuild only, the runner disables foreign-key enforcement **before**
`BEGIN IMMEDIATE`, as required by SQLite's generalised table rebuild procedure.
It checks all foreign references before commit and restores enforcement in
`finally` on success or failure. The write lock covers conversion, rebuild,
validation, ledger and bootstrap. Session rows cannot be lost through cascade
side effects. Readers see committed states; concurrent writers wait or receive
normal busy errors. Current v5 backups must contain canonical values; older
supported backups are upgraded on their temporary upload before restore.

Before deployment, retain a fresh independent application Backup DB export and
verify it is restorable. Schedule a brief service interruption and ensure the old
application has stopped before migration 5 starts: old explicit SQL writers can
still produce naive timestamps after the cutover if allowed to overlap. For the
current single service with its persistent volume, Railway prevents simultaneous
active deployments on that volume; confirm the volume is still attached before
merging. Its normal volume deployment sequence supplies the required interruption
([Railway volume caveats](https://docs.railway.com/volumes/reference#caveats)).
Other hosting arrangements must stop old writers explicitly; a write lock alone
does not stop them from resuming after migration commit. The 2026-10-12 supplied snapshot was verified, but take a
new export if production has changed since it was downloaded. Startup should
reach schema version 5; use the read-only `check` command and smoke checks after
deployment. A conversion failure rolls back the entire pending batch; investigate
the identified field rather than stamping the ledger or running ad hoc SQL.

Code at schema version 4 rejects the newer ledger even though its readers can
parse canonical timestamps. Therefore reverting the deployment to v4 alone is
**not** a supported rollback. Retain v5-compatible code for an application fix,
or deliberately recover the independent pre-cutover snapshot with the matching
v4 application. Pause writes and agree the recovery point first: recovery loses
all stock, users, settings and audit changes made after that snapshot. There is
no automatic downgrade and no dependency on paid Railway backups.

## PostgreSQL SaaS import rehearsal

`backend.migration_import` copies a SQLite snapshot through a private staging
copy. The original file is opened read-only and is never migrated or edited.
The staging copy is upgraded with the existing SQLite migration chain before
validation, so legacy timestamps and anonymous audit actors receive the same
reviewed migrations as an application startup.

The target must be PostgreSQL with every registered PostgreSQL migration
already applied and no organization or application rows. The importer refuses
a nonempty target. It creates one organization, moves operational rows and
history into that tenant, maps the selected legacy superadmin to the first
company owner and a separate platform-admin record, and maps any other legacy
superadmins to company admins. It clears legacy session/reset tokens and does
not copy session rows; all users must sign in again after a future cutover.
The command prints counts and reconciliation results only.

Set the destination migration-role DSN in `MIGRATION_DATABASE_URL`. Do not use
the restricted runtime `DATABASE_URL` for import. The first command is a
rollback-only rehearsal; `--apply` is required to commit:

```bash
export MIGRATION_DATABASE_URL='postgresql://...'
python -m backend.migration_import import-sqlite \
  --source /secure/snapshots/inventory.db \
  --target-dsn-env MIGRATION_DATABASE_URL \
  --organization-name 'First Company' \
  --platform-admin-email admin@example.com

python -m backend.migration_import import-sqlite \
  --source /secure/snapshots/inventory.db \
  --target-dsn-env MIGRATION_DATABASE_URL \
  --organization-name 'First Company' \
  --platform-admin-email admin@example.com \
  --apply
```

Run both commands against disposable rehearsal copies first. Compare the report
to independently recorded counts and balances. Never put a DSN, password hash,
session token, raw record, or backup file in command history, logs, CI artifacts,
or a pull request. A failed import rolls back target changes; fix the source or
empty the disposable target and rehearse again.

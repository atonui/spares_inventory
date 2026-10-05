# Explicit SQLite migrations

## Goal and agreed scope

Make database upgrades explicit, ordered and inspectable while preserving the running inventory application. The user approved migrations first, shared database handling second, and incremental backend organisation afterward. This design covers the first PR: migrations and the database boundary needed to use them consistently. Router extraction has its own later review and PRs.

Keep SQLite, Railway's existing volume/database path and `uvicorn main:app` start command. Preserve API URLs, authentication, permissions, stock quantities, allocations, transfer states, audit evidence and restore safeguards. No ORM conversion, new reporting features, automatic duplicate consolidation or destructive schema changes.

## Current behaviour

`main.init_db()` creates tables, checks individual columns, applies transfer/archive helpers and inserts default settings. Startup invokes it. `database_restore.py` separately applies selected additive upgrades before comparing schemas and restoring. There is no persistent record of completed upgrades. The existing regression fixtures call `main.init_db()` and override `main.DATABASE`; preserve these entry points while extracting implementation.

## Chosen approach

Use a small migration runner built on the existing Python `sqlite3` interface. A migrations package has an explicitly ordered registry of immutable numbered migration modules. Do not discover executable files dynamically. Each registry entry has a version, stable name and source checksum; migration code accepts a connection and cannot commit independently.

The runner owns `schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)`. Store UTC application timestamps. Once shipped, migration sources are not edited: corrections become a later migration. Reject unknown versions, missing/interleaved history, changed checksums and malformed ledger definitions before applying changes. A database from newer code must never be silently downgraded.

Alembic remains a possible later choice if the project adopts SQLAlchemy. Using it now would introduce an unnecessary second database abstraction. Continuing the current scattered column checks would not deliver explicit upgrade history.

## Initial migrations and legacy adoption

1. `0001_core_schema`: the existing core tables, indexes and already-supported additive authentication/reset-token and movement-note columns. Preserve their current definitions; do not rebuild tables or change column types/defaults.
2. `0002_transfer_lifecycle`: the existing `stock_transfers` table and status index. Preserve pending/completed transfers. Legacy transfer movements without lifecycle records remain historical completed movements, as they do today; do not create pending transfers for them.
3. `0003_archiving_integrity`: archive columns and the two inventory identity indexes. Retain the existing narrow legacy audit-user sentinel conversion from absent user 0 to NULL. Duplicate stock identities and other broken foreign references remain errors requiring explicit reconciliation.

A truly empty database runs the chain from the beginning. A nonempty database without a ledger is not blindly stamped current. Inspect its tables, required legacy core columns and known optional additions first. Reject incompatible core definitions and unsupported/conflicting objects. Recognised older layouts can receive the same additive changes already supported by the application, including missing auxiliary tables where the old initializer created them. Existing compatible tables/columns/indexes are validated and retained. Record a migration only after its postconditions pass. Preserve existing rows and settings; do not infer or rewrite stock history.

The supported legacy layout inventory must be encoded in tests using the current schema, the supplied corrected backup, and explicit older fixtures for missing session/reset columns, movement notes, transfer schema and archive columns. Unknown layouts fail with a useful diagnostic; no generic repair or table replacement fallback.

## Transactions and failure handling

Open the migration connection with a bounded lock timeout and enable foreign-key enforcement before starting a transaction. Acquire `BEGIN IMMEDIATE` before inspecting/adopting the ledger, preventing two workers from independently applying pending migrations. Run the entire pending batch, ledger inserts and final validation in one transaction. Execute statements without `executescript()` or helper commits that would break atomicity.

The existing legacy audit-user sentinel repair must occur before the initial foreign-reference validation for recognised legacy databases. No other orphan repair is authorised. Run schema postconditions, foreign-key checks and inventory identity validation before committing. On migration, validation or lock failure, rollback and close the connection, and stop application startup with a diagnostic identifying the version/reason. Never continue serving a partially upgraded database. For existing databases, failure must preserve schema, ledger and data; an empty newly created database file may remain after unsuccessful first startup.

Successful repeated startup must not rerun completed migrations or rewrite application records. Validate ledger compatibility and required current schema even when no upgrades are pending; maintain the existing rejection of invalid foreign references or duplicate stock identities.

## Application integration and defaults

Introduce a focused database module with connection creation, migration invocation and default bootstrap settings. It takes a database path and explicit default-setting values; it does not import `main`, FastAPI route handlers or environment globals. Keep `main.init_db()` and `main.get_db_connection()` as compatibility wrappers in this PR so tests, deployment and existing routes remain stable.

Default store types/settings are bootstrap data, not migration version history. Preserve current insertion conditions and existing configured values. Pass environment-derived default values from the application into bootstrap code. Execute bootstrap after schema validation inside the startup transaction so its failure also rolls back. Do not create any default user or credentials.

Move the startup success log after successful initialization so it never claims initialization succeeded before migrations complete. Keep shutdown and other logging behaviour.

## Restore integration

Keep integrity validation, unsupported trigger/view/virtual-table rejection, superadmin identity matching, session/reset-token revocation, audit evidence, pre-restore snapshot and atomic SQLite copy.

Validate the live ledger/schema without modifying the live database. Migrate only the temporary upload using the same runner and supported legacy recogniser, then perform the existing schema compatibility comparison against the running database. Include the migration ledger in schema validation. Reject newer or incompatible uploads before touching the live database. Revalidate integrity/foreign references after upgrade. The default bootstrap required for accepted older uploads must preserve user-configured values and follow the same application rules.

Only after all checks succeed may restore copy the upload into the live database. Failed migration, schema mismatch or account mismatch must leave live stock, sessions and history unchanged. Restore tests must use realistic supported application schemas; miniature schemas that bypass application migration invariants should be replaced with proper fixtures, not accommodated through production exceptions.

## Operator commands

Provide `python -m backend.migrations status --database PATH`, `check --database PATH`, and `upgrade --database PATH`. `status` reports recorded/current/pending versions without running migrations. `check` validates the current supported schema/ledger and reports pending upgrades as a nonzero status. Both are read-only and must not create a missing database. `upgrade` explicitly applies pending migrations to an existing path; creation requires an explicit `--create` option. Normal application startup continues creating a new database when required, as today.

Commands return nonzero on incompatible history, invalid schema/data, missing paths, or upgrade failure. Output identifies the configured path and migration version without credentials or data dumps. No downgrade command. Reverting application code after a database upgrade is allowed only if that code supports the recorded schema; otherwise use a deliberately chosen compatible database snapshot. Existing restore protections remain the supported snapshot mechanism, not a new paid-backup project.

## Verification and acceptance

- Fresh initialization produces the existing application schema plus the migration ledger and expected bootstrap defaults.
- Current unversioned databases are adopted without changing stock, movements, work orders, transfer states, users, existing settings or audit evidence, except the documented legacy absent-user-0 conversion.
- Recognised older fixtures upgrade to the current schema and can be used by existing routes.
- Repeated initialization leaves migration timestamps and application records unchanged.
- Injected mid-migration/bootstrap failures roll back DDL, data changes and ledger entries together.
- Unknown/newer versions, altered checksums, incomplete history, conflicting schemas, duplicate identities and invalid foreign references are rejected safely.
- Two migration connections serialize through the write lock or fail within the bounded timeout, never applying a version twice.
- Restore accepts compatible older/current backups and rejects incompatible/newer ones without live changes; session revocation and pre-restore snapshots still work.
- Operator status/check are read-only; upgrade creation requires the explicit flag.
- Run the full Python regressions, existing JavaScript regressions, syntax/whitespace checks and a copy-only upgrade of the supplied corrected backup. Compare before/after application-table snapshots and verify the original backup hash is unchanged. No live database writes during development.

## Deployment and later backend organisation

This PR deploys through the existing Railway command and migrates before serving requests. No new environment variable, database replacement, filesystem volume or framework is required. Document supported versions, diagnostics and operator commands. Leave the working tree and user merge/deployment review intact.

After migration stability is confirmed, separate PRs can extract configuration/authentication, catalog/user/store routes, inventory/transfer routes, equipment routes and administrative routes. Preserve dependency interfaces and transaction ownership during each extraction. The first migration PR is not a wholesale rewrite of the 5,000-line backend.

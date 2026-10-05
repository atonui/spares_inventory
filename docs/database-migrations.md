# Database migrations

The app still uses SQLite and Railway's existing database volume/path. Startup applies pending migrations before serving requests; the `uvicorn main:app` command is unchanged. No new production dependencies or environment variables are required.

## Recorded versions

| Version | Name | Changes |
|---|---|---|
| 1 | core_schema | Existing core tables/indexes and known optional authentication/reset/movement-note columns; historical equipment/store-type indexes retained and standardised |
| 2 | transfer_lifecycle | Transfer status table/index; old transfer movements remain completed history |
| 3 | archiving_integrity | Archive columns, stock identity indexes, documented legacy anonymous audit-user repair |

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

Restore first validates the live database without changing it, then upgrades only the temporary upload through the same runner. Integrity, schema compatibility, the requesting superadmin's identity, and forbidden schema-object checks still apply. Compatible columns may appear in a different order after an older upgrade; types/defaults/nullability, keys, constraints and index definitions must remain compatible. Newer/incompatible backups fail before live stock or sessions change. Successful restore still saves a validated pre-restore snapshot, revokes sessions/reset tokens, writes restore evidence and copies the SQLite database atomically.

The deployment performs an additive adoption of existing databases. Confirm deployment/startup logs show successful initialization. A migration failure means the service is not ready; the existing database's schema/data/ledger remain unchanged. Never manually stamp a version to bypass a failure.

There is no automatic downgrade. Reverting application code may be incompatible with a recorded newer schema. Use compatible code or deliberately restore a compatible snapshot through the existing safeguards. Backend route extraction follows in separate PRs after migrations are stable.

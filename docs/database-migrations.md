# Database migrations

The application runs on PostgreSQL only. `DATABASE_URL` must be a
`postgresql://` URL; the settings loader refuses anything else, so a missing or
SQLite-style value fails at startup instead of silently creating a file.

Migrations live in `backend/postgres_migrations/` as numbered modules
(`v0001_core_schema.py` …) listed in `registry.py`. Startup applies any pending
migrations before serving requests, connecting as `MIGRATION_DATABASE_URL`
when it is set (the schema-owning migration role) and otherwise as
`DATABASE_URL`. See `docs/environment.md` for the role setup.

## How a migration is applied

- The ledger table `postgres_schema_migrations` records each applied version,
  its stable name, a SHA-256 checksum of its statements and the UTC time.
- Each migration runs in its own transaction together with its ledger row. A
  failing statement rolls that migration back; earlier migrations stay applied.
- Startup refuses unknown or missing history, a renamed migration, or a changed
  checksum. Shipped migration files are immutable: fix mistakes with a new
  numbered migration, never by editing an applied one.
- There is no automatic downgrade. Rolling application code back past a
  recorded migration is unsupported; restore a database backup taken from the
  matching release instead.

## Adding a migration

1. Create `backend/postgres_migrations/vNNNN_<name>.py` with `VERSION`, `NAME`
   and a `SQL` tuple of statements.
2. Append it to both lists in `registry.py`.
3. Keep data-dependent seeds frozen in the migration itself (see
   `v0028_default_store_types.py`) so later code changes never alter its
   checksum.
4. Add a test in `regression_tests/test_postgres_migrations.py` that applies the
   chain up to the previous version, seeds the relevant data, then applies the
   new version and checks the result.

## Backups

Backups and point-in-time recovery are handled by the database host (Railway).
The application has no file backup/restore endpoints; restore into a separate
database first and validate it before switching `DATABASE_URL`.

## History

The original single-company deployment used SQLite with its own migration chain
(`backend/migrations/`), a file restore tool and a one-time SQLite-to-PostgreSQL
importer. Production completed the cutover to PostgreSQL and all of that code
was removed; it remains available in git history. `docs/saas-cutover-runbook.md`
records the cutover.

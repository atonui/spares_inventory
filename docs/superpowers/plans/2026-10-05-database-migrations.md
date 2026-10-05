# Explicit SQLite Migrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace implicit schema upgrades with recorded, atomic migrations shared by startup and restore, preserving the live inventory application's behaviour.

**Architecture:** A fixed registry owns three immutable migration modules and a SQLite ledger. A runner owns the transaction, compatibility checks and bootstrap callback; a database module provides path-based connections and initialization. Existing `main` entry points remain wrappers, and restore upgrades only its temporary upload.

**Tech Stack:** Python 3.12+, sqlite3, existing FastAPI and pytest; no new production dependencies.

**Spec:** `docs/superpowers/specs/2026-10-05-database-migrations-design.md`

## Global Constraints

- Keep SQLite, Railway's existing volume/database path and `uvicorn main:app` start command.
- Preserve API URLs, authentication, permissions, stock quantities, allocations, transfer states, audit evidence and restore safeguards.
- No ORM conversion, new reporting features, automatic duplicate consolidation or destructive schema changes.
- No live database writes during development.
- No downgrade command.
- Preserve `main.init_db()` and `main.get_db_connection()` wrappers and their use of `main.DATABASE` in this PR.
- Publish selected changes against current GitHub main; the local checkout contains earlier merged work and must not be published wholesale or reset.

## Review Focus

- A partially upgraded unversioned database: validate existing definitions, preserve valid rows and reject conflicting objects (Task 1).
- A valid-looking ledger with an unknown version, altered checksum or missing version: stop before writes (Task 2).
- Two workers starting together, or a database locked by stock operations: serialize or fail within the configured timeout (Task 2).
- A current-version database whose foreign references or schema were changed manually: validate even without pending migrations (Task 3).
- A restored backup from newer code or one that lacks the live superadmin identity: reject before live sessions or stock change (Task 4).

## File Boundaries

| Files | Responsibility |
|---|---|
| `backend/__init__.py` | Package boundary only; no app/database import side effects |
| `backend/migrations/__init__.py`, `registry.py` | Public runner interfaces, fixed ordered registry and source checksums |
| `backend/migrations/v0001_core_schema.py`, `v0002_transfer_lifecycle.py`, `v0003_archiving_integrity.py` | Existing upgrade statements and migration-specific postconditions |
| `backend/migrations/validation.py` | Read-only legacy/current schema, ledger, foreign-reference and stock identity checks |
| `backend/migrations/runner.py` | Transaction ownership and consistent migration status |
| `backend/database.py` | Connection configuration, initialization and existing default bootstrap rules |
| `backend/migrations/__main__.py` | Operator status/check/upgrade commands |
| `main.py`, `database_restore.py` | Integration only; no route extraction |
| `regression_tests/fixtures/legacy_inventory.sql`, `migration_fixtures.py` | Independent pre-change schema fixture and snapshot helpers |
| `regression_tests/test_database_migrations.py`, `test_migration_cli.py`, existing restore/security/integrity tests | Behaviour, transaction, compatibility and operator verification |
| `docs/database-migrations.md` | Supported versions, diagnostics, commands and deployment behaviour |

## Task 1: Freeze Existing Schema Behaviour and Recognise Legacy Layouts

**Files:** Create migration fixture files, `backend/__init__.py`, `backend/migrations/validation.py` and the three migration modules; create `regression_tests/test_database_migrations.py`.

**Interfaces:**
- `validate_legacy(conn: sqlite3.Connection) -> None`: accept empty or explicitly supported unversioned layouts; raise `MigrationError` with table/column/index diagnostics on incompatible definitions.
- `validate_current(conn: sqlite3.Connection) -> None`: validate required current schema, foreign references and inventory identities without writes.
- Each migration module exports `VERSION: int`, `NAME: str`, `upgrade(conn: sqlite3.Connection) -> None`, `validate(conn: sqlite3.Connection) -> None`.
- Shared `MigrationError(RuntimeError)` is defined in `backend/migrations/validation.py`.

- [ ] Capture the independent current unversioned schema SQL from the existing initializer before replacing it. Record per-table rows in deterministic order; fixture includes the existing supported schema and no migration ledger. Do not derive expected schema from new migrations.
- [ ] Write `test_legacy_recognition_preserves_rows`, `test_empty_database_is_supported`, `test_missing_supported_optional_columns_upgrade`, `test_partial_known_additions_are_preserved`, `test_conflicting_table_or_index_rejected`, and `test_unknown_nonempty_layout_rejected`. Assert unknown `users(id)` is rejected, existing stock rows remain identical and conflicting named indexes are not replaced.
- [ ] Run `python -m pytest regression_tests/test_database_migrations.py -q`; confirm failure for missing recognition/migration interfaces.
- [ ] Implement supported definitions from the existing initializer and explicit old fixtures. Versions/names are `1/core_schema`, `2/transfer_lifecycle`, `3/archiving_integrity`. Freeze migration mutation statements inside their own files; do not delegate them to mutable legacy helpers. Keep existing table/index definitions, narrow additive columns and absent-user-0 conversion. Do not invent pending records for historical transfers.
- [ ] Write and run `test_duplicate_inventory_is_not_consolidated`, `test_other_orphans_are_not_repaired`, `test_legacy_audit_zero_is_normalized`, and `test_historical_transfers_stay_completed`; assert only the documented sentinel changes and validation failures preserve all other rows.
- [ ] Run the Task 1 tests to green, inspect the diff and checkpoint only this task's files on the isolated feature branch.

## Task 2: Implement the Atomic Runner and Ledger

**Files:** Create `backend/migrations/registry.py`, `runner.py`, `__init__.py`; extend migration tests.

**Interfaces:**
- `Migration(version: int, name: str, checksum: str, upgrade: Callable, validate: Callable)` is immutable; `MIGRATIONS` is a fixed tuple ordered 1, 2, 3. Checksums are SHA-256 of shipped source file bytes.
- `MigrationStatus(current_version: int, target_version: int, applied: tuple[int, ...], pending: tuple[int, ...], legacy: bool)` is immutable.
- `migration_status(conn: sqlite3.Connection) -> MigrationStatus` performs no writes and validates any existing ledger's structure/history.
- `check_database(conn: sqlite3.Connection) -> MigrationStatus` checks compatible schema/data; recognized legacy/pending status is returned for the CLI to report.
- `apply_migrations(conn: sqlite3.Connection, *, bootstrap: Callable[[sqlite3.Connection], None] | None = None) -> MigrationStatus` requires no pre-existing caller transaction, owns `BEGIN IMMEDIATE`, rollback/commit, and invokes bootstrap before final validation/commit.

- [ ] Write `test_fresh_database_records_versions_1_2_3`, `test_adoption_records_only_validated_versions`, `test_repeat_upgrade_preserves_rows_and_applied_at`, `test_mid_batch_failure_rolls_back_schema_data_and_ledger`, and `test_bootstrap_failure_rolls_back_migrations`. Compare schema plus application-table snapshots after injected failures, not only the version number.
- [ ] Run the Task 2 tests and observe failures before implementing the runner.
- [ ] Implement the ledger exactly as specified: version primary key, non-null name/checksum/applied_at, UTC timestamps. Validate a contiguous known version prefix, names and checksums before writes; reject unexpected ledger definitions and newer/unknown versions. Use individual SQL statements, never `executescript()` or migration commits. Normalize the permitted sentinel before legacy foreign-reference validation within the same transaction.
- [ ] Write `test_unknown_version_rejected_without_writes`, `test_changed_checksum_rejected_without_writes`, `test_gap_in_history_rejected`, and `test_malformed_ledger_rejected`. Snapshot the entire database's logical schema/rows before and after rejection.
- [ ] Write `test_two_workers_apply_once` using separate connections and `test_write_lock_timeout_leaves_database_unchanged` using a held `BEGIN IMMEDIATE`. Configure connections with a 10-second default timeout; tests use 0.1 seconds for the timeout case. Assert each version appears once, errors identify contention, and no partial ledger or schema commits.
- [ ] Run all migration tests to green and checkpoint the runner/registry/test changes.

## Task 3: Integrate Startup and Default Bootstrap

**Files:** Create `backend/database.py`; modify `main.py`; extend migration/security/integrity tests.

**Interfaces:**
- `connect_database(path: str | Path, *, readonly: bool = False, timeout: float = 10.0) -> sqlite3.Connection`: sets Row factory and foreign keys; read-only mode never creates a file.
- `bootstrap_defaults(conn: sqlite3.Connection, defaults: Mapping[str, str]) -> None`: preserves existing store-type insertion conditions and configured settings.
- `DEFAULT_SETTINGS` in `backend/database.py` is `{'calibration_reminder_days':'30','max_login_attempts':'5','lockout_duration_minutes':'15','session_duration_hours':'24','remember_me_duration_days':'30'}`. Startup passes the existing application constants for the four login/session settings; commands and standalone restore use these defaults when none are supplied. Existing database values always take precedence.
- `initialize_database(path: str | Path, *, defaults: Mapping[str, str]) -> MigrationStatus`: opens/closes the connection and calls Task 2's runner with the bootstrap callback.
- `main.init_db()` returns `None`, delegates with `main.DATABASE` and existing configured setting defaults. `main.get_db_connection()` returns the shared configured connection using `main.DATABASE`.

- [ ] Write `test_main_wrappers_respect_database_override`, `test_existing_settings_are_not_overwritten`, `test_no_default_user_is_created`, and `test_startup_does_not_log_success_or_write_system_event_before_migration`. Use a fresh failure injection to verify startup does not modify audit/history before an upgrade succeeds.
- [ ] Run these tests red, then move initializer schema logic to the numbered migrations and bootstrap logic to the database module. Do not touch endpoint bodies or authentication functions.
- [ ] Move database startup success/event logging after successful initialization. Preserve existing external startup-attempt and shutdown logging.
- [ ] Write `test_current_ledger_still_rejects_new_orphans`, `test_current_ledger_still_rejects_missing_required_schema`, and `test_connection_enables_foreign_keys`; validate current schema/data even when the migration registry reports nothing pending.
- [ ] Run `python -m pytest regression_tests/test_database_migrations.py regression_tests/test_security_transactions.py regression_tests/test_archiving_integrity.py -q` to green and checkpoint startup integration.

## Task 4: Upgrade Temporary Restore Uploads Through the Same Runner

**Files:** Modify `database_restore.py`, `regression_tests/test_database_restore.py`, and fixture helpers.

**Interfaces:**
- Preserve `restore_database(upload, live, actor_id)` and return value. Add keyword-only `defaults: Mapping[str, str] | None = None` for application bootstrap values; the restore endpoint supplies existing defaults. No import from `main` in database/migration/restore modules.
- Consume `check_database(conn)` for live validation and `apply_migrations(source, bootstrap=...)` only for the temporary upload. Retain the existing post-upgrade normalized schema comparison.

- [ ] Replace miniature successful-restore fixture schemas with realistic supported legacy/current schema fixtures, without weakening production validation.
- [ ] Write `test_restore_legacy_without_ledger`, `test_restore_current_migrated_backup`, `test_restore_newer_ledger_rejected_without_live_changes`, `test_restore_migration_failure_preserves_live_sessions_and_stock`, and `test_restore_requires_matching_superadmin_after_upgrade`. Assert all live table snapshots are unchanged on every rejected upload.
- [ ] Run restore tests red before replacing conditional schema helper calls with the shared runner.
- [ ] Preserve upload integrity checks, trigger/view/virtual-table rejection, foreign-reference revalidation, session/token revocation, restore audit entry, validated pre-restore snapshot and atomic SQLite copy. Never initialize or migrate the live database inside restore.
- [ ] Verify both restored and saved pre-restore copies have their expected stock/history and valid ledgers. Run migration and restore regressions to green, then checkpoint restore integration.

## Task 5: Read-only Operator Commands and Deployment Documentation

**Files:** Create `backend/migrations/__main__.py`, `regression_tests/test_migration_cli.py`, `docs/database-migrations.md`.

**Interfaces:**
- `main(argv: Sequence[str] | None = None) -> int` implements `python -m backend.migrations {status,check,upgrade} --database PATH`; only `upgrade` accepts `--create`.
- Exit codes: 0 success/current check, 1 validation/upgrade error or pending check, 2 argparse usage error. Status prints current/target/pending and legacy state; diagnostics print database path and failing migration reason without row dumps or secrets.

- [ ] Write subprocess tests `test_status_and_check_are_readonly`, `test_readonly_commands_do_not_create_missing_database`, `test_check_pending_returns_nonzero`, `test_upgrade_requires_create_for_missing_path`, and `test_cli_rejects_newer_history`. Compare file hashes before/after status/check and assert missing paths remain absent.
- [ ] Run CLI tests red, implement argument parsing and shared interfaces, then run to green. Upgrade with existing path uses bootstrap defaults equivalent to existing application defaults; document that startup inserts configured defaults and existing values always win. Do not import `main` to run commands.
- [ ] Document version history, supported legacy adoption, lock/failure diagnostics, existing Railway startup behaviour, precise command examples, and rollback limitations. Explain that reverting old code may be incompatible with a newer recorded schema. Do not add a downgrade command or new backup subscription workflow.
- [ ] Checkpoint operator code, tests and documentation.

## Task 6: Full Verification, Independent Review and Pull Request

**Files:** Selected implementation and test files above, plus this plan/spec; retain legacy helper modules if tests or other callers still need compatibility. Remove unused `main`/restore helper imports only after confirming no production caller remains.

- [ ] Run `python -m pytest regression_tests -q`, `node --test regression_tests/*.cjs`, `python -m compileall backend main.py database_restore.py`, and whitespace checks. Use the existing test environment; do not publish runtime/cache files.
- [ ] Copy the supplied corrected backup to a disposable path. Upgrade the copy, verify required schema/ledger, run integrity/foreign-reference checks, compare every application table's before/after rows and the documented sentinel exception. Verify the original file hash is unchanged. Run a second upgrade and assert no additional changes.
- [ ] Review fresh initialization, startup failure, live-schema adoption, schema/checksum rejection, old restore, existing transfer/minimum/count/audit/report regressions, and dependency boundaries against the approved spec. Confirm the Railway command and API schema/route paths remain unchanged.
- [ ] Request a fresh whole-branch review using `superpowers:requesting-code-review` with the approved spec, this plan, base/head references and selected diff. Fix critical/important findings and rerun affected checks before publishing.
- [ ] Verify fresh GitHub main, reconcile any upstream changes, publish only selected reviewed files, and inspect the resulting commit diff. Create one implementation PR summarizing behaviour, migration adoption, validation and deployment implications. Leave merge/deployment to the user.

## Execution Handoff

Recommend native execution: these tasks share schema/transaction interfaces closely, and a single implementer can retain that context while a fresh reviewer checks the completed branch. Subagent-driven execution is available if the user prefers independent task-by-task review. Implementation starts after the user reviews this plan and chooses the execution method.

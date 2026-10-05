# Session Write Revalidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Native execution is already selected; one independent whole-branch review follows implementation.

**Goal:** Prevent authenticated requests from changing application records after restore or another committed operation invalidates their original session or authority.

**Architecture:** Pass the existing cookie and integer actor ID explicitly into a transaction owner. Validate the exact session after `BEGIN IMMEDIATE`, then check current permissions and mutate/audit using that same connection. Restore injects the same borrowed validator into its existing locked replacement boundary.

**Tech Stack:** Existing FastAPI, SQLite, pytest, TestClient and Node tests; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-05-session-write-revalidation-design.md`

## Global Constraints

- Use disposable databases only; do not open production databases or user backups.
- Preserve existing routes, schemas, cookie metadata, stock behavior, role policy and deployment; full OpenAPI must remain identical.
- Keep `get_current_user` returning an integer; no implicit request globals, process-local locks, JWT conversion or schema migration.
- A protected HTTP write has no optional-token bypass. Internal transaction primitives/offline restore remain trusted explicit interfaces.
- Upload/parsing precede the writer lock; authorization and permissions follow it on the owning connection.
- No frontend work, general authentication/admin extraction, public-authentication redesign or unrelated fixture cleanup.
- Invalid/revoked/missing session: HTTP401, existing `Not authenticated` or `Invalid or expired session`; expired session: existing `Session expired`. Malformed expiry fails401 rather than500.
- Stock busy detail remains `Stock is busy; no changes saved. Try again`; balance-import busy detail remains `Database busy; no balances saved. Try again`; other guarded writes use HTTP409 `Database is busy; no changes saved. Try again`.

## Review Focus

1. A request retains a valid session but loses role/store ownership while waiting: current authority must be checked on the mutation connection, with existing403 behavior (Tasks2–4 tests).
2. Restore reuses user/session IDs: the original token and expected actor must still match, never just an integer ID (Tasks1/5 tests).
3. Decorator or maintenance audit runs after restore/logout: it must not insert records under stale credentials or duplicate atomic mutation evidence (Tasks3/4/6 tests).
4. A route uses dependency overrides or a helper's tokenless internal interface: production HTTP paths must still require explicit valid credentials (Tasks2/6 tests).
5. A denied restore or failed write retains its lock/connection or creates an unauthorized snapshot: fail without live changes, release locks, and create no pre-restore snapshot on authorization denial (Tasks1/5 tests).

## Files and ownership

- Create `backend/services/session_access.py`: borrowed validator, no application import or transaction ownership.
- Create `backend/services/authenticated_transactions.py`: owning guarded transaction.
- Modify `backend/services/stock_transactions.py`: keyword-only configurable busy detail with unchanged default; retain cleanup behavior.
- Modify `main.py`: explicit HTTP token plumbing, guarded mutation wrapper, borrowed permission/audit adapters, converted endpoint transaction boundaries and safe decorator behavior. Preserve public models and route layout.
- Modify `stock_counts.py`, `replenishment.py`: guarded writer injection accepts actor/token; read interfaces stay unchanged.
- Modify `database_restore.py`: optional explicit trusted validator callback executed on the locked live connection; HTTP always supplies it.
- Create `regression_tests/session_fixtures.py`, `test_session_access.py`, `test_authenticated_transactions.py`, `test_session_write_routes.py`, `test_session_restore_ordering.py`.
- Modify `regression_tests/test_stock_safety.py`: shared API fixture issues real disposable session credentials; any other affected fixtures/expectations must be explicitly listed in the execution ledger.
- Create `docs/session-write-coverage.md`: exact route/owner/assertion inventory, maintained alongside each conversion.

## Task 1: Session Validator and Owning Transaction

**Interfaces:** `require_session(conn: sqlite3.Connection, session_token: str | None, *, expected_user_id: int | None = None) -> sqlite3.Row` returns joined session/user fields including `user_id`, role and name. It requires an active transaction, validates token/active account/expiry and optional expected actor, and never changes or closes the connection. Use a cursor-local `sqlite3.Row` factory, supporting connections with either tuple or Row defaults without changing their connection factory. `authenticated_write_transaction(get_connection, *, user_id: int, session_token: str | None, busy_detail: str = GENERIC_BUSY_DETAIL)` yields the owned connection. `write_stock_transaction(get_connection, *, busy_detail=EXISTING_STOCK_BUSY_DETAIL)` retains its existing context-manager contract.

- [ ] Capture complete pre-change OpenAPI to `/tmp/session-write-openapi-baseline.json` using disposable `conftest`; inspect actual route registrations and initialize the coverage document with the inventory below. Characterize current successful profile, catalog/equipment, stock and superadmin responses using the existing API fixture. Expected: current compatibility tests pass; no product code changed.
- [ ] Write validator tests `test_valid_session_borrows_connection`, `test_session_rejects_invalid_credentials`, `test_actor_mismatch`, `test_expiry_formats` and `test_requires_transaction`. Parameterize missing token, unknown token, inactive session, archived/missing user, wrong actor, expired/malformed expiry and an unrelated active session for the same actor. Assert401 exact details above, valid naive/future UTC-aware timestamps accepted, original connection remains usable/in-transaction, and no records change. Reused IDs with different tokens must reject.
- [ ] Write `test_authenticated_transaction_commits_and_closes`, `test_denial_rolls_back_and_closes`, `test_exception_rolls_back_stock_movement_and_audit`, `test_busy_details`, `test_dynamic_database_factory`, and `test_service_import_has_no_main_or_files`. Use real SQLite connections, explicit closing fixtures, and the existing stock evidence helper only where safe. Denial must occur before yield; error rollback evidence must be verified after reconnecting.
- [ ] Run `python -m pytest regression_tests/test_session_access.py regression_tests/test_authenticated_transactions.py -q`. Expected: RED due absent service interfaces, not fixture/import-path mistakes. Implement the interfaces above; normalize aware expiry to UTC, retain naive legacy UTC interpretation, and avoid logging credentials. Run the same command: expected GREEN.
- [ ] Add the main wrapper `authenticated_write_transaction(user_id: int, session_token: str | None, *, busy_detail=GENERIC_BUSY_DETAIL)` resolving the current `get_db_connection` at entry. Convert `get_current_user` to a short owning writer transaction: validate via `require_session` with no expected actor, update last activity for that validated session, commit and return its integer user ID. Invalid session denial does not persist writes. Expired sessions remain unusable without requiring a deactivation write on the denial path.
- [ ] Adapt the shared `api` test fixture to seed real active sessions for its four actors and inject the matching cookie per outgoing request, respecting explicitly supplied cookies. Keep actor overrides usable for existing authorization tests; do not override/bypass the new transaction guard. Add a separate fixture using real `get_current_user` for authentication and race tests. Adjust assertions affected by the additional seeded sessions explicitly, preserving original behavioral assertions.
- [ ] Run `python -m pytest regression_tests/test_session_access.py regression_tests/test_authenticated_transactions.py regression_tests/test_stock_safety.py -q`: expected all pass. Commit `feat: validate sessions inside owned write transactions`.

## Task 2: Stock, Imports, Counts and Archive Boundaries

**Interfaces:** Consume Task1's main guarded wrapper. `archive_record(table, identifier, user_id, restore=False, *, session_token: str | None)` and `complete_transfer(transfer_id, data, user_id, action, request=None, *, session_token: str | None)` require credentials at their HTTP entry. Update count/replenishment writer injection to callable `(user_id: int, session_token: str | None)` returning a guarded context; HTTP obtains tokens from `Request.cookies`, without exposing additional OpenAPI parameters. Extend `require_user_management(user_id: int, requested_role=None, target_user_id=None, *, conn=None)` to borrow a supplied connection for archive permissions. Add `log_endpoint(..., transactional: bool = False)` here: when true, skip its separate database audit on success and failure; converted stock/archive routes already own their mutation evidence.

- [ ] Add HTTP cases for every Task2 inventory row: initially authenticated actor whose session is revoked immediately before transaction entry must receive401 and leave inventory, movements, transfers, thresholds, catalog/archive state and activity rows unchanged. For count confirm prepare valid sheet/preview tokens; for import supply valid rows; for receive/return seed the required pending transfer. Each case must prove it reaches the mutation boundary rather than fail422/400 earlier.
- [ ] Add `test_waiting_stock_write_rechecks_store_owner` and `test_waiting_archive_rechecks_privileged_target`: change current ownership/target superadmin role between initial authentication and entry; assert existing403 and no changes. Add `test_stock_cookie_missing_even_with_actor_override`: a valid body plus tokenless dependency override still fails401.
- [ ] Run `python -m pytest regression_tests/test_session_write_routes.py -k 'stock or count or archive or import or minimum' -q`: expected RED because original mutation boundaries use stale IDs. Convert stock add/update/consume/transfer, receipt/return, balance import, count confirm, minimum update and archive/reactivation HTTP paths to guarded transactions. Preserve import-specific busy message. Put borrowed permission checks under the lock; remove owner-invalidating helper closes/inner commits. Keep stock audit rows on the owner connection.
- [ ] Run the preceding command plus `python -m pytest regression_tests/test_stock_import.py regression_tests/test_stock_counts.py regression_tests/test_replenishment.py regression_tests/test_transfer_receipts.py regression_tests/test_archiving_integrity.py regression_tests/test_stock_audit.py -q`: expected all pass. Update coverage rows and commit `fix: revalidate stock and archive requests before writes`.

## Task 3: Catalog, Store Types and Equipment

**Interfaces:** Extend `check_admin(user_id: int, conn=None) -> bool` so a supplied connection is borrowed; consume Task2's borrowed `require_user_management`; preserve read callers with no connection. Reuse existing `require_superadmin(user_id, conn=None)`. Add borrowed `record_activity(conn, *, user_id, username, action, resource_type=None, resource_id=None, details=None, status='success', error_message=None, ip_address=None, user_agent=None) -> None` in `backend/services/activity.py`; it writes without commit/close and propagates insertion errors.

- [ ] Write per-route revoked-session tests for Task3 inventory rows, `test_catalog_role_changed_before_write`, `test_equipment_owner_changed_before_write`, and `test_mutation_audit_rolls_back_with_record`. Assert401/403, unchanged primary/history/audit tables; valid counterparts retain characterized response values. Verify borrowed permission/audit helpers do not open or close another connection. Run `python -m pytest regression_tests/test_session_write_routes.py -k 'catalog or store_type or equipment' -q`: expected RED.
- [ ] Convert user create/update, store create/update/import, store-type create/update/delete, part create/update/import, equipment create/update/transfer/calibrate/delete and calibration-setting update. Parse bulk input before lock; revalidate permissions on the owner connection; preserve existing validation, uniqueness and ownership behavior. Compute password hashes before locking where possible; when current password verification is required, check its current stored hash inside the lock.
- [ ] For converted mutation decorators, consume Task2's `transactional=True` option to suppress the separate database audit insert on both success and failure. Insert existing success activity evidence through `record_activity` inside the mutation transaction; preserve action/resource fields and safe request metadata. Stock/archives keep their existing atomic audits without duplicates. File error diagnostics remain allowed, without credentials. Do not silently swallow borrowed audit insertion failures.
- [ ] Run the focused command and `python -m pytest regression_tests/test_stock_safety.py regression_tests/test_archiving_integrity.py regression_tests/test_security_transactions.py -q`: expected all pass. Update coverage and commit `fix: guard catalog and equipment mutation transactions`.

## Task 4: Profile, Sessions, Admin and Maintenance Audits

**Interfaces:** Consume Task1 guarded owner and Task3 borrowed permissions/activity. Add `log_authenticated_activity(user_id: int, session_token: str | None, **activity) -> None` as a best-effort main adapter for standalone read/maintenance audit writes: opens its own guarded transaction; skips stale/invalid sessions without changing the completed read response. Never use this adapter inside an already owned mutation transaction.

- [ ] Write per-route revoked-session tests for Task4 inventory rows; valid session-revocation/password-change operations must commit their own invalidation after the entry check. Add `test_admin_role_changed_before_write`, `test_read_audit_after_restore_does_not_write`, `test_logout_has_one_atomic_audit`, `test_admin_audit_failure_rolls_back_mutation` and `test_public_authentication_remains_compatible`. Assert stale401, role403, no stale audit/system-log records and no token in activity details. Run `python -m pytest regression_tests/test_session_write_routes.py -k 'profile or session or admin or audit or public' -q`: expected RED for new stale-write cases.
- [ ] Convert profile/password change, logout/session revocations, all enumerated superadmin record mutations and activity cleanup/purge to guarded owners; perform role/target checks on their connection. Insert success audits on that connection. Preserve protected audit retention and response payloads; no post-commit unauthenticated success insert.
- [ ] Route authenticated read decorators and explicit query/backup/VACUUM database audit writes through `log_authenticated_activity` with their original token. Query/backup/VACUUM operations themselves retain their spec-defined boundaries; no writer lock spans download, email, parsing or VACUUM. Runtime security-config globals must update only after successful DB commit. Public login/reset logging and startup/shutdown system logging remain outside this authenticated contract.
- [ ] Run the focused command plus `python -m pytest regression_tests/test_security_transactions.py regression_tests/test_stock_safety.py regression_tests/test_stock_audit.py -q`: expected all pass. Update coverage and commit `fix: guard account and administration writes`.

## Task 5: Restore Boundary and Real Lock Ordering

**Interfaces:** Extend `restore_database(upload, live, actor_id, *, defaults=None, validate_actor: Callable[[sqlite3.Connection], None] | None = None) -> str`. Offline omission remains trusted. HTTP restore always supplies a callback that invokes Task1 `require_session` with the original token/actor and `require_superadmin` against the locked target. Since the restore target uses tuple rows today, the validator must support its row representation explicitly (set target Row factory and adjust restore actor comparisons, or use cursor-local named mapping without changing identity semantics); Task1's cursor-local Row mapping is the chosen approach, preserving restore's tuple identity checks.

- [ ] Write `test_restore_rechecks_original_session_under_lock`, `test_restore_role_loss_is_403`, `test_unauthorized_restore_creates_no_snapshot`, `test_restore_first_rejects_waiting_http_write`, `test_write_first_is_in_pre_restore_snapshot`, `test_restored_ids_do_not_authorize_original_token`, and `test_failed_restore_preserves_current_session`. Include real independent SQLite connections and an HTTP authenticated request paused at the guarded transaction boundary. Coordinate threads/events with bounded joins; no timing-only sleeps. Distinguish a callback denial from invalid-file validation.
- [ ] Run `python -m pytest regression_tests/test_session_restore_ordering.py -q`: expected RED for missing callback/unguarded restore behavior. Add callback execution immediately after the live `BEGIN IMMEDIATE`, before snapshot creation or live mutation; allow401/403 to propagate without conversion to400. Preserve upload validation, identity matching, backups, counters, migration checks and restore busy/time-limit behavior.
- [ ] Add restore route Request injection and mandatory callback, remove any standalone pre-lock role check as the sole authority. Run the preceding command plus `python -m pytest regression_tests/test_database_restore.py regression_tests/test_restore_concurrency.py -q`: expected all pass. Update coverage and commit `fix: revalidate restore callers under the live writer lock`.

## Task 6: Exhaustive Route Coverage and Compatibility

**Interfaces:** Coverage inventory maps actual registered route method/path to owner, session evidence, current permission checks and named regression case. It is a review record, not a source-only test that substitutes for HTTP behavior.

- [ ] Add a parameterized route test matrix covering every record-write row below with valid bodies/seed state; each has a valid-session success characterization and a revoked-after-initial-auth denial before owner entry. Assertions compare primary and related audit/history tables, allowing no last-activity change from a dependency override. Add a registration inventory assertion that every current POST/PUT/DELETE/PATCH route has an explicit protected/public/read-only classification; include audit-producing GET routes.
- [ ] Run `python -m pytest regression_tests/test_session_write_routes.py regression_tests/test_session_restore_ordering.py -q`: expected GREEN after conversions. Any newly discovered write path must be added to coverage and receive a failing-before-fix regression; do not hide it under a broad exemption.
- [ ] Compare full OpenAPI against `/tmp/session-write-openapi-baseline.json`; expected exact equality. Run `python -m pytest -q`, `node --test regression_tests/*.cjs`, `python -m compileall -q backend main.py database_restore.py stock_counts.py replenishment.py`, `git diff --check`: expected all pass. Commit remaining coverage/tests `test: prove authenticated write route coverage`.

## Task 7: Independent Review and Selected-file PR

- [ ] Request one fresh independent whole-branch review against this plan, approved spec, coverage inventory and ledger, with all five Review Focus lines. Regrade by user effect; fix Critical/Important findings in one RED→GREEN pass with full-suite validation, and ledger deferred minors/rulings. No per-task subagents or second review.
- [ ] Verify fresh remote main and selected-file baselines, preserving upstream work. Publish only reviewed source/test/spec/plan/coverage files; inspect final commit file list/diff. Open one PR describing the original race, transaction ordering, actual checks and remaining public-auth/VACUUM/external-side-effect limits. Do not merge or deploy.

## Protected Route Inventory

All paths below are exact, relative to `/api`; comma-separated verbs apply to that same path. Replace grouping with explicit individual rows in `docs/session-write-coverage.md` during Task1.

| Task | Paths and verbs | Transaction owner |
|---|---|---|
| 2 | POST `/inventory/consume`, `/inventory/add`, `/inventory/transfer`, `/inventory/import-balances`; PUT `/inventory/update`, `/inventory/minimum`; POST `/inventory/transfers/{transfer_id}/receive`, `/inventory/transfers/{transfer_id}/return`, `/inventory/count-confirm` | Main guarded owner; injected guarded owner for count/minimum; import uses its preserved busy detail |
| 2 | DELETE `/users/{target_user_id}`, `/stores/{store_id}`, `/parts/{part_id}`; POST `/users/{target_user_id}/restore`, `/stores/{store_id}/restore`, `/parts/{part_id}/restore` | Guarded archive helper |
| 3 | POST `/users`, `/stores`, `/stores/bulk-import`, `/store-types`, `/parts`, `/parts/bulk-import`; PUT `/users/{target_user_id}`, `/stores/{store_id}`, `/store-types/{type_id}`, `/parts/{part_id}`; DELETE `/store-types/{type_id}` | Main guarded owner |
| 3 | POST `/equipment`, `/equipment/{equipment_id}/transfer`, `/equipment/{equipment_id}/calibrate`; PUT `/equipment/{equipment_id}`, `/settings/calibration-reminder-days`; DELETE `/equipment/{equipment_id}` | Main guarded owner |
| 4 | PUT `/profile`; POST `/profile/change-password`, `/auth/revoke-other-sessions`, `/auth/sessions/revoke-all`, `/auth/logout`; DELETE `/auth/sessions/{session_id}` | Main guarded owner |
| 4 | DELETE `/logs/activity/cleanup`; POST `/superadmin/users/{target_id}/reset-password`, `/superadmin/unlock-account`, `/superadmin/unlock-accounts/bulk`, `/superadmin/sessions/force-logout`, `/superadmin/sessions/force-logout-all`, `/superadmin/announcement`; PUT `/superadmin/security-config/{key}`, `/superadmin/users/{target_id}/role`; DELETE `/superadmin/database/logs/purge`, `/superadmin/announcement` | Main guarded owner |
| 5 | POST `/superadmin/database/restore` | Existing restore owner with mandatory HTTP validation callback |
| 4 | POST `/superadmin/database/query`, `/superadmin/database/vacuum`; GET `/superadmin/database/backup` and decorated authenticated reads | Record audit only uses guarded standalone owner; operation boundaries unchanged |
| 1 | Session last-activity update during any real `get_current_user` invocation | Short owning transaction validates exact token before updating its session row |

Public `/auth/login`, `/forgot-password`, `/reset-password` remain outside session revalidation. Count preview and report/export/read routes remain read-only unless they emit database activity, in which case their activity writer follows Task4. Inspect actual registered routes to catch aliases or additional operations before declaring inventory complete.

## Execution Handoff

Review this plan before implementation. Continue with the existing native execution preference: one implementer retains the connected transaction/permission interfaces, then one fresh independent reviewer checks the complete branch. No production access is required.

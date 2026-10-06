# Superadmin Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the existing 22 superadmin operations and nine schemas out of `main.py` without changing behaviour.

**Architecture:** An explicit-dependency router factory preserves the existing `/api/superadmin` prefix and `superadmin` tag. Shared guards and owners remain in `main.py`; runtime connection/path/permission/audit collaborators resolve through late-bound callbacks. Existing restore module resolution remains inside the restore handler.

**Tech Stack:** FastAPI, Pydantic, SQLite, pytest and existing Node regression tests. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-06-superadmin-extraction-design.md`

## Global Constraints

- Preserve the complete OpenAPI document and existing behaviour, including permissions, session revalidation, transaction ownership, audits, uploads, downloads and maintenance operations.
- Do not access production data, change the schema/UI, merge or deploy.
- Preserve both security-config registrations, their order, signature, query/body requirements, permissions, CSRF and writer behaviour.
- GET `/announcement` currently has no authentication dependency despite its docstring. Preserve its existing public access and response.
- Do not capture `DATABASE` at registration: dashboard, backup, restore and VACUUM must resolve the current path at request time.
- Borrowed activity logging forwards positional/keyword arguments, including `conn`, without dropping transaction ownership.
- Extracted modules never import `main`, create environment settings, configure loggers, initialise databases or open connections at import time.
- No migration, new privilege, authentication-policy change, SQL-policy redesign, connection-lifecycle repair, datetime cleanup, external-effect redesign or UI change belongs to this PR.
- Native execution with one independent final whole-branch review; no per-task agents or second review.

## Review Focus

1. Database path/helper replacement after router registration must reach dashboard, backup, restore and VACUUM; Task2 tests disposable database switching and collaborator calls.
2. Guard and activity callbacks must forward the owner's exact connection, including positional calls; Task2 proves identity and audit rollback without an extra writer.
3. Restore must validate original token, actor and current role on the locked target before snapshot/change, even when restored IDs match; Task2 reruns existing real-order and reused-ID tests.
4. GET `/security-config` remains an alias of the writer, while GET `/announcement` remains public; Task2 pins both actual HTTP behaviours without silently correcting them.
5. Nested factory functions, moved schemas and borrowed guards must preserve OpenAPI, dependency identity and import isolation; Tasks1/2 compare complete contracts and test inert imports.

## Files and Interfaces

Create `backend/schemas/superadmin.py`, `backend/routes/superadmin.py`, and `regression_tests/test_superadmin_router.py`. Modify `main.py`. Include approved spec/plan in the PR. Adapt existing tests only for a demonstrated moved-handler consumer; do not weaken assertions.

The schema module exports unchanged `SystemSettingUpdate`, `AccountUnlockRequest`, `BulkUnlockRequest`, `SecurityConfigUpdate`, `DatabaseQueryRequest`, `UserRoleUpdate`, `ForceLogoutRequest`, `SystemAnnouncementRequest`, `SuperadminPasswordReset`. `main.py` imports/re-exports these same classes, including unused ones.

The route module exports:

```python
def create_superadmin_router(*, get_connection, database_path, authenticated_writer,
                            current_user, csrf_dependency, superadmin_guard,
                            password_hash, activity_log, authenticated_activity,
                            database_defaults, session_validator) -> APIRouter:
    ...
```

`get_connection()` returns the current configured connection; `database_path()` returns current `main.DATABASE`; `authenticated_writer(user_id, session_token)` returns the existing guarded owner; `superadmin_guard(user_id, conn=None)` preserves the optional borrowed connection. `password_hash(password)`, `activity_log(*args, **kwargs)`, `authenticated_activity(user_id, token, **kwargs)`, `database_defaults()`, and `session_validator(conn, token, *, expected_user_id=None)` delegate late-bound helpers. Pass the actual shared `get_current_user` and `verify_csrf` as `current_user`/`csrf_dependency`, without wrapper identities.

Import `PROTECTED_AUDIT_SQL` from its existing module. Preserve the restore handler's local import from `database_restore`, so patched restore functions remain effective. No handler compatibility aliases unless a real consumer is found.

## Task 1: Extract Superadmin Schemas

**Files:** Create schema module and new test module; modify `main.py` schema imports/definitions.

**Interfaces:** Consumes nine current definitions; produces their unchanged classes for Task2.

- [ ] Verify isolated workspace and clean branch; capture complete OpenAPI and nine schema contracts with root `conftest.py` disposable bootstrap into this plan's ignored workspace. Resolve absolute paths before bootstrap changes cwd. Run `PYTHONPATH=/workspace/scratch/22e193396fd5/import-venv/lib/python3.12/site-packages python -m pytest -q`; expected all pass, record actual result.
- [ ] Add `test_superadmin_schemas_preserve_identity_and_contract`: for each name assert `getattr(main,name) is getattr(superadmin_schemas,name)` and `model_json_schema()` equals the captured baseline. Assert `DatabaseQueryRequest(sql='SELECT 1').params == []`, a second instance has an independent list, `SystemAnnouncementRequest(message='x').level == 'info'`, and unspecified `SecurityConfigUpdate` values are `None`.
- [ ] Run the new schema test with the same PYTHONPATH. Expected RED: absent schema module.
- [ ] Move all nine definitions unchanged to `backend/schemas/superadmin.py`, keeping `List`, `Optional` and BaseModel imports; replace definitions with imports in `main.py`. Retain `require_superadmin` unchanged.
- [ ] Run new schema test plus `regression_tests/test_session_write_routes.py` and `regression_tests/test_database_restore.py`. Expected all pass. Compare complete OpenAPI with baseline: exact equality. Commit as `refactor: extract superadmin schemas`.

## Task 2: Extract Router with Preserved Privileged Boundaries

**Files:** Create route module; modify `main.py` and new test module.

**Interfaces:** Consumes Task1 classes and named dependencies above; produces the registered router for Task3.

- [ ] Inventory the spec's 22 actual method/path operations against existing HTTP tests. Reuse current valid/revoked privileged-mutation cases, changed-role checks, SQL/VACUUM/backup audit cases, protected-log retention, upload validation, and all restore ordering/identity cases.
- [ ] Add `test_superadmin_security_config_get_alias`: GET without required key/body returns422; GET with query `key=max_login_attempts` and JSON `{'value':'7'}` reaches the same update handler as PUT, returns its existing success payload, persists setting/audit under a valid superadmin session, and returns401 without changes when the original token is revoked before its writer. Use disposable data and a real Request.
- [ ] Add `test_superadmin_announcement_remains_public`: no session cookie or auth override is needed to read an existing announcement; verify exact response and `{'announcement':None}` when absent. Do not add authentication.
- [ ] Add parametrized `test_superadmin_read_routes_preserved` for dashboard, locked-accounts, sessions, users, database/tables and audit-log: seed identifiable rows, assert existing response fields/data and403 for an engineer. Add SQL-query test for500-row cap and rejection of non-SELECT/forbidden statements, retaining parameter behaviour.
- [ ] Add `test_superadmin_dynamic_database_paths`: switch `main.DATABASE` between two disposable databases after registration; dashboard file-size data, downloaded SQLite content, VACUUM return sizes and restore destination must reflect the current path. For restore destination observation, patch the actual `database_restore.restore_database` function with a recorder and return a synthetic backup name; existing real restore tests separately prove its safeguards. Use pytest tmp paths for any backup files and avoid leaving `/tmp` artifacts.
- [ ] Add `test_superadmin_callbacks_keep_borrowed_connection`: patch `main.require_superadmin` and `main.log_activity` with recording wrappers around their originals; invoke a privileged mutation and assert both receive the same active owner connection. Inject an activity INSERT trigger failure and assert the setting/write is rolled back, the original connection closes/releases its lock, and no standalone audit writer is called. Exercise runtime password hashing, defaults and session-validator replacement through reset/restore callbacks as appropriate.
- [ ] Add explicit HTTP restore upload-cap coverage if absent: more than20MB returns413 `Maximum database size is 20 MB` before restore executes; retain invalid-header400 and all existing success/error/status/cookie tests. All uploaded databases are disposable.
- [ ] Run the new behaviour characterizations before moving handlers. Expected GREEN; compare any failed assumptions to actual existing responses before changing product code.
- [ ] Add `test_superadmin_routes_owned_once_by_extracted_router`: exact22 operation set matches spec; each registered once with tag `superadmin`; GET/PUT security-config share the same endpoint; scoped endpoint modules equal `backend.routes.superadmin`; retained regular user administration stays in `main`.
- [ ] Add `test_superadmin_dependency_override_identity`: inspect actual auth/CSRF dependencies and exercise their existing overrides without bypassing the cookie revalidation owner. Add `test_superadmin_imports_are_inert`: subprocess imports only new schema/router modules from empty cwd; assert no `main` import, cwd change, settings/database/log creation.
- [ ] Run new ownership/isolation tests. Expected RED: unextracted handlers and absent route module.
- [ ] Implement `create_superadmin_router(...)` with exact signature above, prefix `/api/superadmin`, tags `['superadmin']`. Move21 handlers/22 registrations unchanged, including stacked security-config decorators and public announcement. Use local collaborator aliases to minimise body changes; replace each existing `DATABASE` reference with `database_path()` without changing when it resolves. Preserve guard/audit `conn` forwarding and locked restore callback. Preserve names, signatures and decorator order.
- [ ] Compose the router in `main.py` at the existing include location, with late-bound callbacks for all runtime collaborators; retain actual auth/CSRF dependency identity. Remove the original router/models/handler definitions but keep shared helpers, imported schemas and `require_superadmin` available. Do not alter regular admin-only policies or other router composition.
- [ ] Run `python -m pytest regression_tests/test_superadmin_router.py regression_tests/test_auth_router.py regression_tests/test_session_write_routes.py regression_tests/test_session_restore_ordering.py regression_tests/test_database_restore.py regression_tests/test_restore_concurrency.py regression_tests/test_stock_audit.py -q` with established PYTHONPATH. Expected all pass. Compare complete OpenAPI exactly and inspect moved bodies for only dependency/path-access changes. Commit as `refactor: extract superadmin routes`.

## Task 3: Complete Validation, Independent Review and PR

**Files:** Reviewed source/tests/spec/plan only; ignored execution ledger/review package remain local.

**Interfaces:** Consumes Task2 router and baseline evidence; produces one verified PR on current remote main.

- [ ] Run full `python -m pytest -q` with established PYTHONPATH and `node --test regression_tests/*.cjs`. Expected all pass; record actual counts/warnings. Run `python -m compileall -q backend main.py` and `git diff --check`; expected exit0. Reconfirm complete OpenAPI exact equality.
- [ ] Request one fresh independent whole-branch review with approved spec, plan, full diff, all five Review Focus lines and ledgered rulings. Fix Critical/Important findings in one RED→GREEN pass and rerun full checks; ledger Minor findings for the user. No second reviewer.
- [ ] Verify fresh remote main includes merged PR53 and matches selected-file baselines. Reconcile overlapping upstream edits in isolation and rerun affected checks before publishing. Publish only reviewed selected source/test/spec/plan files; verify final commit file list and exact published `main.py` content.
- [ ] Open one PR explaining the extraction, preserved alias/public access, transaction/restore boundaries, actual checks and unchanged limits. Verify head/base and mergeability. Do not merge, deploy or access production data.

## Execution Handoff

Preserve native execution with one independent final review. Begin implementation only after the user reviews and approves this written plan.

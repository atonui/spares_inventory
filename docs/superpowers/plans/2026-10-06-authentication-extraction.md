# Authentication Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move 14 authentication/profile/session operations and six schemas out of `main.py` without changing behaviour.

**Architecture:** An explicit-dependency router factory follows the existing work-order router pattern. Shared helpers and dependency identities remain in `main.py`, which imports schemas and composes the router using late-bound runtime callbacks.

**Tech Stack:** FastAPI, Pydantic, SlowAPI, SQLite, pytest, existing Node regression tests. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-06-authentication-extraction-design.md`

## Global Constraints

- No production database access, migration, UI change or deployment is required.
- No module in this extraction imports `main`.
- Shared dependencies remain in `main.py` for this PR so other routers keep the same dependency identity and existing override support.
- Preserve response models, schema names, route metadata, decorator ordering and registration semantics.
- Do not add tags or prefixes that alter the API contract.
- Protected mutations continue to pass the original cookie token and actor ID into the existing authenticated transaction owner.
- No nested writer, extra commit, connection close, or standalone audit call is introduced inside that owner.
- Publish a selected-file PR on verified current remote main; preserve upstream work, including merged PR52. Do not merge or deploy.
- Native execution is the preserved preference: one implementer, one independent final review, no per-task agents.

## Review Focus

1. Runtime replacement of database/email/hash/audit collaborators must reach the registered handlers; Task2 pins late binding with HTTP tests.
2. Actual Request objects, nested router functions and repeated failed attempts must preserve SlowAPI limits and decorator signatures; Task2 pins all three public limits.
3. Shared dependency overrides and request schema names must remain identical across extracted and retained routes; Tasks1/2 pin class identity, override keys and complete OpenAPI.
4. Revocation or archiving between initial authentication and the writer lock must still reject writes atomically; Task2 runs the existing session-write and archive race suites unchanged.
5. Importing router/schema modules in an empty directory must neither load the application nor create settings, databases or log files; Task2 pins isolated subprocess imports.

## Files and Interfaces

Create `backend/schemas/auth.py`, `backend/routes/auth.py`, and `regression_tests/test_auth_router.py`. Modify `main.py`. Adjust existing tests only if a direct moved-handler consumer requires it; keep assertions. Spec and this plan accompany the PR.

`backend.schemas.auth` produces the unchanged classes `UserProfileUpdate`, `PasswordChange`, `ForgotPasswordRequest`, `ResetPasswordRequest`, `UserLogin`, `UserResponse`. `main.py` re-exports them through imports for existing consumers.

`backend.routes.auth` produces:

```python
def create_auth_router(*, get_connection, authenticated_writer, current_user,
                       csrf_dependency, csrf_token_factory, password_hash,
                       password_verify, security_config, reset_email,
                       activity_log, endpoint_log, mutation_activity,
                       limiter, logger, cookie_secure) -> APIRouter:
    ...
```

`get_connection()` returns the current application's SQLite connection. `authenticated_writer(user_id, session_token)` returns its existing guarded context manager. `current_user` and `csrf_dependency` are the actual shared dependency callables, not wrappers. `csrf_token_factory()`, `password_hash(password)`, `password_verify(plain, hashed)`, `security_config()`, `reset_email(email, token)`, `activity_log(**kwargs)`, `mutation_activity(conn, user_id, action, resource_type, result, request)`, and `cookie_secure()` are late-bound composition callbacks. `endpoint_log(...)`, limiter and logger reuse existing objects; keep logout's existing decorator and borrowed audit interaction. Local aliases can preserve endpoint bodies and names.

## Task 1: Extract Schemas with Existing Contracts

**Files:** Create `backend/schemas/auth.py`, `regression_tests/test_auth_router.py`; modify schema definitions/imports in `main.py`.

**Interfaces:** Consumes the six existing class definitions; produces the exact shared classes listed above for Task2.

- [ ] Capture baseline complete OpenAPI using the root `conftest.py` disposable bootstrap; save JSON in this plan's ignored workspace. Resolve paths via `__file__`/absolute paths because bootstrap changes cwd. Run `PYTHONPATH=/workspace/scratch/22e193396fd5/import-venv/lib/python3.12/site-packages python -m pytest -q`. Expected: all tests pass; record actual count/output.
- [ ] Add `test_auth_schemas_preserve_identity_and_contract`: for each of the six class names assert `getattr(main,name) is getattr(auth_schemas,name)` and `model_json_schema()` equals the captured original schema; assert login defaults `remember_me=False`, profile accepts omitted email, and invalid EmailStr input remains rejected.
- [ ] Run `python -m pytest regression_tests/test_auth_router.py::test_auth_schemas_preserve_identity_and_contract -q` with the same PYTHONPATH. Expected: RED because the new module does not exist.
- [ ] Move the six class definitions verbatim to `backend/schemas/auth.py`; import them into `main.py`. Preserve Pydantic field declarations, class names and nullability. No other model moves.
- [ ] Run the focused schema test plus `regression_tests/test_security_transactions.py` and `regression_tests/test_session_write_routes.py`. Expected: all pass. Compare entire OpenAPI to baseline: exact equality.
- [ ] Commit schema module, imports and tests as `refactor: extract authentication schemas`.

## Task 2: Extract Router and Preserve Runtime Dependencies

**Files:** Create `backend/routes/auth.py`; modify `main.py` and `regression_tests/test_auth_router.py`.

**Interfaces:** Consumes Task1's schemas and the factory dependencies above. Produces the registered authentication router for Task3's verification and review.

- [ ] Inventory existing HTTP coverage against the spec's 14 operations. Add behaviour characterization tests only where missing: successful login/session cookie, remember-me versus normal expiry, failed login/lockout, valid/expired/used reset token, reset email callback, profile update, logout cookie/audit, and session list/revocation. Each test asserts status/detail/response and relevant disposable database state rather than source text. Run characterization before extraction: expected GREEN on existing routes.
- [ ] Add `test_auth_routes_owned_once_by_extracted_router`: exact method/path set equals the spec table, each registered once, scoped endpoint modules equal `backend.routes.auth`, and retained administration endpoints remain in `main`.
- [ ] Add `test_auth_dependencies_keep_override_identity`: inspect FastAPI dependency callables for protected/CSRF routes and exercise HTTP overrides on the supplied callables; assert override works without bypassing the authenticated write token check.
- [ ] Add `test_auth_runtime_collaborators_are_late_bound`: replace `main.DATABASE` between profile requests on two disposable databases; patch `main.verify_password`/`main.hash_password` and assert login/reset reach replacements; patch `main.send_reset_email` and `main.log_activity` and assert password-recovery uses replacements; toggle `main.settings.COOKIE_SECURE` between login requests and assert Secure cookie attribute changes.
- [ ] Add parametrized `test_auth_public_rate_limits_preserved`: reset the shared limiter between cases; submit valid request shapes repeatedly from one client, using non-existent login/account/token values to avoid external effects; expect the sixth login (`5/minute`), fourth forgot-password (`3/hour`), and sixth reset-password (`5/hour`) request to return 429. Do not override the limiter; supply a real CSRF token where required.
- [ ] Add `test_auth_backend_imports_are_inert`: subprocess imports only new router/schema modules from an empty temporary cwd; assert `main` not in `sys.modules`, cwd unchanged and no files created. Use repository absolute PYTHONPATH; do not import test bootstrap in that subprocess.
- [ ] Run new router ownership/isolation tests first. Expected RED against unextracted code. Run behaviour/late-binding/limit characterizations separately and record actual baseline outcomes; where an assertion reveals existing behaviour rather than extraction failure, compare it to the approved preservation requirement before changing anything.
- [ ] Implement `create_auth_router(...)` with the exact signature above. Move only the 14 operations from the spec, preserving endpoint names, signatures, docstrings, decorators and body behaviour. Rename only dependency references; use `cookie_secure()` when setting cookies. Import standard-library/framework objects locally in this module without application initialization.
- [ ] Compose the router once in `main.py` with late-bound callbacks resolving its global helpers at call time. Pass actual `get_current_user`/`verify_csrf`, shared limiter/logger and endpoint decorator. Remove original route definitions; retain helpers. Do not create duplicate handlers or compatibility aliases without an actual direct consumer.
- [ ] Run `python -m pytest regression_tests/test_auth_router.py regression_tests/test_security_transactions.py regression_tests/test_archiving_integrity.py regression_tests/test_session_write_routes.py regression_tests/test_session_restore_ordering.py -q` with the established PYTHONPATH. Expected: all pass, including existing stale-session, role and archived-user assertions unchanged.
- [ ] Compare complete OpenAPI with baseline again. Expected exact equality, including operation IDs, schema references and route metadata. Commit as `refactor: extract authentication routes`.

## Task 3: Full Validation, Independent Review and PR

**Files:** Reviewed source/tests/spec/plan only; ignored execution ledger and review package remain local.

**Interfaces:** Consumes registered Task2 router and baseline evidence; produces one reviewed PR against current remote main.

- [ ] Run `python -m pytest -q` with the established PYTHONPATH. Expected all tests pass; record actual count and warnings. Run `node --test regression_tests/*.cjs`; expected all tests pass. Run `python -m compileall -q backend main.py` and `git diff --check`; expected exit0. Confirm complete OpenAPI exact equality.
- [ ] Request one fresh independent whole-branch review against approved spec, this plan, full diff and execution rulings, including all five Review Focus lines. Fix Critical/Important findings in one RED→GREEN pass and rerun full validation; ledger Minor findings for the user. No per-task agents or second review.
- [ ] Verify fresh remote main and pre-existing selected-file baselines. If upstream overlaps, reconcile in isolation and rerun affected checks before publication. Publish only reviewed source/test/spec/plan files; inspect final commit and compare published `main.py` to reviewed content.
- [ ] Open one PR describing unchanged behaviour, explicit dependency boundary, actual test counts and exact OpenAPI comparison. Verify PR head/base and mergeability. Do not merge, deploy or access production data.

## Execution Handoff

Retain native execution with one independent final review. Implementation starts after the user reviews and approves this written plan.

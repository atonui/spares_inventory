# Superadmin route extraction

## Intent and success criteria

Continue backend organisation after the merged authentication extraction, PR53. Move the existing superadmin section out of `main.py` so privileged operations are easier to locate and review. The user approved extracting this section separately from regular user administration, and preserving the existing security-config GET behaviour during the move.

Success means 22 method/path operations live in a focused route module, their nine models live in a schema module, and `main.py` composes the router. Preserve the complete OpenAPI document and existing behaviour, including permissions, session revalidation, transaction ownership, audits, uploads, downloads and maintenance operations. Do not access production data, change the schema/UI, merge or deploy.

## Approach and responsibilities

Follow the authentication and work-order router factory pattern with explicit dependencies. Move existing handlers with minimal dependency-reference changes. No new dependency container, application singleton, service hierarchy or authentication framework.

- `backend/routes/superadmin.py`: `create_superadmin_router(...)` registers the existing operations using prefix `/api/superadmin` and tags `['superadmin']`.
- `backend/schemas/superadmin.py`: move `SystemSettingUpdate`, `AccountUnlockRequest`, `BulkUnlockRequest`, `SecurityConfigUpdate`, `DatabaseQueryRequest`, `UserRoleUpdate`, `ForceLogoutRequest`, `SystemAnnouncementRequest`, and `SuperadminPasswordReset` unchanged, including currently unused schemas.
- `main.py`: import/re-export these schemas and include the router once at its existing registration location. Retain `require_superadmin(user_id, conn=None)` and shared authentication, CSRF, transaction, database, configuration and logging helpers.
- Regression tests: focused extraction and behaviour checks, reusing existing HTTP/race coverage and preserving its assertions.

Moving regular administration at the same time would widen the regression surface. Moving only helpers would leave most endpoint code in `main.py`. The existing superadmin router is the first cohesive administration boundary.

## Exact route scope

Paths below are relative to `/api/superadmin`.

| Method | Path |
|---|---|
| POST | `/users/{target_id}/reset-password` |
| GET | `/dashboard` |
| GET | `/locked-accounts` |
| POST | `/unlock-account` |
| POST | `/unlock-accounts/bulk` |
| GET | `/sessions` |
| POST | `/sessions/force-logout` |
| POST | `/sessions/force-logout-all` |
| GET | `/security-config` |
| PUT | `/security-config/{key}` |
| GET | `/users` |
| PUT | `/users/{target_id}/role` |
| GET | `/database/tables` |
| POST | `/database/query` |
| GET | `/database/backup` |
| POST | `/database/restore` |
| POST | `/database/vacuum` |
| DELETE | `/database/logs/purge` |
| POST | `/announcement` |
| DELETE | `/announcement` |
| GET | `/announcement` |
| GET | `/audit-log` |

There are 21 handlers and 22 method/path registrations. The existing GET `/security-config` decorator attaches to `update_security_config`, alongside PUT `/security-config/{key}`. Preserve both registrations, their order, signature, query/body requirements, permissions, CSRF and writer behaviour. Do not silently replace GET with a new read handler. Characterize this explicitly; correction is a separate task.

GET `/announcement` currently has no authentication dependency despite its docstring. Preserve its existing public access and response; do not add a guard during extraction.

## Dependency boundary

The factory receives named collaborators for connection acquisition, current database path, authenticated writer ownership, current-user and CSRF dependencies, superadmin checks, password hashing, borrowed activity logging, guarded standalone authenticated activity, database defaults, and exact-token session validation. Import standard-library/framework objects and the existing stock-audit protection constant directly without application initialization.

Use the actual shared `get_current_user` and `verify_csrf` functions in `Depends`, retaining override identity. Keep runtime helpers late-bound through callbacks in `main.py`, including database path and connection acquisition. Do not capture `DATABASE` at registration: dashboard, backup, restore and VACUUM must resolve the current path at request time. Preserve path resolution timing within each existing operation rather than introducing a new snapshot convention.

The injected superadmin guard accepts both `user_id` and optional borrowed `conn`, retaining its cursor-local row mapping and connection ownership. Borrowed activity logging forwards positional/keyword arguments, including `conn`, without dropping transaction ownership. Keep `database_restore.restore_database` resolved through the existing restore module; existing concurrency tests that patch it must remain effective.

Extracted modules never import `main`, create environment settings, configure loggers, initialise databases or open connections at import time. Router creation registers routes only. Do not create aliases for every moved handler; expose an existing registered handler only if an actual direct consumer requires compatibility.

## Behaviour and safety preservation

Protected record mutations still receive the original actor and cookie token in the authenticated owner. Current superadmin role checks and their writes/audits share that connection after the writer lock. Preserve role-change rules, reset-password behaviour, session termination, unlock counts, settings validation, announcements, protected audit retention and exact error responses.

Restore keeps its existing early superadmin check, 20 MB upload cap, SQLite header check and exception/status mapping. Its callback must validate the original session token and actor ID and current superadmin role on the locked target connection before recovery snapshot creation or live changes. Preserve cookie deletion and the sign-in-again response. Retain both restore-first and write-first ordering guarantees and trusted offline restore behaviour.

Read-only SQL keeps its SELECT/keyword checks, parameters, 500-row cap, response and guarded standalone audit. Backup remains a consistent SQLite backup with the existing filename/content disposition. VACUUM and file effects retain their existing boundaries; do not claim they become session-atomic. Guarded standalone audit checks remain in place.

No migration, new privilege, authentication-policy change, SQL-policy redesign, connection-lifecycle repair, datetime cleanup, external-effect redesign or UI change belongs to this PR.

## Verification and delivery

Capture complete OpenAPI and all nine schema contracts before extraction under the disposable test bootstrap. Inventory actual registrations and existing tests. Add missing behaviour characterization before moving code, concentrating on read endpoints, the security-config GET alias, public announcement access, database path changes, upload/backup behaviour and collaborator forwarding.

Use tests that prove exactly one registration of every operation, ownership by the extracted module, unchanged dependency identity, inert imports and preserved schema identity. Run existing session-write, restore, archive and audit protections unchanged. Preserve the currently narrower regular admin-only policies, as those routes remain outside this extraction.

After extraction, compare complete OpenAPI for exact equality and run full Python/JavaScript suites, compilation and whitespace checks. All databases and file effects used for testing are disposable. Never import the application without the established safe test configuration.

Use native execution with one independent final whole-branch review. Review priorities are late-bound database paths and callbacks, borrowed permission/audit connections, locked restore validation, the security-config alias and public announcement, and OpenAPI/schema/import identity. Publish only reviewed selected files against verified current remote main, preserving upstream work and merged PR53. Do not merge or deploy.

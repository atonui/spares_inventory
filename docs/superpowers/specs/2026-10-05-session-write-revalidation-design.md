# Session revalidation during authenticated writes

## Intent and success criteria

The inventory application is in daily use on Railway. Close the race where a request authenticates, database restore revokes its session, and the waiting request subsequently changes records using its earlier user ID. Protect authenticated application-record writes without changing stock behavior, role policy, schema, deployment or public request/response formats. Use disposable databases only.

The owner approved the approach: revalidate the session inside the transaction that performs the write. Invalid, expired or revoked sessions receive HTTP 401 and commit no application changes. A write that acquired the writer lock first may complete before restore; a restore that committed first prevents the waiting write. This also protects against logout, password changes and account archiving committed before a waiting write.

## Current behavior

`main.get_current_user` reads an active session and active account, updates last activity, commits, closes its connection and returns an integer user ID. Endpoints subsequently open other connections. That integer is insufficient evidence that the original session is still valid.

`stock_write_transaction` already owns `BEGIN IMMEDIATE`, commit, rollback and closure through `backend.services.stock_transactions`. Stock access and inventory helpers borrow its connection. Stock counts and replenishment receive the owning transaction through injection; balance imports own a separate explicit transaction.

`database_restore.restore_database` owns a live writer lock throughout validation, snapshot and record replacement. It revokes all sessions in restored records, but currently checks the caller's account identity/role rather than the caller's live session under that lock. Other authenticated mutation routes retain individual connection/commit patterns.

## Chosen architecture

Use explicit request credentials and an owning guarded transaction, not process-local locks or implicit global request state. Keep `get_current_user` returning the existing integer user ID. HTTP boundaries additionally obtain the existing session cookie and pass it, with that ID, into their mutation boundary. Do not log tokens or include them in errors/audits.

Add a borrowed-connection session validator in a focused backend service. It accepts the active connection, expected actor ID and session token. It verifies the exact token's active session, matching actor, expiry and an unarchived user. It neither opens a connection nor commits, rolls back or closes one. Missing/invalid/revoked/expired credentials fail closed with existing authentication-style HTTP 401 errors. No token may be replaced by a lookup of another session belonging to the same user.

An authenticated transaction owner opens the current configured database, obtains `BEGIN IMMEDIATE`, validates the session and yields that same connection. Permission and ownership checks then read current records on that connection before mutation. The owner commits on success and rolls back/closes on every failure. Preserve existing stock busy HTTP 409 behavior and defensive cleanup; non-stock busy responses must be explicit in the implementation plan. No new persistent credential storage or migration is needed.

Generic stock services remain independent of FastAPI requests and `main`. The HTTP layer constructs guarded transaction callbacks for count/replenishment modules and passes credentials explicitly into shared route helpers. Existing unguarded transaction primitives remain available for trusted internal operations/tests; every authenticated HTTP record mutation must demonstrably use the guarded boundary. There is no optional-token bypass in a protected route.

Revalidation of permissions is distinct from session validity. Read the current role, target privilege, store ownership and account archive state under the same lock. Preserve admin/superadmin visibility and existing engineer/manager ownership rules. A still-valid session whose permissions changed receives the existing appropriate HTTP 403 response.

## Coverage and boundaries

The implementation plan must enumerate all authenticated record-mutating HTTP operations and their actual transaction owner, including:

- Stock add/update/consume/transfer, transfer receipt/return confirmation and balance imports.
- Stock-count confirmation and replenishment confirmation routes registered outside the main decorator block.
- Part/store/user create, update, archive/reactivate and bulk import; store-type operations.
- Equipment creation, update, transfer, calibration and deletion; calibration reminder settings.
- Profile/password changes, logout and individual/other/all session revocation.
- Superadmin password reset, account unlock, forced logout, role changes, security settings and announcements.
- Activity/audit log cleanup or purge and authenticated database writes performed by maintenance endpoints.
- Database restore itself, as described below.

Do not infer coverage from HTTP method alone. Read-only POST database queries do not need a record-mutation transaction. Authentication's last-activity update must follow validation within its own short writer transaction so it cannot update a reused session ID after restore. Audit helpers must use the owning connection when they are part of a mutation; do not open another writer while holding the lock.

Public login, forgot-password and reset-password flows use credentials or reset capabilities rather than an authenticated session. They are outside the session-revalidation contract; retain their existing validation and behavior. This change does not claim to resolve all public authentication races.

`VACUUM` cannot run inside a SQLite transaction and does not change application records. It is outside the record-write guarantee; its authentication remains required, and any associated record/audit write must use a guarded transaction. File creation/download, email delivery and other external side effects are not made transactional by this work. Avoid adding such side effects inside the database lock. Authenticated reads are not held under a writer lock for their entire request.

## Restore integration

The restore HTTP boundary passes its session token and expected actor through a validator callback to the restore owner. Once `target` obtains `BEGIN IMMEDIATE`, and before creating the pre-restore backup or changing live records, invoke validation against that live connection and recheck current superadmin authority there. Preserve the existing uploaded-account identity requirement and snapshot/replacement logic.

Keep the offline restore utility's existing explicit trusted-call interface available to tests/tools, but the HTTP route must always supply its required live-session validator. Do not validate against the uploaded database's sessions. Uploaded sessions remain revoked in the committed replacement. An expired/revoked caller fails with HTTP 401 propagated through the route; authority loss fails with HTTP 403. Failed authorization creates no pre-restore backup and changes no live records.

## Transaction ordering and observable behavior

If an ordinary write gets the writer lock first, its session and permissions are checked against the pre-restore database and it commits or rolls back before restore acquires the lock. Restore may subsequently replace those records, as it does today; the pre-restore snapshot retains committed pre-restore state.

If restore commits first, the ordinary write acquires the lock afterward and sees revoked sessions. It rejects without changing stock, movements, audits or other application records. ID reuse in an uploaded database must not permit the original request to act as a different user. The exact original token and expected actor must match.

Long uploads and parsing take place before the writer lock; credentials and permissions are checked after that preparation, immediately inside the transaction. No request-wide writer lock, cross-worker mutex, middleware-only check or check on another connection substitutes for this boundary.

## Validation and review

Use real SQLite databases and independent connections for ordering tests. Seed minimal accounts, active/expired/revoked sessions and records; explicitly close all fixture connections. Test valid writes, absent/wrong-user tokens, expiry, archive, role/ownership changes, logout/revocation and both lock orderings. Include a restored database with reused user/session IDs and no valid original session.

Characterize existing endpoint behavior before refactoring. Exercise actual HTTP routes and their injected count/replenishment/restore boundaries, not just the new validator. A route coverage inventory must connect every protected operation to its guarded transaction and regression evidence. Ensure no protected route uses a tokenless fallback.

Verify invalid sessions roll back record changes and mutation audit/movement rows, locks release after exceptions, dynamic database-path selection remains intact, services import without initializing `main`, and restore failures leave the live database unchanged. Successful password/session revocation may invalidate the caller during its own transaction after the initial boundary check; this is intentional.

Run the complete Python and JavaScript suites, compile and whitespace checks. Compare full OpenAPI to the pre-change baseline; preserve its public schema, including cookie metadata. Obtain one independent whole-branch review focused on missed write paths, connection ownership, permission checks on separate connections, token/actor identity and restore timing. No live database or production backup is used.

## Non-goals and delivery

No JWT conversion, session schema changes, frontend redesign, general authentication/admin extraction, public-authentication redesign or unrelated stock feature work. The previously deferred fixture cleanup is separate from this change.

Deliver a selected-file PR based on verified current GitHub main. The owner merges and deploys. This written spec requires review before the detailed implementation plan; native execution remains the existing preference, followed by one independent review.

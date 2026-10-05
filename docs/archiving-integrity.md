# Archiving and database integrity

The management panels now offer **Archive** for users, stores and parts. Archiving retains the original row and its ID so movement and audit history continue to show the original references. Archived records disappear from normal lists, stock selections and active counts. Their email addresses and part numbers remain reserved; restore the existing record instead of creating another one with the same identity.

Admins and superadmins can open **Archived records** to see and restore retired records. Existing DELETE API paths now archive; POST `/api/parts/{id}/restore`, `/api/stores/{id}/restore` and `/api/users/{id}/restore` reactivate them. `include_archived=true` on the corresponding list endpoints is restricted to admins and superadmins. CSRF protection applies to every state change.

Parts and stores must have no positive stock and no pending transfer before archiving. Zero-balance rows are retained but hidden while either reference is archived. Users must have active stores and equipment reassigned and pending transfers completed. A user cannot archive their own account, and ordinary admins cannot archive or restore superadmins. Restore the assigned user before restoring a store assigned to that user.

Archived users cannot sign in, use existing sessions or obtain/verify password-reset tokens. Archive and restore both revoke sessions and clear reset credentials. Restoring an account requires a new login. Session creation rechecks account activity under the same write lock used by archiving.

## Upgrade

Startup adds an `archived_at` column to users, stores and parts and two stock-identity indexes. The unallocated index explicitly covers NULL work orders, which the previous SQLite UNIQUE rule allowed to repeat. Allocated stock retains separate rows per work order. Application connections enable foreign-key enforcement.

The migration preserves quantities and movement history. Historical audit entries with the anonymous user-ID sentinel 0 are changed to NULL only when there is no real user 0; their names and text are retained. Unknown broken references or duplicate stock keys stop the migration with identifying details rather than silently changing data. Resolve those records before deploying the upgrade. The migration can run repeatedly.

Database restore applies these known additive migrations to the temporary upload, validates references and the full schema, and requires the requesting superadmin to remain active. Older backups remain supported. A restore still replaces later data, so choose the snapshot deliberately.

No new environment variables are required. Merge the PR for the existing Railway deployment and refresh open app tabs. No production stock adjustments are required.

## Checks

Run `python -m pytest` and `node --test regression_tests/*.cjs`. Tests cover history preservation, archive restrictions, permissions and CSRF, session revocation and login races, reset credentials, FK/duplicate protection, migration refusal for unexpected data, and restore account safety. A disposable copy of the verified backup was upgraded twice and restored from the old schema without changing its 484 stock rows or 1,188 units.

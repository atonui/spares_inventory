# Stock validation patch

Based on deployed commit 95ad55a. This patch changes no database schema and performs no stock reconciliation.

- Receipts, transfers and consumption require positive JSON integer quantities.
- Adjustments allow zero but reject negative, fractional or boolean quantities.
- Transfers to the source store are rejected.
- User roles must be engineer, manager, admin or superadmin.
- Ordinary admins cannot create a superadmin, promote another account to superadmin, or edit/delete an existing superadmin. Superadmins retain user-management access.
- Existing store-access rules remain unchanged pending workflow confirmation.
- The Add Stock form converts its input to a JSON number.

## Tests

Use Python 3.12 and Node.js (for the existing frontend function regression).
Install `requirements-dev.txt`, then run `python -m pytest` from the repository root.
Optional: set `INVENTORY_TEST_BACKUP` to the absolute path of a SQLite backup to run tests on disposable restored copies. Never commit the backup.
Test settings, logs, users and stock are created in temporary directories. Authentication and CSRF dependencies are overridden only in tests; this suite does not verify the login flow.
The pre-existing store-type test is diagnostic rather than assertion-based.

## Release

Confirm `/data/inventory.db` is on the Railway volume and take a fresh live backup before deploying. Smoke-test receipt, transfer, consumption, adjustment and user administration. The patch intentionally leaves existing duplicate rows intact.

Rollback the application commit if needed; no schema rollback is required. Do not restore an older database over stock changes made since release.

Known pre-existing limitations remain: duplicate unallocated stock rows, missing ownership checks on stock changes, startup migration indentation, disabled foreign key enforcement, and dependency deprecation warnings. This is a focused patch, not a complete security fix.

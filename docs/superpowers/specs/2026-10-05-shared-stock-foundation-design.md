# Shared stock-service foundation

## Intent and staging

Continue organising the live inventory backend through small PRs. Stock mutations already share stock_write_transaction, require_active_record, require_stock_access and add_inventory_quantity in main.py. The first stock-services PR extracts these existing responsibilities into focused backend services, preserves compatibility for current callers and makes transaction ownership explicit. It introduces no feature, database migration, new dependency or permission expansion.

The restore snapshot-to-replacement write gap was fixed in PR49. A request authenticated before restore can still begin writing after restore completes. This foundation extraction does not solve that request-level race. The subsequent safety PR must revalidate the authenticated session/actor under the acquired write lock across every affected stock-writing path; it must not merely recheck whether a user ID exists. This needs an explicit authentication-to-write context and its own reviewed design and tests.

After the foundation and session safety work, move individual stock business operations out of main.py in small groups, retaining transaction-local movement and audit evidence. Transfer dispatch/receipt/return is a separate group because its lifecycle differs from immediate stock changes. Authentication/administration organisation remains a later stage.

## Approaches

1. Recommended: extract the existing transaction, record/access checks and inventory identity helper first, using dynamic main.py wrappers as a compatibility boundary. This is a contained foundation for subsequent operation extraction and session safety work.
2. Move every stock endpoint and all business logic together. This removes more of main.py but increases the regression surface across imports, counts, replenishment, archiving and transfers.
3. Introduce a repository/ORM abstraction. This adds dependencies and another database model without helping the current sqlite3 transaction guarantees.

Use approach1. Keep the existing registration interfaces for stock_counts.py, replenishment.py and other callers unchanged in this PR.

## Responsibilities and interfaces

- backend/services/stock_transactions.py: write_stock_transaction(get_connection) is a context manager. It opens one connection, acquires BEGIN IMMEDIATE before callers inspect or change stock, yields it, commits once on success, rolls back on failure and always closes. Busy/locked OperationalError handling retains HTTP409 and the existing message: Stock is busy; no changes saved. Try again. No application import or captured database path.
- backend/services/stock_access.py: require_active_record(conn, table, identifier) retains the users/stores/parts allowlist, missing/archived record checks and existing HTTP400 responses. require_stock_access(conn, user_id, store_type, store_owner) retains admin/superadmin, owner and central-store access and the HTTP403 Permission denied for this store response. Neither borrowed-connection helper opens, commits or closes its supplied connection.
- backend/services/inventory.py: add_inventory_quantity(conn, store_id, part_id, quantity, work_order_id) retains existing NULL/numeric work-order identity matching, single-row reuse, updated_at behaviour and returned row ID. It uses the extracted active-record checks. To retain the existing direct-caller contract, it acquires BEGIN IMMEDIATE only when conn.in_transaction is false, but never commits or closes. Do not silently redefine quantity validation or allocation rules; routes already supply validated quantities and current callers retain those responsibilities.
- main.py: preserve stock_write_transaction(), require_active_record(...), require_stock_access(...) and add_inventory_quantity(...) as thin compatibility wrappers. The transaction wrapper supplies main.get_db_connection at call time so main.DATABASE overrides keep working. Do not duplicate implementation or capture the path/function too early. Existing injected route registrations continue receiving these wrappers.

Compatibility wrappers preserve existing callable names and signatures. No backend service imports main.py. No unused generic repository, dependency registry or future authentication framework is introduced.

## Connection ownership correction

The current require_stock_access closes the caller's connection before raising HTTP403, forcing the transaction wrapper to tolerate a failed rollback on a closed connection. The extracted borrowed-connection helper must leave it open. The owning write context performs rollback and closure. This is an intentional internal ownership correction; the user-facing403 response and lack of persisted changes remain the same. Retain defensive cleanup compatibility until all current callers and existing failure-injection tests are understood; do not erase it solely because the new helper no longer closes connections.

## Preserved behaviour

Stock, movement and audit writes remain committed together by existing callers. The new services do not introduce independent commits or audit records. Existing stock-count/import/replenishment/archiving/transfer checks and validation order remain intact. SQLite write exclusion remains cross-process; do not replace it with a process-local mutex.

All URLs, response models, authentication dependencies, store permissions, transfer semantics, SQLite schema and uvicorn main:app remain unchanged. Stock mutation endpoint bodies stay in main.py in this foundation PR. Reports, work-order listing and UI remain unchanged.

## Verification

Characterise the existing transaction commit/rollback/busy response, dynamic database path and inventory identity helper with real disposable SQLite connections. Test exact row reuse for unallocated stock and equivalent numeric work-order IDs, return IDs, active-record rejection and shared audit/movement rollback.

Before implementation, add failing service-level tests proving borrowed connections remain open after access rejection and that the owner still rolls back all prior mutations. Test newly extracted services in isolation without importing or initializing main.py. Include two independent connections to prove the shared write context still excludes concurrent writers; use short test-specific connection timeouts rather than production-length sleeps.

Run existing stock safety, security/atomic writes, transfers, audit, archiving, imports, counts and replenishment regressions, then the complete Python and JavaScript suites. Compare the full OpenAPI document with a disposable baseline. Compile changed modules, check whitespace and request one fresh independent review. Publish only reviewed selected files against freshly verified GitHub main. No live database or authoritative supplied backup is accessed.

Acceptance: shared ownership and identity/access rules live in focused modules; callers retain compatible wrappers; transaction-local stock/movement/audit behaviour, public API and permissions remain identical; borrowed helpers never close the owner's connection; all checks pass.

## Delivery and next safety design

The owner merges/deploys the single foundation PR and confirms normal stock operations. The next design covers session revalidation under the write lock for requests spanning restore, including count application, replenishment, imports and transfer completion as well as ordinary stock endpoints. Tests must reproduce authentication before restore and mutation afterward, reject revoked/replaced sessions and preserve all stock/history on rejection. The application must not treat a matching restored numeric user ID as proof of continued authorization.

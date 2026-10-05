# Shared Stock-Service Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract shared stock transactions, access checks and inventory-row reuse into backend services with compatible main.py wrappers and clear connection ownership.

**Architecture:** The transaction service owns opening, BEGIN IMMEDIATE, commit/rollback and closure. Access/inventory helpers borrow that connection; main.py remains the dynamic composition boundary for current callers. This foundation preserves API and permissions; session revalidation for requests spanning restore is a separate follow-up.

**Tech Stack:** Existing Python, FastAPI HTTPException and sqlite3; no dependencies or migrations added.

**Spec:** docs/superpowers/specs/2026-10-05-shared-stock-foundation-design.md

## Global Constraints

- Keep stock_write_transaction(), require_active_record(conn,table,identifier), require_stock_access(conn,user_id,store_type,store_owner) and add_inventory_quantity(conn,store_id,part_id,quantity,work_order_id) compatible in main.py.
- Transaction opens one connection, acquires BEGIN IMMEDIATE before yield, commits on success, rolls back on failure, always closes. Preserve HTTP409 and `Stock is busy; no changes saved. Try again`.
- Borrowed access/inventory helpers never open, commit or close. Inventory helper acquires BEGIN IMMEDIATE only when no transaction exists, preserving existing direct callers.
- Preserve users/stores/parts active-record allowlist and exact missing/archived errors; admin/superadmin, owner and central-store access; HTTP403 `Permission denied for this store`.
- Preserve CAST(work_order_id AS NUMERIC) IS CAST(? AS NUMERIC) identity matching, returned row IDs and updated_at behaviour. No new quantity or allocation rules.
- main.py wrappers resolve main.get_db_connection dynamically. Services import no main.py and capture no DATABASE value. Keep defensive closed-connection rollback cleanup compatibility.
- No stock endpoint bodies, injected count/replenishment registration signatures, transfer semantics, API/schema/UI/startup/dependency changes. No independent audit commits.
- Use disposable databases only. Publish selected files against fresh GitHub main; owner merges/deploys. The existing request-spanning-restore session race remains tracked for the next safety design.

## Review Focus

1. A caller closing its connection during failure must not mask the original error or leak another connection; Task1 exercises defensive cleanup.
2. An access rejection after earlier stock/audit writes must leave the connection usable until its owner rolls everything back; Task2 exercises this intentional ownership correction.
3. NULL and numerically equivalent textual work-order IDs must reuse one identity without cross-allocation changes; Task2 pins literal row IDs/quantities.
4. A connection opened before main.DATABASE changes must finish on its original database; the next transaction must use the newly selected path; Task3 exercises both.
5. Existing injected stock-count/replenishment/import/transfer callers must retain atomic audit behaviour; Task3 runs their regressions and Task4 runs all suites.

## Files and Test Fixtures

Create backend/services/stock_transactions.py (owning context), stock_access.py (borrowed checks), inventory.py (borrowed identity helper). Modify only the four helper implementations/imports in main.py and add regression_tests/stock_service_fixtures.py, test_stock_transactions.py, test_stock_service_helpers.py, test_stock_service_integration.py. Include the approved spec and this plan in the PR.

The shared test fixture `make_stock_database(path) -> Path` initialises the canonical schema with backend.database.initialize_database(defaults={}); users1/admin,2/superadmin,3/engineer,4/manager; stores1/central/unassigned,2/car/owner3,3/car/owner4; part1/PART; work_order7/WO-7/engineer3; inventory11/store1/part1/NULL/quantity10,12/store2/part1/NULL/quantity5,13/store2/part1/work_order7/quantity8. Use literal expected values, real sqlite3.Row connections and explicit fixture cleanup. Password hashes can be unused literals for service tests because they do not authenticate.

Existing isolated worktree: /workspace/scratch/22e193396fd5/inventory-migrations. Runtime: `PYTHONPATH=/workspace/scratch/22e193396fd5/import-venv/lib/python3.12/site-packages python -m pytest ...`. conftest changes cwd; derive paths from __file__ or capture absolute roots. Existing full baseline:284Python/59JavaScript passed before this work; verify selected source against fresh upstream before publication.

## Task 1: Extract the Owning Write Transaction

**Files:** Create backend/services/stock_transactions.py, regression_tests/stock_service_fixtures.py and test_stock_transactions.py; modify main.py transaction helper only.

**Interfaces:** Produces `write_stock_transaction(get_connection: Callable[[],sqlite3.Connection]) -> context manager yielding sqlite3.Connection`. The supplied factory is called when the context is entered. main.stock_write_transaction() retains its no-argument context-manager interface and delegates using the current get_db_connection.

- [ ] Add test_main_transaction_commits_and_closes and test_main_transaction_rolls_back_all_evidence against the current wrapper before extraction. Within a real transaction update inventory11, add a movement and call the existing stock_audit balance/change/record helpers on that connection; on failure assert stock quantity10 and no new movement/audit remain. After success/failure the yielded connection must reject SELECT1 with ProgrammingError. Expected: current behaviour passes.
- [ ] Capture full OpenAPI from the disposable conftest runtime outside the repo for Task4 comparison.
- [ ] Write test_transaction_service_commits_and_closes, test_transaction_service_rolls_back, test_transaction_service_blocks_another_writer and test_transaction_preserves_error_when_caller_closes_connection. Import the new module and run `python -m pytest regression_tests/test_stock_transactions.py -q`; expected RED: module absent. The closed-connection case closes the yielded real connection then raises ValueError('original failure'); that same error must reach the caller.
- [ ] Implement the owning context with the existing transaction/error behaviour. Another held BEGIN IMMEDIATE causes a second context to raise HTTP409 before yielding, using a test factory timeout0.02; stock/movement/audit remain unchanged. Preserve the rollback ProgrammingError fallback and always close in finally.
- [ ] Delegate main.stock_write_transaction() without changing any endpoint or injected registration. Run `python -m pytest regression_tests/test_stock_transactions.py regression_tests/test_security_transactions.py -q`; expected PASS. Commit transaction service/wrapper and tests.

## Task 2: Extract Borrowed Access and Inventory Helpers

**Files:** Create backend/services/stock_access.py, backend/services/inventory.py and regression_tests/test_stock_service_helpers.py; replace main.py helper bodies with compatible wrappers.

**Interfaces:** Produces `require_active_record(conn,table,identifier) -> None`, `require_stock_access(conn,user_id,store_type,store_owner) -> None`, and `add_inventory_quantity(conn,store_id,part_id,quantity,work_order_id) -> int`. Inventory imports active-record checks from stock_access; both use the caller's sqlite3.Row connection and never commit/close.

- [ ] Write test_access_rejection_preserves_borrowed_connection against current main.require_stock_access, expecting HTTP403 followed by a successful SELECT1 on the same connection. Run it before changing code; expected RED: current helper closes the connection. Add new-module tests and observe missing-module RED before implementation.
- [ ] Add literal access matrix cases: actors1/2 may access another owner's car store; actor3 owns store2 and may access central; actor3 cannot access store3; missing actor999 cannot access central. Rejection preserves HTTP403/detail and leaves the borrowed transaction open.
- [ ] Add active-record allowlist/missing/archive cases with HTTP400 exact messages `{table} record does not exist` and `{table} record is archived; restore it first`; unsupported table raises ValueError. Check users/stores/parts and ensure failures leave SELECT1 usable.
- [ ] Pin inventory identity expectations with real transactions:
  ```python
  assert add_inventory_quantity(conn,1,1,3,None) == 11  # quantity13; one NULL identity
  assert add_inventory_quantity(conn,2,1,2,'007') == 13 # quantity10; one numeric7 identity
  assert quantity_for_id(12) == 5                     # other allocation untouched
  ```
  Test a new row ID, updated_at using a fixed old timestamp, and equivalent values7/'007'/'7e0'. With no active transaction the helper leaves one open; rollback restores prior rows. Missing/archived stores/parts reject without committing. Expected values are fixture literals, not calculated through the helper.
- [ ] Implement the extracted helpers and main.py wrappers. Remove connection closure only from borrowed access rejection; retain transaction-owner cleanup compatibility from Task1. Run `python -m pytest regression_tests/test_stock_service_helpers.py regression_tests/test_stock_safety.py regression_tests/test_archiving_integrity.py -q`; expected PASS. Commit helpers and ownership correction/tests.

## Task 3: Verify Wrapper and Existing Caller Integration

**Files:** Create regression_tests/test_stock_service_integration.py; update only newly extracted services/wrappers if these tests expose an integration defect.

**Interfaces:** Consumes Tasks1/2 through unchanged main.py callables and existing injected route registration interfaces. No new production interface.

- [ ] Add test_access_rejection_rolls_back_prior_stock_and_audit using the owning context: update inventory11 to99 and record evidence, then reject actor3/store3; outside the context assert inventory11 is10 and no new movement/audit. This catches a helper that closes early or a wrapper that independently commits.
- [ ] Add test_wrapper_uses_dynamic_database_path: create two seeded databases, enter a transaction on first, change main.DATABASE to second while inside it, update inventory11 to14 and finish; verify first14/second10. Enter another transaction and update inventory11 to15; verify first14/second15. The wrappers must not use a captured factory/path.
- [ ] Add test_stock_service_imports_do_not_initialise_application using a subprocess in an empty cwd with repo/runtime on PYTHONPATH. Import the three modules, assert main is absent from sys.modules and no DB/log files appeared. Real imports, not source-string checks.
- [ ] Run `python -m pytest regression_tests/test_stock_service_integration.py regression_tests/test_stock_audit.py regression_tests/test_stock_import.py regression_tests/test_stock_counts.py regression_tests/test_replenishment.py regression_tests/test_transfer_receipts.py -q`; expected PASS. These existing real API regressions protect injected callers and stock/movement/audit transactions. Fix a genuine defect through RED→GREEN; do not change endpoint business logic merely for cleanup. Commit integration tests and any necessary compatibility correction.

## Task 4: Full Verification, Review and PR

**Files:** Selected service/wrapper/test files, spec and plan; no database/log/runtime/cache/UI files.

- [ ] Compare full OpenAPI to Task1 baseline; expected identical. Run `python -m pytest -q`, `node --test regression_tests/*.cjs`, `python -m compileall -q backend main.py` and `git diff --check`; expected all tests pass and checks exit0. Read complete failure summaries; do not omit existing failures.
- [ ] Request one fresh independent whole-branch review using spec, plan, base/head, ledger and the five Review Focus lines. Fix Critical/Important findings in one test-backed pass; record scope rulings/deferred minors; rerun affected/full checks when changes justify them.
- [ ] Verify fresh GitHub main and the modified main.py baseline, reconcile upstream changes and publish only selected reviewed files. Inspect the resulting commit diff/file list and open one PR covering foundation extraction and the ownership correction. Leave merge/deployment to the owner.
- [ ] In the PR/final report explicitly retain the unresolved request-spanning-restore concern for the next reviewed session-revalidation design. Do not claim this extraction resolves it.

## Execution Handoff

Continue with the already selected native execution method: the interfaces are tightly connected, so one implementer retains context, followed by one fresh whole-branch reviewer. Review and approve this plan before implementation; no new execution-method choice is needed.

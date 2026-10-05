# Work-order Backend Boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the existing work-order listing into route/service/schema modules and let superadmins see every work order.

**Architecture:** main.py remains the composition point and supplies its current authentication callable and dynamic connection factory to an APIRouter factory. The route owns its connection, the service borrows it for read-only queries, and the schema retains the existing response contract. Reports and stock mutations remain unchanged.

**Tech Stack:** Existing Python, FastAPI, Pydantic and sqlite3; no new dependencies.

**Spec:** docs/superpowers/specs/2026-10-05-work-order-backend-boundaries-design.md

## Global Constraints

- GET /api/work-orders keeps its method/path, authentication, generated operation ID and WorkOrderResponse schema name.
- Admin and superadmin roles see all work orders, including orders assigned to other people and unassigned orders. Engineer and manager roles see only work orders assigned to their own ID.
- Orders remain sorted by wo.created_at DESC. Preserve the LEFT JOIN and nullable response fields; no pagination, archive filtering, tie-breaker or further permission changes.
- main.py passes main.get_db_connection and main.get_current_user. No new module imports main.py or captures DATABASE.
- Route owns opening/closing; service neither opens/closes nor commits/migrates. Preserve dependency-overrides compatibility and the main.WorkOrderResponse import alias.
- Package initializers have no application/database side effects. uvicorn main:app, schema, dependencies, environment and all other endpoints remain unchanged.
- Only disposable databases may be used. Keep reports and stock_services follow-up outside this PR. Publish selected files against verified GitHub main; owner merges/deploys.

## Review Focus

1. Unassigned work orders and nullable engineer/customer/description fields must remain serializable and visible to both privileged roles; Task 1 pins the exact payload.
2. Work orders assigned to archived engineers remain historical listings with engineer names; Task 1 pins unchanged LEFT JOIN behaviour.
3. An empty result and a borrowed connection must remain usable without service commits or closure; Task 2 exercises real SQLite transaction state.
4. A database path changed after router registration must be used, and query failure must close the route-owned connection; Task 3 exercises both.
5. Importing backend components alone must not load main.py, initialise a database or create logs; Task 3 checks this in an isolated subprocess.

## Execution Context

The existing linked worktree is /workspace/scratch/22e193396fd5/inventory-migrations. Verify isolation/clean status and start an implementation branch from its approved docs checkpoint. GitHub main contains merged migration/restore PRs; local history is an implementation checkpoint, so publish selected files only after comparing modified source baselines with fresh GitHub main.

Use the existing runtime: `PYTHONPATH=/workspace/scratch/22e193396fd5/import-venv/lib/python3.12/site-packages python -m pytest ...`. conftest.py changes cwd into a disposable directory; fixture paths must derive from __file__ or a captured absolute root. The existing api fixture in regression_tests/test_stock_safety.py supplies IDs 1/admin, 2/superadmin, 3/engineer and 4/manager.

## Task 1: Pin the Contract and Correct Superadmin Visibility

**Files:** Create regression_tests/test_work_orders.py; modify main.py only at the existing get_work_orders role condition.

**Interfaces:** Produces endpoint characterization tests and corrected role visibility consumed unchanged by Tasks 2/3. The shared seed helper in this test file inserts four work orders with IDs 101,102,103,104 assigned to users 3,4,NULL,2 respectively; ascending timestamps are IDs 104 (2026-10-01),101 (2026-10-02),102 (2026-10-03),103 (2026-10-04), all with status open. ID103 has NULL customer_name/description and no engineer.

- [ ] Write and run test_work_order_role_scope (admin/engineer/manager), test_work_order_response_contract, test_work_order_ordering, test_archived_engineer_name_is_retained, test_work_order_get_is_readonly, and test_work_orders_require_authentication. Use literal expected IDs/payloads and snapshot inventory/movements/users/work_orders around GET. For authentication, temporarily remove the current_user override; expect 401 without a cookie. Expected: existing behaviour passes before extraction.
- [ ] Pin the OpenAPI operation ID `get_work_orders_api_work_orders_get`, list response referencing `#/components/schemas/WorkOrderResponse`, exact seven properties and required/nullable semantics. Capture a full OpenAPI baseline outside the repository for Task 4 comparison; never generate it by importing main outside the disposable conftest environment.
- [ ] Add the superadmin role case and watch it fail against the current endpoint:
  ```python
  # IDs below are literal independent fixture expectations.
  assert ids_for_actor(1) == [103, 102, 101, 104]
  assert ids_for_actor(2) == [103, 102, 101, 104]
  assert ids_for_actor(3) == [101]
  assert ids_for_actor(4) == [102]
  assert admin_payload_for(103) == {'id':103,'work_order_number':'WO-103','customer_name':None,'description':None,'status':'open','assigned_engineer_id':None,'engineer_name':None}
  ```
  The helpers use the real authenticated api fixture and GET requests. Expected RED: actor2 previously returns only ID104.
- [ ] Change only the existing privileged-role condition to membership in ('admin','superadmin'). Run `python -m pytest regression_tests/test_work_orders.py regression_tests/test_stock_reports.py -q`; expected PASS. Commit the permission correction and characterization tests.

## Task 2: Extract the Response Model and Borrowed-Connection Query Service

**Files:** Create backend/schemas/__init__.py, backend/schemas/work_orders.py, backend/services/__init__.py, backend/services/work_orders.py and regression_tests/test_work_order_service.py. Modify main.py to import WorkOrderResponse as its compatibility alias; keep the current handler until Task 3.

**Interfaces:** Produces WorkOrderResponse and `list_work_orders(conn: sqlite3.Connection, user_id: int) -> list[dict]`. The connection has sqlite3.Row. Task 3 calls this service and uses this schema; the service never opens/closes/commits a connection.

- [ ] Add test_query_service_matches_role_visibility, test_query_service_empty_result and test_query_service_preserves_borrowed_transaction. Seed real disposable databases with Task 1's fixture values. Import the new service and run `python -m pytest regression_tests/test_work_order_service.py -q`; expected RED: module is absent.
- [ ] Implement list_work_orders using the existing role lookup and listing queries, with admin/superadmin full visibility and own assignments otherwise. Return dictionaries including the joined engineer_name; keep existing ordering. Copy the response model exactly (id:int, work_order_number:str, customer_name:Optional[str], description:Optional[str], status:str, assigned_engineer_id:Optional[int], engineer_name:Optional[str]); do not add defaults that change required fields. Package initializers contain only a docstring.
- [ ] In the borrowed-transaction test, BEGIN, insert a temporary work order, call the service, assert conn.in_transaction remains true and `SELECT 1` works; rollback and assert the inserted order is absent. This catches accidental commits or closure rather than merely inspecting source.
- [ ] Replace main.py's inline model with its imported alias, then run `python -m pytest regression_tests/test_work_orders.py regression_tests/test_work_order_service.py -q`; expected PASS with unchanged OpenAPI schema. Commit schema/service extraction and tests.

## Task 3: Extract and Mount the Dependency-Injected Router

**Files:** Create backend/routes/__init__.py, backend/routes/work_orders.py and regression_tests/test_work_order_router.py; modify main.py only at model import/router registration/old handler removal.

**Interfaces:** Consumes Task 2's schema/service. Produces `create_work_order_router(*, get_connection: Callable[[], sqlite3.Connection], current_user: Callable) -> APIRouter`, with async get_work_orders(user_id:int=Depends(current_user), request:Request=None). main.py mounts it at the old handler's registration location and passes its unchanged dependency objects.

- [ ] Write test_router_uses_supplied_authentication_and_database using a minimal FastAPI app and the supplied factory/dependency, test_registered_router_uses_changed_main_database, test_router_closes_connection_on_query_failure, and test_backend_imports_have_no_application_side_effects. Run `python -m pytest regression_tests/test_work_order_router.py -q`; expected RED: router module absent.
- [ ] Implement the router factory. Its GET handler uses response_model=list[WorkOrderResponse], opens a connection with the supplied factory, guarantees closure via contextlib.closing and calls list_work_orders. Keep handler name and docstring `Get work orders` to preserve OpenAPI summary/description. It imports no main.py and captures no path.
- [ ] Mount in main.py where the old decorator/handler stood, remove that handler, and preserve main.WorkOrderResponse. Do not move other registrations or edit stock_reports.py.
- [ ] For the dynamic-path test, initialise two temporary databases with distinct literal work-order numbers, change main.DATABASE between requests after app registration and assert each response uses the selected database. For query failure, give the router a real SQLite connection lacking work_orders, request with raise_server_exceptions=False, assert 500 and subsequent SELECT raises ProgrammingError because the route closed the connection.
- [ ] For the import test, run a subprocess from an empty temporary cwd with the repo on PYTHONPATH; import the three work-order modules, assert 'main' is absent from sys.modules and no database/log files appeared. No source-string assertions.
- [ ] Run `python -m pytest regression_tests/test_work_orders.py regression_tests/test_work_order_service.py regression_tests/test_work_order_router.py regression_tests/test_stock_reports.py -q`; expected PASS. Commit route extraction/integration and tests.

## Task 4: Verify, Review and Publish One PR

**Files:** Selected files from Tasks 1–3, this plan and the approved spec. No UI, runtime, cache, database or log files.

- [ ] Compare the full current OpenAPI document with Task 1's disposable baseline. Expected: identical paths/methods/operation IDs and component definitions; the only intended behavioural difference is the already tested superadmin listing visibility. Correct unintended schema/description changes before continuing.
- [ ] Run `python -m pytest -q`, `node --test regression_tests/*.cjs`, `python -m compileall -q backend main.py`, and `git diff --check`. Expected: all tests pass, compile/whitespace checks exit0. Check stock/history snapshots in GET tests; do not touch live data.
- [ ] Use requesting-code-review for one fresh read-only whole-branch review with spec, plan, base/head and Review Focus. Fix Critical/Important findings with reproducing RED→GREEN tests and rerun affected/full checks as needed. Record any declined scope or deferred minor findings.
- [ ] Fetch fresh GitHub main, compare modified main.py baseline to the approved source, reconcile any upstream changes and publish only selected files. Inspect the resulting commit file list/diff; create one PR summarising superadmin correction, extraction, verification and unchanged deployment/API. Owner merges and confirms work-order listing.

## Execution Handoff

Continue with the previously selected native method: one implementer retains the shared endpoint/schema/dependency context, followed by one fresh whole-branch review. Review this plan before implementation; no separate choice of execution method is needed.

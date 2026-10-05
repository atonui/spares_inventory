# Work-order backend boundaries

## Intent and scope

Organise the existing FastAPI backend in small, reviewable PRs while the Railway application remains in use. This first refactor extracts the remaining GET /api/work-orders endpoint from main.py into focused route, service and schema modules. It preserves the endpoint's external contract and corrects the listing's role visibility as requested: admins and superadmins see all work orders; engineers and managers see only their own assigned orders. This permission correction is the sole intentional behaviour change. It performs no database migration or live data operation.

Reports already live in stock_reports.py, with consumption JSON/CSV and actor-scoped work-order consumption history. Those handlers and their registration remain unchanged in this PR. Stock mutation services and authentication/administration extraction follow in separate designs and PRs. The pre-existing concern about requests that read before a restore and write afterward belongs to the stock-services stage; a read-only work-order extraction does not resolve it.

## Approaches and decision

1. Recommended: explicit APIRouter factory, query service and response schema. main.py supplies the existing authentication dependency and database connection factory. This creates clear boundaries without extracting all authentication or introducing global application imports.
2. Move only the handler into another module. This is smaller but leaves route responsibilities, SQL and response definitions coupled and makes the next extraction harder.
3. Extract all shared authentication and database dependencies first. This provides a larger common foundation but spreads this first PR across security-sensitive endpoints and increases the regression surface.

Use approach 1. These modules must not import main.py or capture a fixed DATABASE value.

## Module ownership and interfaces

- backend/schemas/__init__.py and backend/schemas/work_orders.py: WorkOrderResponse retains the existing class name, field names, annotations and required/nullable semantics. Its fields are id, work_order_number, customer_name, description, status, assigned_engineer_id and engineer_name. main.py imports the same class as a compatibility alias instead of keeping a duplicate definition.
- backend/services/__init__.py and backend/services/work_orders.py: list_work_orders(conn, user_id) borrows an existing sqlite3.Connection configured with sqlite3.Row, reads the user's role, executes the listing query with the approved admin/superadmin visibility rule and returns list[dict]. It does not open, close, commit or migrate a database connection. It performs no writes and owns no authentication/session implementation.
- backend/routes/__init__.py and backend/routes/work_orders.py: create_work_order_router(*, get_connection, current_user) returns a FastAPI APIRouter. Its async get_work_orders handler retains the existing user_id dependency and optional Request parameter. It owns opening and closing the connection using contextlib.closing, delegates the listing query to the service and keeps response_model=list[WorkOrderResponse].
- main.py is the composition point. It mounts the router exactly where the previous work-order handler was registered and passes main.get_db_connection and main.get_current_user. Removing the inline handler/model is the only route/model restructuring in main.py.

The existing callable dependency object remains the authentication boundary so main.app.dependency_overrides[main.get_current_user] continues to work. The supplied connection factory must resolve main.DATABASE at call time; tests and deployments must not accidentally connect to a captured/default path. Package initializers have no application/database side effects.

## Observable behaviour and intentional permission correction

- GET /api/work-orders keeps its method/path, authentication, generated operation ID and WorkOrderResponse schema name.
- The response remains a JSON array with exactly the seven model fields, including the existing nullable fields. created_at remains excluded from the response even though it participates in ordering.
- Admin and superadmin roles see all work orders, including orders assigned to other people and unassigned orders. Engineer and manager roles see only work orders assigned to their own ID. Expanding superadmin visibility is explicitly requested and must be implemented and tested in this PR.
- Orders remain sorted by wo.created_at DESC. The engineer-name LEFT JOIN and treatment of missing/unassigned engineers remain unchanged. Do not add a tie-breaker, pagination, archive filtering or further visibility changes beyond the approved superadmin correction.
- Existing authentication continues to handle absent/expired sessions and archived users. The query service does not become a new authorization entry point.
- Connection closure is guaranteed on success and query failure; errors retain FastAPI's existing propagation. No new status codes or fallback responses are introduced.
- The consumption reports, CSV exports, work-order consumption history, stock writes and UI remain unchanged.
- uvicorn main:app, environment variables, SQLite schema and production dependencies remain unchanged.

## Validation and acceptance

Before extraction, add characterization tests against the existing endpoint using real disposable SQLite databases and the existing authenticated API fixture. Cover current admin visibility and engineer/manager assignment, unassigned work orders, descending creation order, nullable fields, exact serialized keys, authentication enforcement and the OpenAPI operation/model contract. Add a separate regression requiring a superadmin to see all work orders, including other engineers’ assignments and unassigned orders; observe its failure against the current implementation before correcting the permission rule. Expectations must be literal fixture values rather than reconstructed from the implementation.

After extraction, add failing integration tests for the new router with a supplied connection factory and authentication callable, then implement the boundary. Exercise a second temporary database to demonstrate the injected path is actually used; verify a failed query closes its owned connection while a caller-supplied service connection remains usable. Do not replace report regression tests with mocks or duplicate framework mechanics.

Run the full Python and JavaScript suites, compile the changed modules and main.py, and check whitespace. Compare the before/after OpenAPI paths, methods, operation IDs and work-order schema (all unchanged) and demonstrate GET requests do not modify stock/history. Run existing stock_reports regressions to verify registration/dependency compatibility. Request one fresh read-only code review before publishing the selected implementation files.

Acceptance: the application exposes the same public API and schema against the same test databases, with admin/superadmin visibility across all work orders and unchanged engineer/manager assignment scoping; route/service/schema responsibilities are distinct; imported backend components do not import or initialise the web app; all required checks pass. No production database is touched.

## Delivery and follow-up

Publish one implementation PR against freshly verified GitHub main, including this design and the approved implementation plan. The owner merges/deploys and confirms startup and work-order listing. Do not automatically merge or deploy.

Next stages are shared stock services with preserved transaction/audit rules and explicit treatment of requests spanning a restore, followed by authentication and administration modules. Those changes require their own bounded designs or architectural specs according to actual scope; this PR must not pre-empt them with an unused dependency framework.

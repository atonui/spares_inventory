# Spares Tracker (backend + web)

A multi-tenant SaaS built on FastAPI and PostgreSQL 16/17, with Alpine.js pages in `static/`.
The mobile app lives in atonui/spares_inventory_mobile; it uses SQLite only as its offline cache.
**This repo is PostgreSQL-only.** Don't reintroduce SQLite paths or `is_postgres` checks.

## Layout
- `main.py` wires the app. Routers live in `backend/routes/`, logic in `backend/services/` and Pydantic models in `backend/schemas/`.
- `backend/postgres_migrations/vNNNN_*.py`: append-only and checksummed, one transaction each.
  Never edit an applied migration; add the next number instead.
- `static/` holds the pages (`index.html`, `profile.html`, and `superadmin.html`, which is the platform console)
  and their JS in `static/js/{shared,inventory,pages}/`.
- `regression_tests/`: pytest (`test_*.py`) and Node UI tests (`*.cjs`).

## Running checks (CI runs all three)
- Backend tests need PostgreSQL. CI's database uses the superuser `inventory_test` (password `inventory_test`).
  ```bash
  TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test \
  PGOPTIONS="-c lock_timeout=5s -c statement_timeout=60s" pytest -q regression_tests
  ```
  The full suite takes about 8 minutes. Run it before every commit.
- UI: `node --test regression_tests/*.cjs`
- CSS: `cd tooling/css && npm ci && npm run check:css`

## Rules that bite
- **Tenancy and RLS:** tenant tables carry `organization_id`. Requests run as a NOBYPASSRLS role
  with `app.organization_id` set. Use `authenticated_tenant_transaction` or
  `authenticated_write_transaction`; never query tenant data on a bare connection.
- **SQL placeholders:** `database_sql.execute(conn, sql, params)` accepts `?`, but a raw `conn.execute` needs `%s`.
- **After editing a stylesheet**, run `npm run build:css` in `tooling/css`. Production serves
  `static/minified/*.css` whenever it exists, and CI fails when the minified copy is stale.
- **After editing a page script or stylesheet**, bump its `?v=` in the HTML and update the version map in
  `test_frontend_entrypoints.cjs` or `test_sitewide_visual_system.cjs`.
- **Tests import fixtures by name** (for example `from regression_tests.test_stock_safety import api`).
  Never auto-remove "unused" imports under `regression_tests/`.
- The shared PostgreSQL fixtures are in `regression_tests/postgres_app.py`: `tenant_api`, `stock_api`,
  `database_state` and `fail_inserts`, plus the `ACTORS` (`admin`, `owner`, `engineer`, `manager`,
  `other`, `platform`).

## Product rules
- Accounts are invitation-only. Admins never set passwords, and `POST /api/users` returns 410.
- Company roles are owner, admin, manager and engineer. Platform admins are separate (`platform_admins`).
  `saas_mode` is always true and is kept only for API clients.
- Part numbers are limited to 25 characters. The calibration reminder is set per company,
  and new companies get default store types.
- A member can't be deactivated or removed while they have pending transfers or still hold
  active stores or equipment (`services/archiving.require_member_can_leave`).

## Workflow
- One PR per area, on a branch. Never commit to `main`.
- For UI changes, also load the page in headless Chromium with stubbed API responses and check for JS errors.
- Plans and specs from earlier work live in `docs/superpowers/`.

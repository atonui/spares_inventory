# PostgreSQL CI Recovery Plan

**Goal:** Complete the backend regression suite without test-created transaction lock hangs.

**Scope:** Test fixtures and CI only; no production settings or application behavior changes.

- [x] Reproduce the existing member-removal test failure with PostgreSQL lock_timeout=5s and statement_timeout=60s in disposable CI.
- [x] Commit setup mutations before invoking endpoints through independent connections; preserve membership, session and activity-history assertions.
- [x] Review adjacent tests for the same transaction boundary error and fix only confirmed failures.
- [x] Keep the 15-minute job deadline, remove first-failure truncation, and emit Python stack diagnostics for stalls.
- [ ] Run the full PostgreSQL backend suite and report every remaining failure.
- [ ] Review the diff and open a PR with exact verification evidence.

## Diagnostic baseline

The bounded full PostgreSQL run completed with 1,329 passing and nine failing tests. Two failures were uncommitted fixture lock waits. Five were missing mobile timestamp classifications. The timezone upgrade test applied later security migrations that intentionally revoke legacy credentials. The user-route contract omitted membership removal and admin-managed email changes.

Local focused checks: 58 passed after corrections. Full PostgreSQL verification pending.

## Separate frontend baseline

The Node regression suite on the unmodified main checkout returned 860 passed and 15 failed. The Frontend assets workflow checks generated CSS only. These failures remain outside this backend CI fix:

- regression_tests/test_brand_assets.cjs:12:1 — brand palette tokens and source logo variants are present
- regression_tests/test_frontend_entrypoints.cjs:26:5 — profile.html: shipped scripts precede Alpine with one controller
- regression_tests/test_frontend_entrypoints.cjs:26:5 — superadmin.html: shipped scripts precede Alpine with one controller
- regression_tests/test_inventory_action_visuals.cjs:10:1 — inventory summary and Add Stock are separated from filter and export controls
- regression_tests/test_keyboard_controls.cjs:18:1 — Escape dismisses Export and restores its trigger without stealing focus when closed
- regression_tests/test_keyboard_controls.cjs:28:1 — Tab within Export keeps it open, while leaving the disclosure dismisses it
- regression_tests/test_keyboard_controls.cjs:38:1 — every export choice closes the list and returns keyboard focus after invoking the action
- regression_tests/test_keyboard_controls.cjs:55:1 — native CSV inputs remain keyboard reachable and the skip link has a focusable destination
- regression_tests/test_profile_settings_ui.cjs:46:1 — pending password change cannot submit twice
- regression_tests/test_profile_settings_ui.cjs:50:1 — expired security token on a write disables writes and offers token retry
- regression_tests/test_profile_settings_ui.cjs:54:1 — missing-token rejection exposes security recovery on the profile page
- regression_tests/test_sidebar_navigation_visual_contract.cjs:10:1 — authenticated app uses a labeled sidebar and a separate content column
- regression_tests/test_sitewide_visual_system.cjs:75:1 — every page cache-busts the updated site-wide stylesheets
- regression_tests/test_ui_accessibility.cjs:316:1 — remaining fixed inventory tables become labeled mobile cards and keep row actions
- regression_tests/test_users_admin_feature.cjs:16:1 — user administration owns its invitation state and independent forms

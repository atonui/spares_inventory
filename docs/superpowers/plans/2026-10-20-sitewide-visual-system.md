# Site-wide Visual System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the approved restrained Spares Tracker visual system across the workspace, account pages, and superadmin while preserving all product behavior.

**Architecture:** Keep the existing static HTML, AlpineJS, and page-specific stylesheets. Treat the shared tokens in `static/mystyle.css` as the canonical visual foundation, then align the workspace, account pages, and superadmin CSS to those tokens. Add source-level visual contracts and preserve the existing page structure and behavior.

**Tech Stack:** Static HTML, CSS, AlpineJS, Node.js test runner, Python pytest.

**Spec:** `docs/superpowers/specs/2026-10-20-sitewide-visual-system-design.md`

## Global Constraints

- Keep brand navy `#15263B`, brand amber `#E9A23B`, supporting slate `#64748B`, page background `#F5F7FA`, and surface `#FFFFFF`.
- Use the existing single system sans-serif stack; do not add font or image dependencies.
- Do not change business logic, API calls, data shape, authentication, tenant boundaries, permissions, or role-based visibility.
- Preserve the stock action menu behavior and visual rules merged in PR #226.
- Maintain minimum 44 px touch targets for primary mobile controls and accessible names for icon-only controls.
- Review representative surfaces at 390×844, 768×1024, and 1440×900.

## Review Focus

- Long part/store names and validation messages must wrap without clipping; verify workspace and profile controls at 390 px.
- Narrow viewports must not gain page-level horizontal overflow; verify inventory, reports, profile, and superadmin.
- Dense tables must retain header-to-cell relationships and usable row actions; verify stock, report, and audit tables.
- Keyboard focus and loading/error form states must remain visible and operable; verify auth and profile flows.
- Superadmin panels, filters, tables, and confirmation dialogs must remain usable at tablet and mobile widths.

## File Map

- `static/mystyle.css`: canonical shared tokens and workspace shell, panel, form, and table presentation.
- `static/index.html`: only add or adjust semantic classes needed to style existing workspace regions consistently.
- `static/login.css`: sign-in and account recovery typography, fields, buttons, messages, and responsive spacing.
- `static/profile.css`: profile headings, settings surfaces, tabs, fields, buttons, and responsive spacing.
- `static/superadmin.css`: superadmin navigation, panels, tables, filters, messages, controls, and responsive layouts.
- `static/*.html`: version query strings for every changed stylesheet, so browser caches load the new visual rules.
- `regression_tests/test_sitewide_visual_system.cjs`: focused assertions for tokens, common control treatment, and cross-page stylesheet contracts.
- Existing targeted regression files remain the behavior contracts for each screen family; no product behavior tests are to be weakened or removed.

## Tasks

### Task 1: Establish the shared token and control foundation

**Files:**
- Modify: `static/mystyle.css`
- Create: `regression_tests/test_sitewide_visual_system.cjs`

**Interfaces:**
- Produces the canonical CSS custom properties used by the workspace, auth, profile, and superadmin stylesheets.
- Keeps the existing palette, system font stack, focus token, and 44 px minimum control sizing.

- [ ] Write failing tests `sharedScaleIncludesTypeXlAndSpaceFive` and `sharedFocusAndReducedMotionRulesRemainDefined`. The first asserts `--type-xl: 1.5rem` and `--space-5: 1.25rem`; the second asserts the shared focus token is used and a reduced-motion media query disables nonessential transitions.
- [ ] Run `node --test regression_tests/test_sitewide_visual_system.cjs`; confirm `sharedScaleIncludesTypeXlAndSpaceFive` fails because those two scale tokens are absent.
- [ ] Add only the missing scale tokens and shared focus/control primitives to `static/mystyle.css`; preserve the approved palette values.
- [ ] Run the new test and `node --test regression_tests/test_brand_assets.cjs regression_tests/test_ui_accessibility.cjs`; confirm all pass.
- [ ] Commit as `style: establish site-wide visual tokens`.

### Task 2: Align the workspace shell and operational panels

**Files:**
- Modify: `static/mystyle.css`
- Modify: `static/index.html` only where an existing region needs a stable semantic class.
- Modify: `regression_tests/test_sitewide_visual_system.cjs`
- Verify: `regression_tests/test_inventory_store_visual_contract.cjs`, `regression_tests/test_stock_row_actions_menu.cjs`, `regression_tests/test_inventory_usability.cjs`, `regression_tests/test_stock_reports_ui.cjs`, `regression_tests/test_activity_logs_ui.cjs`, `regression_tests/test_equipment_ui.cjs`, `regression_tests/test_navigation_ui.cjs`.

**Interfaces:**
- Consumes the shared CSS tokens from Task 1.
- Produces consistent shell, panel-heading, toolbar, form, status, table, and empty-state presentation for the workspace panels.

- [ ] Write failing tests `workspacePanelRulesUseSharedSpacingAndSurfaceTokens` and `workspaceTablesKeepResponsiveDataLabels`. Assert the inventory panel heading and toolbar rules use shared spacing/surface tokens, and that responsive stock/report rules retain data labels and bounded overflow containers.
- [ ] Run `node --test regression_tests/test_sitewide_visual_system.cjs`; confirm `workspacePanelRulesUseSharedSpacingAndSurfaceTokens` fails on the missing token references.
- [ ] Align existing workspace selectors to the shared tokens: app shell, navigation, headings, panel surfaces, filters/toolbars, common controls, alerts/empty states, report tables, and operational data tables.
- [ ] Extend the merged inventory table pattern only to suitable operational tables; use per-panel responsive handling for wide reports and retain their labeled columns.
- [ ] Add or adjust only stable classes in `static/index.html`; do not alter Alpine expressions, IDs, action labels, permissions, or panel visibility conditions.
- [ ] Run the source-contract and listed targeted regression tests; confirm all pass.
- [ ] Commit as `style: align workspace panels with shared visual system`.

### Task 3: Align sign-in, account recovery, invitation, and profile pages

**Files:**
- Modify: `static/login.css`
- Modify: `static/profile.css`
- Modify: `regression_tests/test_sitewide_visual_system.cjs`
- Verify: `regression_tests/test_frontend_entrypoints.cjs`, `regression_tests/test_invitation_acceptance_ui.cjs`, `regression_tests/test_email_change_confirmation_ui.cjs`, `regression_tests/test_profile_accessibility.cjs`, `regression_tests/test_profile_settings_ui.cjs`, `regression_tests/test_profile_email_change_ui.cjs`.

**Interfaces:**
- Consumes Task 1 shared tokens.
- Preserves each page's current form structure, content, state, and interaction behavior.

- [ ] Write failing test `accountPagesUseSharedSurfaceAndControlTokens`. Assert `login.css` and `profile.css` use `--radius-surface`, `--radius-control`, and spacing tokens for their principal surfaces and fields.
- [ ] Run `node --test regression_tests/test_sitewide_visual_system.cjs`; confirm the test fails on the profile rules that still use literal surface/control radii.
- [ ] Align existing auth layouts, fields, primary/secondary buttons, links, validation messages, and loading/success states to the shared scale without changing copy or form semantics.
- [ ] Align profile headings, tabs, settings surfaces, fields, and actions to the same rules while retaining its distinct account-settings layout.
- [ ] Update the `login.css`, `profile.css`, and `mystyle.css` cache versions in each account page that loads them.
- [ ] Run the source-contract and listed auth/profile tests; confirm all pass.
- [ ] Commit as `style: align account pages with shared visual system`.

### Task 4: Align the superadmin surface

**Files:**
- Modify: `static/superadmin.css`
- Modify: `regression_tests/test_sitewide_visual_system.cjs`
- Verify: `regression_tests/test_superadmin_ui.cjs`, `regression_tests/test_profile_accessibility.cjs`, `regression_tests/test_announcements_ui.cjs`.

**Interfaces:**
- Consumes Task 1 shared tokens.
- Retains the existing superadmin sidebar and panel structure, navigation, filters, quick actions, audit behavior, and confirmation dialogs.

- [ ] Write failing test `superadminUsesSharedSurfaceAndControlTokens`. Assert the sidebar, panel, table header, and form control rules use shared radius, spacing, and focus tokens.
- [ ] Run `node --test regression_tests/test_sitewide_visual_system.cjs`; confirm the test fails on the current hard-coded superadmin presentation values.
- [ ] Replace presentation-only duplicate values with shared tokens and align navigation, panel headers, tables, filters, status tags, empty states, and dialogs to the restrained visual direction.
- [ ] Add focused responsive rules for the existing mobile superadmin layout; do not change its navigation or authorization behavior.
- [ ] Update the `superadmin.css` and `mystyle.css` cache versions in `static/superadmin.html`.
- [ ] Run the source-contract and listed targeted regression tests; confirm all pass.
- [ ] Commit as `style: align superadmin with shared visual system`.

### Task 5: Review all page families and complete verification

**Files:**
- Verify all files changed in Tasks 1–4.
- Update: `regression_tests/test_sitewide_visual_system.cjs` only for verified contract gaps.

- [ ] Run `node --test regression_tests/*.cjs`; confirm all frontend tests pass.
- [ ] Run `pytest regression_tests -q`; record the result, including any environment dependency or database setup blocker.
- [ ] Capture and inspect workspace inventory, reports, profile, sign-in, and superadmin at 390×844, 768×1024, and 1440×900.
- [ ] Check keyboard focus, action menus, long labels, loading/error/empty states, and page-level horizontal overflow on representative pages.
- [ ] Run `git diff --check` and review the final diff for behavior or copy changes.
- [ ] Confirm every page loading a changed stylesheet uses the `20261020-sitewide-visual-system` cache version.
- [ ] Record screenshot/test limitations and any remaining visual findings in the PR summary.

## Acceptance Criteria

- Workspace, account, and administration pages share the approved palette, typography, spacing, controls, and restrained surface treatment.
- Desktop operational tables remain compact and scannable; mobile rows remain readable and action-ready.
- Existing workflows, content semantics, permissions, and data behavior are unchanged.
- Frontend regression tests pass and relevant backend tests are unchanged and passing.
- Reviewed screenshots cover all representative page families at 390×844, 768×1024, and 1440×900.

## Risks

- `static/index.html` contains many Alpine-driven panels; keep any markup change to presentation classes and retain all bindings.
- `static/mystyle.css` has accumulated responsive rules; validate computed rendering at target widths instead of deleting rules based on source appearance.
- Auth and profile pages intentionally have different layouts; reuse typography and controls without forcing identical page composition.
- Superadmin includes wide data sets and sensitive controls; preserve its explicit table labels, role access, and confirmation steps.

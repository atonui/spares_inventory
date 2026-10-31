# Platform Administration Console UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Redesign the SaaS platform-admin UI into a restrained operations console while preserving all existing platform and legacy SQLite behavior.

**Architecture:** Keep the existing Alpine.js `superPanel()` and `/api/platform` contracts. Add a SaaS-mode visual shell and an Offset icon sprite, then reshape the SaaS-only overview, organization workflow, and administrative pages in the current shared HTML document. Keep all tenant data access within the existing organization-scoped, audited support workflow.

**Tech Stack:** HTML, CSS, Alpine.js, existing FastAPI platform endpoints, SVG symbols.

**Spec:** `docs/superpowers/specs/2026-10-31-platform-admin-console-ux-design.md`

## Global Constraints

- Change only the SaaS platform-administrator presentation and its client-side orchestration.
- Preserve the shared HTML document’s legacy SQLite superadmin rendering and behavior.
- Reuse existing platform APIs; do not add endpoints, database objects, permissions, or background jobs.
- Keep tenant and platform identity boundaries explicit in labels, navigation, and organization context.
- Keep platform administrative mutations reason-confirmed and audited as they are today.
- Preserve keyboard navigation, dialog focus management, accessible names, and loading/error/empty states.
- No new frontend framework or third-party dependency.
- Use the established palette: navy `#15263B`, amber `#E9A23B`, slate `#64748B`, page `#F5F7FA`, and white surfaces.
- Offset icons use a 24 px grid, 1.75 px rounded stroke, and 1.6 px accent registration; stroke and accent must stay subdued.
- Do not show organization owner counts or tenant-member rosters unless an existing API response provides them.

---

## File Map

- `static/superadmin.html`: SaaS-specific shell, navigation, view templates, create-organization dialog, and existing modal integration. Keep legacy sections and visibility conditions intact.
- `static/superadmin.css`: SaaS-only shell, cards, tables, details, support workspace, dialog, responsive rules, and subdued icon styles.
- `static/js/pages/superadmin.js`: Add selected-organization and organization-activity state plus loaders; retain the existing API and action methods.
- `static/superadmin-icons.svg`: New local SVG symbol sprite containing only the Offset icons used by the SaaS platform console.
- `docs/superpowers/specs/2026-10-31-platform-admin-console-ux-design.md`: Approved design authority.

## Task 1: Add the SaaS console shell and subdued Offset icon set

**Files:**
- Create: `static/superadmin-icons.svg`
- Modify: `static/superadmin.html`
- Modify: `static/superadmin.css`

**Interfaces:**
- The `<body>` adds the `platform-console` class only when `me?.saas_mode` is true.
- Sidebar links continue to select existing tab keys: `dashboard`, `organizations`, `support`, `platformAdmins`, `config`, `announcement`, and `platformAudit`.
- The icon sprite exposes symbol IDs `overview`, `organization`, `support`, `platform-access`, `security`, `announcement`, `audit`, `search`, `filter`, `refresh`, `open`, `mail`, `activity`, `check`, `clock`, and `add`.
- Each icon uses two references to the same symbol: a low-opacity muted amber offset layer followed by the muted slate line layer.

- [x] **Step 1: Create the focused SVG sprite.** Use a 24×24 viewBox per symbol, rounded 1.75 px line caps/joins, and the paths from the supplied Offset pack for the matching symbols. Set no script or external dependencies. Use `fill="none"` and inherited stroke for the line geometry; apply a separate fill to the offset `<use>` in CSS.
- [x] **Step 2: Scope SaaS visual rules.** Add `:class="{'platform-console': me?.saas_mode}"` to the body and scope all new shell rules under `.platform-console` so legacy SQLite screens do not inherit them.
- [x] **Step 3: Reorganize the SaaS sidebar.** Group Overview, Organizations, and contextual Customer support under Platform; group Platform access, Security settings, Announcements, and Audit log under Administration. Keep text labels visible and the signed-in platform identity in the footer. Preserve existing tab keys and role gating.
- [x] **Step 4: Add responsive shell styles.** Use the existing palette, quiet surface/border treatment, 44 px minimum control targets, visible keyboard focus, and a compact mobile navigation presentation. Keep the `Offset` amber layer desaturated with low opacity and the stroke neutral.
- [x] **Step 5: Run static diff validation.** Run `git diff --check` and inspect that all new selectors are scoped to `.platform-console`.

## Task 2: Redesign Overview and Organizations

**Files:**
- Modify: `static/superadmin.html`
- Modify: `static/superadmin.css`
- Modify: `static/js/pages/superadmin.js`

**Interfaces:**
- Overview consumes `/platform/dashboard` fields: `organizations_total`, `organizations_active`, `identities_active`, `platform_admins`, `mail_pending`, and `mail_failed`.
- Recent platform events consume `/platform/audit-events` with the existing pagination and curated `details` response.
- Organization directory continues to consume `/platform/organizations` with its current `rows`, `total`, `limit`, and `offset` response.
- Organization events use `/platform/audit-events?organization_id=<UUID>&limit=10&offset=0` and remain separate from global audit filters.
- Organization creation continues to call `provisionOrganization()` and `POST /platform/organizations`; status changes continue through the existing `requestOrganizationStatus()` action.

- [x] **Step 1: Replace the SaaS overview content.** Group the six backend metrics into four clear cards: total/active organizations, active identities, platform admins, and invitation mail with pending and failed counts. Add a failed-mail attention state and a recent activity list. Keep the identity label “Active accounts,” since `identities_active` counts active user identities and is not a tenant-member count.
- [x] **Step 2: Add organization selection and activity state.** Add `selectedOrganization`, `organizationAuditRows`, `organizationAuditLoading`, and `organizationAuditError` to `superPanel()`. Add `openOrganization(org)` and `loadOrganizationActivity(orgId)`; the loader must query the existing audit endpoint with the organization ID, limit 10, and offset 0, without mutating `platformAuditFilters` or `platformAuditRows`.
- [x] **Step 3: Reshape the organizations view.** Put search, status, result count, pagination, and a primary “Create organization” action above the table. Retain active member and invitation mail counts. Put row actions in an accessible secondary menu or explicit detail action; keep suspend/reactivate wording and existing confirmation flow.
- [x] **Step 4: Add the organization detail panel.** Show only directory fields (name, slug, status, created date, active member count, pending/failed invitation mail counts) plus recent filtered platform events. Do not add user names, owner counts, or tenant inventory. Provide the existing “Start support session” action in organization context.
- [x] **Step 5: Move provisioning into a focused dialog.** Reuse `organizationForm`, current constraints, `provisionOrganization()`, `actionPending`, and `actionErrors`. On success, close the dialog, clear the form, reload the organization directory and overview, and announce the result. Preserve field labels and server validation errors.
- [x] **Step 6: Handle empty and error states.** Keep explicit loading, retry, empty-results, and pagination states for directory and organization activity. Avoid treating a successful zero count as a platform-health claim.
- [x] **Step 7: Run static validation.** Run `node --check static/js/pages/superadmin.js` and `git diff --check`; inspect the Overview and Organizations Alpine expressions against the named response fields.

## Task 3: Apply the console system to support and administrative pages

**Files:**
- Modify: `static/superadmin.html`
- Modify: `static/superadmin.css`
- Modify: `static/js/pages/superadmin.js` only if existing page state needs a presentation-only addition

**Interfaces:**
- Support uses existing `/platform/support-sessions/current`, session creation/end, and allowlisted lookup endpoints.
- Platform access uses existing `/platform/admins` grant/list/revoke behavior.
- Security settings use existing `/platform/security-config` endpoints.
- Announcements use existing announcement manage/create/delete endpoints and current audience, time, expiry, and conflict state.
- Global audit retains `/platform/audit-events` filters and pagination.

- [x] **Step 1: Restyle the support workspace.** Add a persistent organization-scope banner, reason, expiry countdown, and “End support session” action. Keep exact-identifier lookup types, result rendering as text, and loading/empty/error/retry states. Keep the start-session password and reason dialog unchanged in meaning.
- [x] **Step 2: Restyle Platform access.** Present the existing platform-admin list and grant form as a focused panel. Keep grant/revoke confirmation behavior, self-revoke protection, loading state, and error messages. Do not add global user search.
- [x] **Step 3: Restyle Security settings.** Preserve the current supported security fields and inputs, including the SaaS mobile session maximum. Keep saving, bounds, validation, and error feedback unchanged.
- [x] **Step 4: Restyle Announcements.** Preserve draft conflict handling, audience selection, schedule/expiry controls, saved preview, publication/removal actions, and their status messages. Keep the UTC notice for SaaS scheduling.
- [x] **Step 5: Improve the Audit presentation.** Keep all existing filters, pagination, curated detail fields, and UTC timestamps. Improve label hierarchy and wrapping without changing query behavior.
- [x] **Step 6: Run static validation.** Run `node --check static/js/pages/superadmin.js` and `git diff --check`; confirm all SaaS pages still use the existing platform routes and no legacy-only route is exposed in SaaS mode.

## Task 4: Responsive and accessibility pass

**Files:**
- Modify: `static/superadmin.html`
- Modify: `static/superadmin.css`
- Modify: `static/superadmin-icons.svg`

- [x] **Step 1: Check heading and action hierarchy.** Keep one amber primary action in each task context; keep secondary actions outlined/neutral and destructive actions clearly labeled with confirmation.
- [x] **Step 2: Check keyboard and assistive-technology semantics.** Ensure sidebar links are buttons/links with visible labels, the current page uses `aria-current`, icon-only actions have accessible names, dialogs retain their existing focus trap/escape behavior, and loading/error states use the existing live-region semantics.
- [x] **Step 3: Check narrow-layout rules in source.** Ensure organization information does not depend on horizontal scrolling at narrow widths, the filter/action toolbar wraps, dialogs fit the viewport, and the support scope banner remains visible and understandable.
- [x] **Step 4: Final static review.** Run `git diff --check` and `node --check static/js/pages/superadmin.js`. Review `git diff -- static/superadmin.html static/superadmin.css static/js/pages/superadmin.js static/superadmin-icons.svg` to confirm legacy SQLite markup/visibility and all existing actions remain intact. Do not run the project test suite as part of this plan.

## Scope and verification notes

- This plan makes no backend, schema, permission, or tenant-data-access changes.
- The shared page intentionally continues to contain both legacy and SaaS markup; changes must use `platform-console` scoping and existing `me?.saas_mode` visibility gates.
- Static validation is included. The project test suite is not part of this execution.

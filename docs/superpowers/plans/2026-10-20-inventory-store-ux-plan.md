# Inventory and Store Experience Implementation Plan

> **For implementation:** Execute this plan as small verified steps. Preserve existing AlpineJS behavior and keep the visual work limited to the shared app shell, sign-in entry screen, and inventory/store experience described below.

**Goal:** Give Spares Tracker a more deliberate, polished visual hierarchy while keeping inventory workflows, permissions, data, and semantic stock states unchanged.

**Approach:** Extend the existing CSS token system in `static/mystyle.css`, refine the sign-in treatment in `static/login.css`, and make only the markup changes needed in `static/index.html` to support a clear desktop shell and a compact mobile navigation. Keep the existing AlpineJS panel state, search/filter expressions, and stock actions intact. Add source-level regression assertions and review rendered screenshots at mobile, tablet, and desktop sizes.

**Frontend stack:** Static HTML, AlpineJS, CSS, vanilla JavaScript. No new framework, font package, or image dependency.

## Guardrails and Assumptions

- The accepted first slice covers the all-stores inventory view, the all-stores list, and selected-store inventory. It does not restyle unrelated admin, report, equipment, or superadmin screens beyond shared shell/token effects.
- Desktop navigation stays visible within the application shell. “Persistent” means consistently present while navigating app panels, not fixed or sticky while scrolling.
- Mobile navigation becomes a single accessible menu control that exposes the same seven destinations. Management actions remain in their existing separate disclosure.
- The primary mobile stock reading order is part/description, available quantity and stock state, store/location context when relevant, then actions. Work order remains available as supporting detail.
- The existing sign-in value proposition is retained and tightened only if needed to remove redundant copy. No unverified customer, security, or service claims are added.
- Keep the established brand palette and all semantic success, warning, error, and stock-state colors. Do not alter application logic, API calls, or authorization rules.

## Implementation Tasks

### 1. Lock behavior and markup contracts before changing presentation

**Files:** `regression_tests/test_inventory_usability.cjs`, `regression_tests/test_inventory_browsing_ui.cjs`, `regression_tests/test_navigation_ui.cjs`, `regression_tests/test_account_menu_ui.cjs`, new focused UI regression test if required.

- Add assertions for the current search, store selector, clear filters, open-store action, refresh control, Add Stock action, and management disclosure being present exactly once in the appropriate inventory shell.
- Assert that navigation controls retain their existing panel target expressions and active/current-page semantics.
- Assert that stock table cells retain accessible labels and low-stock text semantics.
- Add a markup contract for the mobile navigation control: accessible name, `aria-expanded`, controlled menu relationship, and all existing destinations represented.
- Keep tests behavior focused; do not assert incidental class ordering or exact whitespace.

**Verify:** `node --test regression_tests/test_inventory_usability.cjs regression_tests/test_inventory_browsing_ui.cjs regression_tests/test_navigation_ui.cjs regression_tests/test_account_menu_ui.cjs`.

### 2. Establish reusable visual tokens and app-shell grid

**Files:** `static/mystyle.css`.

- Add shared tokens for the single system sans-serif stack, typography scale/line heights, spacing, control heights, border radii, borders, restrained elevation, and visible focus treatment.
- Keep the current brand color values unchanged; use semantic variables only for shared chrome and neutral surfaces.
- Define a consistent content grid and spacing for the app container, header, page heading, navigation, toolbar, and results.
- Reduce stacked shadows and arbitrary local values only in the scoped shell and inventory/store components. Do not perform a broad CSS cleanup.
- Check contrast for primary navy/amber and supporting slate text, including hover, focus, and disabled controls.

**Verify:** existing CSS/brand assertions plus a manual contrast review; run the targeted tests from Task 1.

### 3. Refine the shared shell and responsive navigation

**Files:** `static/index.html`, `static/mystyle.css`, focused navigation UI regression test.

- Organize the existing header, current-view heading, primary nav, management disclosure, and content controls into a consistent alignment grid without changing panel order or action semantics.
- Keep all seven day-to-day destinations available on desktop in the shell.
- On narrow viewports, replace the wrapping row of seven buttons with a compact menu button and a menu containing the same buttons. Support keyboard activation, Escape to close and restore focus, outside click close, and accurate `aria-expanded` state.
- Keep the account menu's existing accessible name and behavior unchanged.
- Maintain management role visibility and existing disclosure behavior.

**Verify:** `node --test regression_tests/test_navigation_ui.cjs regression_tests/test_account_menu_ui.cjs regression_tests/test_inventory_usability.cjs`; manually check keyboard-only navigation and focus restoration at 390 px.

### 4. Make inventory and store selection the clear first task

**Files:** `static/index.html`, `static/mystyle.css`, `regression_tests/test_inventory_browsing_ui.cjs`, `regression_tests/test_inventory_usability.cjs`.

- Group the existing search field, store selector, clear filters, and open-store action as one clearly labeled toolbar. Keep common search/store controls visible without extra disclosure steps.
- Keep result count and refresh discoverable, and style Add Stock as the primary allowed action without changing its existing permission behavior.
- Apply the same hierarchy to all-stores inventory, all-stores listing, and selected-store inventory.
- On mobile, render stock rows as readable cards using existing responsive table semantics and data labels. Make quantity/status easy to scan and actions reachable at 44 px minimum touch height, without horizontal scrolling for primary fields.
- Preserve low-stock indicators, read-only labels, loading/failure/empty/no-results states, and transfer/count/import/export actions.
- Avoid introducing new store filters, hiding common controls, changing search matching, or moving controls in a way that adds task steps.

**Verify:** targeted browser-source tests; manually exercise all-store search/filter, open a store, search within it, inspect stock/status, and perform a permitted stock action.

### 5. Align sign-in and shared typography with the restrained system

**Files:** `static/login.css`, limited shared token references in `static/mystyle.css`, `static/index.html` only if copy/layout needs a small markup adjustment.

- Align the sign-in card, brand, short value proposition, and form to the same type and spacing system.
- Keep sign-in as the sole primary action and password recovery secondary. Do not add testimonials, promotional panels, carousel content, extra buttons, or decorative imagery.
- Preserve the current logo SVG, form field labels, autocomplete attributes, error message semantics, and loading state.
- Keep mobile login content compact enough that the form is immediately visible without unnecessary decorative space.

**Verify:** existing login/authentication regression tests and keyboard/focus review at 390 px and 1440 px.

### 6. Complete visual and regression verification

**Files:** tests added/updated above; no additional product behavior files.

- Capture screenshots of sign-in, inventory, all stores, and selected-store inventory at 390×844, 768×1024, and 1440×900.
- Review for clipping, unintended horizontal scrolling, hierarchy, first-viewport access to search/store controls, and a balanced whitespace-to-data ratio.
- Verify focus visibility, keyboard operation, 44 px mobile targets, accessible mobile-nav state, and status meaning without color alone.
- Run the complete frontend regression suite and backend suite; backend tests should remain unchanged but ensure no accidental integration regressions.

**Verify:**

```bash
node --test regression_tests/*.cjs
pytest regression_tests -q
```

If local PostgreSQL is not configured, use the repository's CI setup from `.github/workflows/postgres-tests.yml` or run the PostgreSQL suite in CI before merge.

## Acceptance Criteria

- The same stock lookup and store workflows remain available with the same behavior and permissions.
- The desktop shell, sign-in screen, and inventory/store views use a consistent grid, spacing, type hierarchy, and restrained surfaces.
- Mobile navigation is compact, keyboard operable, screen-reader named, and provides all current destinations.
- Mobile stock records expose part identity, quantity/status, relevant store context, and allowed actions without horizontal scrolling.
- Store selection and search remain visible in the first useful mobile viewport.
- Brand and semantic colors remain distinguishable and accessible; no fabricated trust claims or generic imagery appear.
- All existing tests and the new focused UI contracts pass, and screenshots at the specified widths have been reviewed.

## Risks

- `static/index.html` carries many unrelated views; keep markup edits anchored to the shared header/navigation and inventory/store blocks.
- `static/mystyle.css` contains overlapping responsive rules; verify computed behavior at all target widths rather than deleting rules by inspection alone.
- A mobile navigation toggle can regress keyboard/focus behavior; test Escape, outside click, and focus restoration explicitly.
- Screenshot capture depends on a working local or deployed app and test account. If the hosted site remains unavailable, use a local run with an available test account and record that limitation.

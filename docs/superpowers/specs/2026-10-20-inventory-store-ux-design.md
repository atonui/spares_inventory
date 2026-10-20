# Inventory and Store Experience Design

**Status:** Proposed for review

**Date:** 2026-10-20

**Baseline:** `1c61265` (`main`, PR #205)

## Purpose

Improve the perceived quality and day-to-day usability of Spares Tracker by
making the inventory and store experience feel like a coherent, deliberate
product. The first implementation slice focuses on the core task of selecting a
store, finding stock, and understanding available quantities. Shared visual
rules established in this slice will be used to improve the rest of the app in
later work.

The product is for inventory staff and field-service engineers. Its visual
style should remain clean, practical, modern, and legible in work settings.

## Goals

- Give the app a consistent visual hierarchy across the header, navigation,
  page heading, actions, filters, and stock results.
- Make the store selection and stock lookup path quick to scan and operate on
  desktop and mobile.
- Establish reusable visual tokens and component rules beyond the existing
  brand colors.
- Apply intentional visual restraint: whitespace, consistent alignment, clear
  hierarchy, and progressive disclosure instead of decorative complexity.
- Preserve current workflows, permissions, data, and semantic stock/status
  colors.
- Improve visual QA so layout regressions are checked at representative screen
  sizes, alongside the existing behavior and accessibility tests.

## Out of scope

- Changing inventory, store, transfer, consumption, or reporting behavior.
- Changing user roles, permissions, or tenant behavior.
- Replacing AlpineJS or introducing a frontend framework.
- Redesigning every administrative, report, equipment, or superadmin screen in
  the first slice.
- Introducing a dark theme or changing the established brand palette.
- Adding heavy animation, carousels, generic stock photography, or decorative
  graphics that do not help staff complete inventory tasks.

## Current-state evidence

- `static/index.html` is approximately 143 KB and contains the app shell and
  many view templates. Its JavaScript behavior is split into modules, but the
  primary HTML surface remains large.
- `static/mystyle.css` is approximately 40 KB and 1,247 lines. It defines the
  palette at the root, while many layout, typography, spacing, border, and
  elevation values remain local declarations. Responsive rules are distributed
  across several media-query blocks.
- The inventory area currently places the view heading, refresh action,
  navigation, management disclosure, and inventory filters in the same
  controls surface. Primary navigation contains seven destinations.
- Recent merged UI work improved the icon set, brand colors, and account menu
  behavior (PRs #198–#205). These changes address important details but do not
  define a complete shared visual system.
- Existing regression tests protect many UI behaviors and accessibility
  contracts. They do not provide a rendered visual baseline.

The live site could not be rendered during the initial audit because the
inspection browser received an upstream connection error on both the custom
domain and the legacy Railway URL. The findings above are source-based; the
first implementation review must include fresh screenshots from a working
deployment or local run.

## Proposed experience

### Shared app shell

- Use a compact header with the Spares Tracker wordmark, current workspace or
  user context where already available, and the existing account control.
- On desktop, present the existing primary destinations as a persistent,
  compact navigation region. Keep management actions visually separated from
  day-to-day destinations and retain their existing role visibility.
- On narrow screens, keep the header compact and place navigation behind an
  accessible menu. Preserve the user's current icon-only account control.
- Keep the page title and its main action close together so the current view
  and the primary task are immediately clear.
- Use generous but functional whitespace: separate sections clearly without
  pushing inventory data below the first useful viewport.
- Align the shell, page heading, toolbar, and results to a consistent grid and
  repeat spacing patterns across the screens in scope.
- Reveal secondary management actions through the existing disclosure pattern
  while keeping common inventory actions immediately visible.

### Sign-in entry screen

- Keep the first view focused on the product identity, a concise explanation
  that Spares Tracker helps teams manage parts across stores and field work, and
  the sign-in form as the single primary action.
- Keep password recovery available as a secondary link. Do not add competing
  marketing buttons, carousels, or promotional panels to the sign-in flow.
- Use verified support or privacy information only where it is already
  available; do not invent testimonials, customer counts, or trust claims.

### Inventory and store slice

- Group store selection, search, and filters into one clearly labeled toolbar.
- Keep the current search and filtering behavior, labels, and available options.
- Keep the common store selector and search immediately available; place any
  genuinely secondary controls behind a clear disclosure only if the current
  workflow can still be completed without extra steps.
- Present stock results with a clear reading order: part identity, store or
  location context, available quantity, stock status, then row actions.
- On desktop, retain a compact, readable table suited to scanning many parts.
- On mobile, present each stock record as a legible row/card with quantity and
  the most-used action easy to find. Avoid requiring horizontal scrolling for
  the primary fields.
- Keep `Add Stock` as the primary action where the user's current permissions
  allow it. Preserve other actions and their existing semantics.
- Give loading, no-results, empty-store, error, and success states consistent
  spacing and clear next steps.

### Visual foundation

Keep the approved palette:

| Role | Value |
| --- | --- |
| Brand navy | `#15263B` |
| Brand amber | `#E9A23B` |
| Supporting slate | `#64748B` |
| Page background | `#F5F7FA` |
| Surface | `#FFFFFF` |

Add shared tokens for typography, spacing, control heights, border radius,
border colors, elevation, and focus treatment. Use navy and amber for brand
actions and emphasis, while keeping stock levels, errors, warnings, and success
states semantically distinct. Prefer restrained borders and elevation over
stacked, heavily shadowed cards.

Use one primary sans-serif font stack for this workflow. Build hierarchy with
type size, weight, and line height rather than adding decorative font families.
Use the existing custom logo and functional icon set where they clarify
meaning; do not add generic stock imagery to operational screens. Keep visual
transitions subtle and avoid motion that delays or distracts from stock work.

## Responsive and accessibility requirements

- Validate at 390×844, 768×1024, and 1440×900 viewports.
- Keep controls keyboard operable and provide visible focus states.
- Maintain at least 44 px touch targets for primary mobile controls.
- Preserve accessible names for icon-only controls and the current account
  menu's Escape, outside-click, and focus behavior.
- Verify text and control contrast, including navy text on amber actions.
- Support zoom and long labels without clipping or overlap.
- Keep semantic colors and do not rely on color alone to convey stock status.
- Keep the first viewport useful on mobile: users should reach store selection
  and stock search without scrolling through brand decoration or oversized
  whitespace.
- Keep page loads light by avoiding unnecessary fonts, large imagery, and
  motion-heavy assets.

## Implementation sequence

1. Add the shared visual tokens and establish the app-shell layout without
   changing behavior.
2. Apply the system to the inventory/store selection and stock-list experience.
3. Review desktop and mobile screenshots, then adjust the design before
   extending the patterns to other views.
4. Migrate remaining shared controls and selected high-use views in later,
   separately reviewed slices.

Remove or consolidate obsolete declarations only where they conflict with the
new shared rules. Avoid a broad CSS rewrite unrelated to the selected screens.

## Verification

- Run the existing JavaScript regression suite and relevant Python tests.
- Preserve current role-based visibility, navigation actions, search/filter
  behavior, stock actions, and empty/error/loading behavior.
- Add or update targeted assertions only where needed to protect responsive
  semantics and accessibility contracts.
- Capture and review screenshots at the three specified viewports. Automated
  behavior tests alone are not acceptance for visual polish.
- Manually walk through selecting a store, finding a part, reading its
  available quantity/status, and performing an allowed stock action.

## Open review points

- Confirm the proposed desktop persistent navigation and mobile menu treatment.
- Confirm the first screen slice should cover both the all-stores inventory
  view and selected-store inventory view, or start with selected-store view
  only.
- Confirm the mobile stock row/card priority order before implementation.
- Confirm the concise sign-in value proposition and single-action treatment.

These are design review items; no workflow or product behavior changes are
assumed unless separately approved.

# Spares Tracker Site-wide Visual System

**Status:** Proposed for review

**Date:** 2026-10-20

**Baseline:** `205acbb` (`main`, merged PR #226)

## Purpose

Extend the restrained visual style established in the inventory table refresh
across the full Spares Tracker web application. The product serves inventory
staff, administrators, and field-service engineers who need to scan operational
data and complete routine tasks quickly on desktop and mobile.

The reference style is practical and quiet: clear type hierarchy, aligned
controls, compact data rows, subtle dividers, useful whitespace, and secondary
row actions behind a small overflow menu. The visual system should feel
consistent across the app without forcing every screen into the same layout.

## Goals

- Give the application a consistent visual language for typography, spacing,
  page headings, controls, surfaces, status messages, and focus states.
- Carry the compact desktop table and readable mobile row treatment to
  operational screens where they support scanning and action.
- Make forms, reports, account settings, and administration pages feel related
  while preserving layouts suited to their tasks.
- Keep mobile layouts readable and touch-operable, with no clipped controls or
  accidental horizontal page scrolling.
- Preserve the approved Spares Tracker palette and the meaning of existing
  status colors.
- Improve visual review across sign-in, workspace, account, and administrative
  surfaces.

## Scope

The web application surfaces in scope are:

- The main workspace shell and its inventory, store, transfer, replenishment,
  report, activity, equipment, and management panels.
- Sign-in and account entry pages, including password recovery, password reset,
  invitation acceptance, and email-change confirmation.
- Profile and superadmin pages.

The native mobile app is not part of this pass. Backend logic, APIs, database
schemas, billing, deployment, product copy changes, and business workflows are
also out of scope.

## Design direction

### Visual foundation

Keep the established palette:

| Role | Value |
| --- | --- |
| Brand navy | `#15263B` |
| Brand amber | `#E9A23B` |
| Supporting slate | `#64748B` |
| Page background | `#F5F7FA` |
| Surface | `#FFFFFF` |

Use the existing single system sans-serif stack. Build hierarchy with a small,
consistent scale of sizes, weights, and line heights. Use the existing shared
tokens for spacing, control height, borders, radius, focus, and restrained
elevation; consolidate duplicates only as a screen is brought into scope.

Prefer white surfaces, light neutral page backgrounds, fine dividers, and
limited elevation. Avoid nested cards, decorative gradients, unnecessary
shadows, and accent colors that compete with stock and workflow status colors.
Navy remains the primary action color. Amber remains a restrained brand accent.
Errors, warnings, success, low-stock, and other statuses retain distinct
semantic colors and readable text labels.

### Shared page structure

- Align the page title, supporting description, primary action, filters, and
  results to a consistent content grid.
- Keep the current task and its main action visually easy to identify.
- Group related controls into compact toolbars with consistent spacing.
- Separate management and destructive actions from routine actions, following
  the existing permission and disclosure rules.
- Use restrained section headers and panel surfaces. Avoid repeating the same
  title in a page heading and its immediate content panel.
- Keep loading, empty, no-result, success, warning, and error states legible and
  consistent without changing their content or behavior.

### Tables and row actions

- Use the merged inventory table treatment as the reference for compact
  desktop data tables: understated headers, clear column alignment, subtle row
  separators, and visible emphasis for the primary identifier and key value.
- Put secondary per-row actions behind a compact accessible overflow control
  when that reduces clutter; keep frequent or safety-critical actions directly
  available when needed for the task.
- On mobile, use stacked rows/cards when the record can be understood without
  losing relationships between columns. Keep the identifier, key value/status,
  relevant location or context, and allowed actions in a predictable order.
- For genuinely wide analytical tables, retain clear column labels and use an
  explicit responsive strategy rather than allowing the page itself to overflow.
- Preserve all existing row actions, permission checks, filters, sorting,
  pagination, exports, status meaning, and accessible table semantics.

### Forms and controls

- Use a consistent control height, border, radius, label style, help-text
  spacing, and visible keyboard focus treatment.
- Keep primary, secondary, and destructive actions visually distinct and
  consistent across the workspace and standalone pages.
- Preserve existing labels, validation, loading/disabled states, field order,
  autocomplete behavior, confirmation steps, and error semantics.
- Maintain minimum 44 px touch targets for primary mobile controls and
  accessible names for icon-only controls.

### Responsive and accessibility requirements

- Review representative surfaces at 390×844, 768×1024, and 1440×900.
- Preserve keyboard operation, clear visible focus, logical reading order, and
  accessible names.
- Maintain readable contrast for text, controls, and focus indicators. Do not
  rely on color alone for status.
- Support zoom, long part numbers, long store names, and validation messages
  without clipping or overlapping controls.
- Respect reduced-motion preferences and avoid adding decorative motion.
- Keep common tasks and their primary controls accessible on the first useful
  mobile viewport where practical.

## Rollout

Implement the visual system in reviewable slices:

1. **Shared foundation and workspace shell:** consolidate shared tokens and
   align common headings, navigation, buttons, inputs, toolbars, and panel
   surfaces.
2. **Operational workspace:** extend the table, filter, status, empty-state,
   and responsive row patterns through inventory, stores, transfers,
   replenishment, reports, activity, equipment, and management panels.
3. **Account and platform pages:** align sign-in, recovery, invitation,
   confirmation, profile, and superadmin pages to the same tokens and control
   language while preserving their distinct layouts.

Each slice should be independently reviewable and retain focused regression
coverage. Shared CSS changes must be checked against all page families they
affect. Avoid broad markup or stylesheet rewrites unrelated to visual
consistency.

## Behavior and content constraints

- Do not change business logic, API calls, data shape, authentication, tenant
  boundaries, permissions, or role-based visibility.
- Do not add features, remove workflow steps, or change the meaning of labels
  and status messages as part of the visual pass.
- Do not add new fonts, image dependencies, promotional content, or fabricated
  trust claims.
- Preserve the stock action menu behavior and visual rules merged in PR #226.

## Verification

- Run focused frontend regression tests for every screen family changed, then
  run the complete frontend suite.
- Run relevant backend tests to confirm the visual-only changes do not affect
  server behavior.
- Capture and review representative screenshots at the three target
  viewports for each rollout slice.
- Manually check navigation, form focus, row action menus, empty/error/loading
  states, and responsive behavior on representative workspace and standalone
  pages.
- Run `git diff --check` before each review handoff.

## Acceptance criteria

- Workspace, account, and administration pages visibly share the same
  restrained palette, typography, spacing, control, and surface rules.
- Dense operational data remains easy to scan on desktop and understandable
  on mobile.
- Forms and actions remain accessible and usable at supported mobile widths.
- Existing workflows, content semantics, permissions, and data behavior are
  unchanged.
- All changed screen families have passing regression coverage and reviewed
  screenshots at the specified sizes.

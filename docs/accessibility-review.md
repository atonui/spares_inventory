# Signed-in UI accessibility review — 29 October 2026

Scope: workspace inventory, stores, equipment/calibration, replenishment,
dialogs, account settings and platform administration. This review used source
inspection and automated regression checks; it is not a WCAG conformance claim.

## Changes

- Keep all three CSV import inputs in keyboard navigation. Their native file
  controls remain visually hidden, and the visible label gains a focus outline.
- Make Export a named disclosure with a linked group of ordinary buttons.
  Escape closes it and restores the trigger; Tab out dismisses it; choosing an
  export restores focus after invoking the existing action.
- Add a keyboard-visible skip link to the focusable main workspace.
- Increase mobile row-action controls and filter/export actions to at least
  44px high. Keep drawer navigation links at least 44px high at drawer widths.
- Rebuild generated CSS and refresh stylesheet versions on every consuming page.

## Existing behavior checked

- Form controls across HTML pages have associated labels or accessible names.
- Inventory dialogs expose names and modal semantics, move focus on opening,
  wrap Tab/Shift+Tab, close with Escape and restore the opener.
- Mobile navigation has a named trigger, expanded state, keyboard focus wrapping
  and a dismiss control. Account actions support Escape and focus departure.
- Profile tabs have selected state, roving tab stops and arrow/Home/End bindings.
- Existing automated contrast checks cover buttons, table headers and calibration
  status badges. Status colours retain their meanings.

## Verification

- Focused accessibility and interaction regressions: 68 passed.
- Full frontend regressions: 862 passed, 5 failed. The same five profile
  email/password security tests fail on unchanged main (`a66746a`); they are
  outside this change.
- Generated CSS freshness and `git diff --check`: passed.

## Manual verification still required

In the deployed signed-in UI, check VoiceOver on iOS and keyboard/screen-reader
navigation on desktop, including native file-picker activation, modal reading
order, visible focus, and touch targets. No authenticated browser or assistive
technology session was used in this review.

# Button style guide

Use this guide for compact button groups in Spares Tracker, especially inventory and store headers.

## Match the supplied Filter and Export reference

- Keep buttons in the same action group visually equal. Do not make one button brighter, filled, larger, or bolder to imply priority.
- Use a quiet outlined treatment: white surface, neutral border, navy text, and a subtle neutral hover state.
- Give each button a consistent height, padding, corner radius, font weight, and icon size.
- Put a simple line icon before a short text label. Keep labels visible; reserve icon-only controls for familiar actions such as Close and provide an accessible name.
- Do not add decorative dropdown arrows, group boxes, or divider lines. Use an indicator only when the control actually opens a menu or disclosure.
- Keep the group compact and aligned with its related heading or search field. Let it wrap cleanly on narrow screens without horizontal scrolling; retain touch-friendly targets on mobile.

## Implementation

- Reuse the shared button and icon styles and design tokens in `static/mystyle.css` (`--brand-surface`, `--brand-border`, `--brand-navy`, spacing, and radius tokens).
- Avoid inline styles and one-off color treatments for individual buttons in a peer group.
- Preserve each control's existing behavior, permissions, accessible label, focus ring, and disabled state when changing its appearance.

When in doubt, follow the supplied compact outlined **Filters** and **Export** buttons: matching visual weight, clear labels, and simple icons.

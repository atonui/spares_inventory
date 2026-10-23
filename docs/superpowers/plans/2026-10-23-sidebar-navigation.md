# Sidebar navigation implementation plan

## Goal
Replace the crowded horizontal navigation and collapsed Management disclosure with the selected reference pattern: a light, labeled sidebar on wide screens and a working drawer on narrower screens. Keep inventory actions in the page content and keep the store picker limited to its dedicated `id`/`name` option data.

## Scope
- Restructure the authenticated inventory shell into a desktop sidebar and content area.
- Move main destinations and role-authorized management destinations into labeled sidebar sections.
- Use text links with icons and a restrained navy selected state.
- At tablet/mobile widths, hide the sidebar and expose a menu trigger that opens a dismissible navigation drawer; Escape and selection close it and return focus appropriately.
- Preserve existing panel flags, loaders, role gates, account actions, search/filter behavior, and store picker data contract.
- Do not change authentication, permissions, business rules, or deployment settings.

## Test-first steps
1. Update visual-contract tests for the sidebar sections, link destinations, accessible drawer state, role gates, and responsive layout.
2. Run the focused regression tests and confirm the new structure/style assertions fail before implementation.
3. Implement sidebar/drawer markup and CSS; preserve active panel state and existing loaders.
4. Run the complete frontend regression suite, syntax checks, and `git diff --check`.
5. Review the rendered shell at desktop, tablet, and mobile sizes if a usable browser environment is available.
6. Commit, push the feature branch, and open a focused PR. Do not deploy.

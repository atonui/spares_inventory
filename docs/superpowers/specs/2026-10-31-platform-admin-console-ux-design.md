# Platform Administration Console UX Design

**Status:** Approved concept; written specification for review
**Date:** 2026-10-31
**Scope:** PostgreSQL SaaS platform-administrator interface only

## Goal

Make the platform-administration experience feel like a focused operations console. Help platform administrators understand platform-level attention items, find an organization, perform audited lifecycle actions, and enter the existing read-only support workflow without confusing platform authority with tenant membership.

## Current state

The SaaS interface is rendered from `static/superadmin.html`, styled by `static/superadmin.css`, and driven by `static/js/pages/superadmin.js`. It currently exposes Overview, Security Settings, System Announcement, Organizations, contextual Customer Support, Platform Administrators, and Platform Audit. The legacy SQLite superadmin screens share the same document but are shown only outside SaaS mode.

The existing platform API already supplies dashboard totals, organization search/status pagination and counts, platform-admin management, organization suspension/reactivation, announcements, security settings, filtered platform audit events, and short-lived audited support sessions. The redesign will reuse those behaviors and data contracts. It will not add a general tenant-user directory, tenant inventory browsing, impersonation, billing controls, feature flags, or operational telemetry that the backend does not currently provide.

## Navigation and page structure

Use a persistent desktop sidebar, compact mobile navigation, and a clear page title/action area. Group destinations as:

**Platform**

- Overview
- Organizations
- Customer support, shown as active/contextual when a support session exists and otherwise entered from an organization’s support action

**Administration**

- Platform access
- Security settings
- Announcements
- Audit log

Keep the signed-in platform administrator identity visible in the sidebar footer. Use an explicit platform-level context marker in the header. Do not expose tenant workspace navigation from this console.

## Screen behavior

### Overview

Present a small set of platform metrics derived only from `/api/platform/dashboard`: active and total organizations, active identities, platform administrator count, and invitation-mail pending/failed counts. Keep the pending and failed mail figures distinguishable. Add a “Needs attention” area that calls out failed invitation delivery when `mail_failed` is nonzero and a recent platform activity list sourced from the existing platform audit endpoint. Empty and error states must remain explicit; a zero count must not be presented as a service-health guarantee.

### Organizations

Make the directory the main tenant-portfolio view. Retain name/slug search, status filtering, pagination, active-member count, pending/failed invitation counts, creation date, and the existing status controls. Move organization provisioning behind one primary “Create organization” action that opens a focused form with organization name, URL slug, and initial owner email; preserve existing validation and invitation behavior.

Opening an organization should show its status, slug, created date, active member count, invitation-mail counts, lifecycle actions, and recent platform events filtered by organization. Use only fields provided by the directory and filtered audit API. Do not add a tenant member roster or claim an owner count unless an existing response provides it. Keep suspension/reactivation confirmation and reason auditing intact. Offer “Start support session” in this organization context.

### Customer support

Retain the current short-lived, organization-scoped, read-only workflow. The workspace must clearly display the selected organization, reason, remaining time, read-only limits, and end-session action. Keep exact-identifier lookup, allowlisted resource types, loading/empty/error/retry states, and audited reads. Starting a session continues to require the existing reason and password confirmation. Never make the support workspace resemble ordinary unrestricted tenant browsing.

### Platform access, Security settings, Announcements, and Audit log

Retain all currently available operations and safety semantics. Platform access continues to list only platform administrators and supports existing grant/revoke flows. Security settings continue to use the existing global security-policy endpoint. Announcements retain the existing audience, schedule, expiry, conflict, and publication behavior. The audit log retains its current filters, pagination, curated details, and UTC timestamps while receiving a more readable activity presentation. No permissions or backend contracts change.

## Visual direction

Use Spares Tracker’s established palette: navy `#15263B`, amber `#E9A23B`, slate `#64748B`, page `#F5F7FA`, and white surfaces. Follow the supplied button guide: one dominant primary action per task context, outlined secondary controls, explicit destructive labels and confirmations, visible focus, and minimum 44 px interactive targets where practical, especially on mobile.

Use the supplied Offset line-icon geometry (24 px grid, 1.75 px rounded stroke, 1.6 px down-right accent registration). Subdue it per the user’s feedback: muted slate strokes and a low-opacity, desaturated amber offset; icons must support hierarchy rather than compete with labels or primary actions. Keep accessible text labels for navigation and actions; do not rely on icons or color alone.

Preserve the existing type scale and visual tokens from the shared app system. Prefer quiet surfaces, restrained borders, clear spacing, and responsive tables/details over dense admin styling. The mobile view must keep primary actions and organization status readable without forcing horizontal scrolling for essential information.

## Technical boundaries

- Change only the SaaS platform-administrator presentation and its client-side orchestration.
- Preserve the shared HTML document’s legacy SQLite superadmin rendering and behavior.
- Reuse existing platform APIs; do not add endpoints, database objects, permissions, or background jobs.
- Keep tenant and platform identity boundaries explicit in labels, navigation, and organization context.
- Keep platform administrative mutations reason-confirmed and audited as they are today.
- Preserve keyboard navigation, dialog focus management, accessible names, and loading/error/empty states.
- No new frontend framework or third-party dependency.

## Acceptance criteria

1. In SaaS mode, the navigation and page hierarchy match the approved platform-operations concept and expose all existing platform-admin destinations.
2. Overview metrics and attention items map only to existing API fields and do not imply unavailable health or billing capabilities.
3. Organization search, status filter, pagination, provisioning, suspension/reactivation, and support-session entry remain functional.
4. Organization context uses only existing directory and audit data and never exposes a global tenant-member roster or inventory.
5. Support access remains visibly scoped, read-only, reason-recorded, time-limited, and endable.
6. Platform access, security settings, announcements, and audit behavior remain available with current semantics.
7. Offset icons are visually subdued and decorative accent layers do not reduce label or focus contrast.
8. At desktop and mobile sizes, controls remain usable, text does not clip, and key organization information is readable.
9. Legacy SQLite superadmin sections remain unchanged in behavior and visibility.

## Review notes

- The mockup uses fictional organization names and illustrative counts/events. Production values must come from existing API responses.
- The first implementation should preserve existing page behaviors while changing hierarchy and presentation. Any backend data gap discovered during implementation should be reported and kept out of scope pending a separate design approval.

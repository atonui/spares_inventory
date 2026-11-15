# Platform Invitation Delivery History

## Problem

The platform dashboard reports a count of failed organization invitation emails, but an administrator cannot identify the affected recipients or inspect whether other invitation messages were sent without opening each organization and using the resend workflow. This makes it difficult to triage delivery issues.

## Recommendation

Add a read-only, paginated invitation delivery history to the platform administrator dashboard. Keep the existing aggregate failure count and provide a nearby link or section that lists organization invitation messages across organizations.

Each row should show:

- Organization name and slug.
- Recipient email address.
- Queue/send state: pending, processing/claimed, sent, or failed.
- Provider delivery state when available: unknown, sent, delayed, delivered, bounced, complained, failed, or suppressed.
- Attempt count, created time, last updated time, sent time when present, and a sanitized failure code when present.

The view is limited to `organization_invitation` messages. It does not include owner welcome messages or other email types. It does not add a resend action; administrators continue to use the existing organization invitation workflow to resend.

## Semantics

`sent` means the email provider accepted the message. It does not prove that the message reached the recipient's inbox. Delivery outcomes appear only when the provider sends webhook events and the application records them. When no delivery event is known, show `unknown` rather than implying successful delivery.

## Security and privacy

- Require an authenticated platform administrator session and use the existing platform-authorized transaction path.
- Return only the organization identifiers/display fields and invitation delivery metadata needed by this screen.
- Never expose encrypted payloads, invitation URLs or tokens, idempotency keys, raw provider responses, or unsanitized error text.
- Apply bounded pagination and a stable newest-first ordering. Do not permit arbitrary message-type selection.
- Record a curated platform audit event when the history is read. Include safe filter and result-count metadata only; do not put recipient email addresses or message payload details in the audit event.
- Continue to rely on existing outbox role separation; do not grant broad direct table access to the application role. Use a narrowly scoped database function/view or equivalent authorized query path consistent with repository conventions.

## User experience

Add an “Invitation email history” section to the platform overview near the existing failed invitation notice. A compact table should make failed messages easy to scan while still showing successful and pending messages. Include pagination and clear empty/loading/error states. The recipient address is shown because identifying affected recipients is the requested capability.

## Alternatives considered

1. Add recipient details only to each organization’s administration page. This follows the current organization workflow but still makes a dashboard-wide failure count hard to investigate.
2. Add a global invitation history on the platform overview. This directly answers which organization and recipient were affected, and is the recommended approach.
3. Add controls to resend from the dashboard. This introduces a new delivery action and duplicate-send risk; it is outside the current request and can be considered separately.

## Out of scope

- Resending, canceling, or otherwise mutating invitation messages from the dashboard.
- Showing non-invitation email types.
- Retention or purge behavior.
- Changes to provider webhook configuration or delivery processing.
- Exposing message contents, invitation links, or tokens.

## Acceptance criteria

- A platform administrator can identify organization invitation recipients and their current send and known delivery states from the dashboard.
- Failed rows include a sanitized failure code and useful timestamps/attempt counts when available.
- Results are paginated and newest first.
- Non-platform users cannot access the history endpoint.
- Reading recipient-level history emits a curated platform audit event without copying recipient addresses into audit details.
- No sensitive message payload or invitation credential is returned to the browser.

# Platform Invitation Acceptance History

## Intent

Platform administrators need to know whether an organization invitation was accepted and when. The application already stores `accepted_at` and `accepted_by` on each invitation, but the platform console only exposes mail delivery records.

## Goals

- Provide a paginated, platform-admin-only history of organization invitations.
- Show organization, invitee email, role, invitation time, lifecycle status, and acceptance time.
- Keep invitation lifecycle separate from email provider delivery status.
- Reuse the existing invitation records; do not infer acceptance by matching recipient email to mail-outbox rows.

## Approaches

- **Acceptance event in recent activity:** small change, but old acceptances are not easy to find or filter.
- **Add acceptance columns to email delivery history:** convenient, but mail rows do not carry an invitation ID, and matching on organization plus email can confuse re-invitations and retries.
- **Dedicated invitation lifecycle history (chosen):** reads the invitation records directly and gives admins a durable, paginated view with accurate status and acceptance time.

## Design

Add a read-only platform API and a distinct invitation history section in the platform console. The data source is `organization_invitations`, exposed through a curated PostgreSQL view that joins organization display fields and accepted-user display fields while excluding the token hash. The route validates platform-admin authority, returns bounded pages, and orders newest invitations first.

Status is derived from stored timestamps: `Accepted` when `accepted_at` is set, `Cancelled` when `canceled_at` is set, `Expired` when neither is set and `expires_at` has passed, otherwise `Pending`. Show `accepted_at` in UTC and identify the invitee by the invitation email; where available, show the accepted account name as supporting context.

The existing invitation email history remains focused on provider queue and delivery outcomes. The two histories stay separate because an accepted invitation and a delivered email are different facts.

## Constraints and non-goals

- Only authenticated platform administrators can read the global history.
- The response must not expose invitation tokens, token hashes, encrypted payloads, or unrelated user records.
- Do not add acceptance notification emails, retention or purge behavior, or tenant invitation UI in this change.
- No change to invitation acceptance rules or mail delivery behavior.

## Success criteria

- A platform administrator can find an invitation and see whether it is pending, accepted, cancelled, or expired, with an acceptance timestamp when accepted.
- Multiple invitations for the same email remain distinct records.
- Pagination is bounded and stable; access is denied to non-platform sessions.
- Existing invitation delivery history continues to report provider status independently.

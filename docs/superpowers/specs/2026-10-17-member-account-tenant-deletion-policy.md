# Member, Account, and Tenant Deletion Policy Proposal

**Status:** Proposed policy for owner review. The tenant-deletion window below
has been selected by the product owner; the remaining decisions are not yet
approved for implementation.

## Purpose and scope

Define separate outcomes for company-member departure, personal account deletion,
and company deletion before any deletion UI, endpoint, or database migration is
built. This proposal is for the invitation-only SaaS using the shared PostgreSQL
tenant model. It does not authorize production data changes.

The current model has one membership per global user identity. Company records
and activity history can reference user IDs; activity rows also store usernames
and may contain IP addresses or user-agent strings. Account deletion therefore
must not cascade into a company's operational records or erase attribution
without a deliberate retention rule.

## Proposed action rules

### Remove or leave a company

- A company owner or authorized administrator may remove a member. A member may
  request to leave. The last active owner cannot leave or be removed until
  ownership is transferred to another active member.
- Removal takes effect immediately: revoke the member's active sessions and
  remove their membership so they have no access to that company. Keep the
  global identity so the person can accept a later invitation. Since an identity
  can belong to only one company at a time, removing the membership makes the
  person eligible to be invited to another company.
- Retain the company's inventory, work-order, equipment, movement, and other
  operational records. Removing a member does not delete the company or its
  data. Retain a proportionate audit event for the removal.
- An invited but not yet accepted address is not a member. Removing an inviter
  does not silently accept or delete the invitation; the company owner/admin
  must be able to cancel or reassign it. The exact reassignment behavior is an
  implementation detail to settle before the invitation flow is changed.

### Delete a personal account

- Offer a clearly labeled, confirmed in-app request and a public web request
  path for people who cannot sign in. The public path must not reveal whether an
  email address or company exists. A request is not proof of account control and
  must not itself delete data.
- Verify control of the account through an authenticated, recently
  reauthenticated session or a time-limited verification link sent to the
  account's existing address. Do not act on a request that cannot be verified.
- Resolve ownership first: an account with an active owner membership must
  transfer ownership or have its tenant deletion handled separately. Account
  deletion must never delete the company as a side effect.
- Remove the account's active company membership as part of deletion. Do not
  leave an inactive membership row that blocks the one-membership-per-identity
  rule or permits company access. This applies after ownership is transferred
  for an owner and directly for a non-owner.
- Once approved for execution, revoke all sessions and credentials, cancel
  pending invitations addressed to the account, and remove or anonymize direct
  account identifiers. Preserve company-owned operational records. Where a
  record must retain an actor reference for history or integrity, replace
  personal display fields with a non-identifying deleted-account label while
  keeping the minimum stable reference needed by the record.
- Remove the account's platform-admin assignment as part of account deletion.
  If historical foreign keys require the global user row to remain, disable
  sign-in, clear credentials and reset tokens, remove platform-admin privilege,
  and anonymize the row rather than retaining a privileged deleted identity.
- Keep an account-deletion request status and completion event without keeping
  the requester's email or other unnecessary personal details in that status
  record. Do not expose request existence through the public response.

### Delete a company (tenant)

- Treat company deletion as a separate owner-authorized request. Require recent
  reauthentication and an explicit confirmation that describes the company-wide
  impact. A user's account deletion is never a tenant deletion request.
- Before scheduling deletion, make a tenant data export available to the owner
  and record when it was requested and made available. Once the export is ready
  and the owner is notified, set a cancellation deadline exactly 30 calendar
  days later using UTC timestamps. Keep the tenant usable until that deadline;
  do not start destructive deletion during the cancellation period.
- An authorized owner can cancel the request before the recorded UTC deadline.
  Accept cancellation only when a transaction locks the request, verifies the
  deadline has not passed, and commits the canceled state; return success only
  after that commit. At or after the deadline, the deletion job must lock the
  same request and atomically confirm it remains active and no retention hold
  applies before marking deletion started. These serialized state transitions
  decide deadline races: a committed cancellation prevents deletion, and a
  request already marked for deletion cannot be canceled. Then revoke all
  tenant sessions and invitations, remove the tenant's operational data, and
  anonymize any minimal records that must remain for platform operations or
  audit purposes. Record the export-ready notice, cancellation deadline,
  cancellation (if any), and deletion start/completion times.
- Remove all memberships for the deleted tenant so its former members can be
  invited to another company. Retain their global identities for future
  invitations; tenant deletion does not delete individual accounts or remove
  an independent platform-admin assignment. Because current sessions are
  user-scoped, revoke every session belonging to a member of the tenant, even
  if that session also provided platform access. A platform administrator may
  sign in again under the ordinary platform-admin flow after tenant deletion.
- Do not delete a tenant with an unresolved legal hold or other approved
  retention exception. Restrict access to retained data, record the exception
  and its owner, and delete it when the hold ends.
- Notify the requester when the request is accepted, when the cancellation
  period starts or ends, and when deletion completes. Provide a support path for
  failed exports, cancellation, and contested requests.

## Retention and recovery rules

- Member removal retains tenant data. Personal account deletion removes or
  anonymizes the account's direct identifiers while preserving company-owned
  records and the minimum attribution necessary to interpret their history.
- Tenant deletion removes tenant data from the live database after the approved
  cancellation period, except for documented retention holds or narrowly
  justified platform records.
- Backups may retain deleted data until their documented expiry. The public
  policy must state the actual backup retention period before deletion features
  ship. A restore must reapply deletion requests completed after the restored
  backup was taken before the restored service is made available. The deletion
  ledger used for this must survive restoration of an older application backup
  or be independently recoverable; a tombstone stored only in the restored
  snapshot is insufficient.
- Keep deletion-request records only as long as needed to prevent duplicate
  processing, prove completion, and reapply deletions after restore. Store the
  least identifying information necessary for those purposes.
- Deletion audit records must record the action, outcome, timestamps, and
  responsible system/operator or organization, while avoiding unnecessary
  copies of email addresses, credentials, request contents, or tenant data.

## Safeguards and operations

- Public request submission and status responses must not confirm whether an
  account or tenant exists. Use rate limits and generic acknowledgements.
- Verify authority separately for a member action, personal-account request,
  and tenant request. Platform-admin status alone does not grant access to
  tenant inventory or authorize a tenant deletion.
- Make processing idempotent. Duplicate submissions must not create duplicate
  exports, delete another tenant, or change a completed request's result.
- Provide request tracking for authorized users and support staff. Restrict
  support access, record manual actions, and require a reason for an exception.
- Before enabling any deletion operation, test ownership transfer, last-owner
  protection, failed verification, duplicate requests, cross-tenant attempts,
  session revocation, export completion, cancellation, backup restore, and
  retention holds.

## Decisions required before implementation

The tenant-deletion cancellation period and access rule have been selected:
30 calendar days with the tenant usable until the deadline, and owner
cancellation allowed before it expires. The following values and behaviors
still require product-owner approval:

| Decision | Needed before | Current state |
| --- | --- | --- |
| Account-deletion completion target after verification | Request status and support workflow | Unset |
| Backup retention duration and restore procedure owner | Public deletion disclosure and deletion guarantees | Not documented in the SaaS runbook |
| Records that must be retained, reason, duration, and approver | Account and tenant deletion jobs | Unset; requires a verified business/legal basis |
| Export format, availability window, and download expiry | Tenant deletion request flow | Unset |
| Invitation handling when its inviter is removed | Member-removal flow | Unset |
| Notification channels and support contact | Request lifecycle | Unset |

No deletion endpoint, UI, scheduler, migration, retention promise, or production
operation should be implemented until these decisions are resolved and the
final policy is approved. The follow-on implementation should be split into
independently reviewable member removal, account deletion, and tenant deletion
work if the data-model changes make one combined change too broad.

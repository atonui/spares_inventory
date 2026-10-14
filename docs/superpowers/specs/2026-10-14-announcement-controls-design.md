# Announcement audience, schedule and dismissal controls

## Intent and approved scope

Give the owner finer control over the existing site-wide announcement: who sees
it and how long it stays visible. Retain one saved announcement at a time, as
approved. Add public/all-signed-in/selected-role audiences, immediate or scheduled
publication, optional expiry and optional dismissal. Do not add multiple notices,
per-user targeting, store targeting, push delivery or a notification inbox.

## Stored notice and compatibility

Keep the single notice in the existing system_settings record. In addition to
message, level and set_at, store an opaque revision ID, audience, selected roles,
starts_at, expires_at and dismissible. Each successful save creates a new revision;
previous dismissals no longer suppress the updated notice. The editor explains
that saving republishes the notice and resets dismissals. Remove deletes the saved
notice and its dismissals.

An existing notice without the new fields remains public, immediately active,
without expiry and non-dismissible. Give legacy notices a stable revision derived
from their stored payload until the next save. No automatic content or audience
change is made during upgrade.

## Audience enforcement

Audience choices are Everyone (including visitors), Signed-in users, and Selected
roles. Selected roles are engineer, manager, admin and superadmin. At least one
role must be selected; roles are exact matches with no implicit hierarchy.

The public banner read endpoint evaluates time and audience on the server. Missing
or expired sessions are anonymous; they receive only active public notices.
Authenticated eligibility uses the current active user and current database role,
not a role supplied by the client. Infrastructure/database errors remain errors,
rather than being treated as anonymous authentication failures. Responses for
ineligible, scheduled, expired or account-dismissed notices contain no message or
restricted metadata: announcement is null. Responses send Cache-Control: no-store
so intermediaries and browsers cannot reuse another audience's response.

Add a separate protected management read endpoint for superadmins. It returns the
saved notice regardless of schedule, audience or dismissal, with its status and
revision. The editor must use this endpoint; an expired or role-targeted notice
must remain editable. Existing create/remove endpoints remain protected by role,
active-session revalidation and CSRF checks.

## Schedule and time handling

The editor uses date/time inputs explicitly labelled with the organisation's IANA
timezone, never the device timezone. Blank start means publish immediately; blank
expiry means remain active until removed. Activity is start-inclusive and
expiry-exclusive. Expiry must follow the effective start; saving an already expired
notice is rejected. Existing public delivery remains periodic: initial load,
60-second visible-page polling and refresh when a page becomes visible. It is not
instant push delivery.

Convert organisation-local input to UTC on the server using the existing timezone
policy. Include the editor's timezone revision in saves; a changed organisation
zone requires reloading before retry. Reject ambiguous/nonexistent local times
rather than guessing a daylight-saving offset. Store and return canonical ISO UTC
instants. Editing an existing schedule reconstructs local inputs from its UTC
instants using the currently displayed organisation zone. Labels and summaries
make the resulting start/expiry explicit before saving.

The banner checks returned UTC expiry locally as well as polling, so an already
loaded notice is hidden at its expiry without waiting another minute. Resuming a
hidden/restored page refreshes eligibility. Role changes, revocation and newly
published notices propagate on the next successful eligibility check. Changes
cannot retract text already delivered to a client; targeted broadcasts must not
be treated as a confidential document delivery system.

## Dismissal

Non-dismissible notices have no dismiss control. Dismissible notices have an
accessible Dismiss button. Authenticated dismissal persists per user and revision
in a new announcement_dismissals table, with user foreign key, revision, canonical
UTC dismissed_at and a unique user/revision constraint. A protected CSRF POST
validates the current notice revision, dismissibility and eligibility inside the
existing authenticated transaction before recording dismissal. Repeated dismissal
is idempotent; a stale revision cannot dismiss a newer notice.

Anonymous public-notice dismissal is browser-local, keyed by revision. Only a
revision marker is stored, not the message. Clearing browser storage restores the
notice; storage failure still permits dismissal for the current page. The read
response identifies account versus browser dismissal mode. After sign-in, browser
markers must not suppress the account's server-controlled result. Account switches
and sign-out refresh eligibility and must not reuse another user's dismissal.

Add explicit migration v6 through the existing registry and validation workflow;
do not mutate any previously published migration/checksum. Clear obsolete dismissal
rows when saving/removing the one notice. Restore/backup and schema-validation tests
cover the new table.

## Editor and banner behaviour

Show audience selection, role checkboxes, publish-now/scheduled start, optional
expiry and dismissal controls alongside the existing message/severity fields.
Show Saved status: Scheduled, Active or Expired. Keep the saved preview separate
from unsaved form edits. Retain visible load/save errors and Retry; block conflicting
editor reads/writes as in the existing implementation.

Use revision-aware save/remove requests to reject stale administrative edits,
retaining the draft and requiring explicit reload after a conflict. The first
notice uses an empty expected revision; replacing/removing an existing notice
requires its current revision. Loading always obtains fresh protected metadata.

All five pages keep the shared banner and plain-text rendering. Loading failures
show a warning and Retry. For role-restricted notices, failure to revalidate
eligibility clears the displayed notice rather than retaining a possibly
ineligible stale message. Dismiss requests remain pending until server success;
on failure keep the notice visible with an actionable error. Clear polling,
expiry timers and listeners on component teardown. Avoid overlapping loads and
late responses overwriting a newer notice or dismissal.

## Validation and acceptance

Use disposable databases for write tests; do not change production settings or
broadcasts as part of verification. Cover every audience against anonymous and all
four roles, expired/revoked sessions, role changes, exact start/expiry boundaries,
no expiry, timezone-revision conflicts, DST gaps/folds and legacy notices. Verify
restricted text never appears in denied read responses and reads are not cached.

Cover account dismissal isolation/idempotence, stale revisions, non-dismissible
notices, anonymous storage failure, sign-in/account switches, save/reset/remove,
editor races and stale administrative edits. Test real shipped page references,
safe text rendering, accessibility, timer teardown and expiry hiding. Run all
Python/JavaScript regressions, syntax/diff checks and a fresh independent review.

After owner merge, verify deployment/assets and public endpoint behaviour.
Signed-in rendered desktop/mobile checks remain a separate gate while the recorded
browser credential-protection restriction applies. Do not reset or route around
that restriction; automated tests must not be reported as live rendered checks.

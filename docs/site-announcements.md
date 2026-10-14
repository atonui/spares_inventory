# Announcement controls

One notice is saved at a time. Superadmins can target Everyone (including visitors),
all signed-in users or selected exact roles: engineer, manager, admin, superadmin.
The server filters eligibility; denied, scheduled, expired and dismissed notices
return no message. Public notice text can be read without signing in. Targeting
is not a confidential-document delivery mechanism: delivered text cannot be
retracted from a client.

Schedule inputs use the organisation's displayed IANA timezone. The server resolves
local input into canonical UTC, rejecting daylight-saving gaps/folds and stale
timezone revisions. Blank start publishes immediately; blank expiry keeps the
notice until removed. Start is inclusive and expiry exclusive. Management metadata
retains scheduled/expired notices so the owner can edit or remove them. Stale
administrative saves/removals fail with a conflict; the draft remains until the
owner explicitly reloads. Every successful save creates a new revision and resets
previous dismissals.

Dismissible notices offer a Dismiss control. Signed-in dismissal persists per user
and revision across devices. Anonymous public-notice dismissal uses browser storage
and survives reloads there; unavailable storage falls back to the current page.
Signing in ignores anonymous dismissal markers. Non-dismissible notices have no
Dismiss control. Dismissal checks the active session, eligibility, current revision
and CSRF under the write lock; a pending failure leaves the notice visible.

All five pages check on initialization, every 60 seconds while visible, and when
visibility/session changes. Returned expiry also hides an already-loaded notice
without waiting for polling. Hidden pages refresh when resumed. Timers/listeners
are released on teardown. Responses are not cached; stale completions cannot
restore dismissed notices or another account's result. Restricted notices clear
when eligibility cannot be revalidated; errors remain visible with Retry.

Existing pre-controls notices remain public, immediate, unexpired and non-dismissible.
Migration v6 adds announcement_dismissals while preserving existing notice content
and v1–v5 migration checksums. Existing backups are upgraded through the explicit
migration runner and validated. A git revert alone is not a safe schema downgrade:
code that does not recognize v6 will reject the database. Rollback needs compatible
code or an appropriate validated backup, with explicit consideration of newer data.

Configuration writes still enforce 1–100 login attempts, 1–1440 lockout minutes,
1–720 session hours, 1–365 remember-me days and 1–365 calibration reminder days.
Authentication policy changes apply to new login decisions and sessions; existing
session expiry remains unchanged.

Tests use disposable databases and shipped-page JavaScript. Production settings
and broadcasts are not changed during verification. Live signed-in desktop/mobile
acceptance remains pending when browser credential protection blocks access.

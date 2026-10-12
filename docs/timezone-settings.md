# Organisation and personal timezone policy

The current app is still single-organisation. Migration 4 adds business timezone
settings with default `Africa/Nairobi`, revision 1, an explicit UTC update time,
and updating actor. Nullable `users.display_timezone` means organisation default.
This does not add tenant isolation. Reporting and calendar reminders now consume this policy.

`GET /api/timezone-context` returns the active user's organisation identity,
business timezone, effective display timezone and settings revision. The context
resolver checks an active account and returns an immutable value. Reporting/history
routes resolve it once inside their read transaction so a setting change
cannot mix policies during one request.

`PUT /api/organisation/timezone` accepts `timezone` and `expected_revision`.
It requires an active admin/superadmin, a valid session and CSRF. Conflicting
revisions return 409; unknown zones, bare abbreviations and extra fields return
422. The setting update and old/new zone/revision audit entry share a transaction.
This is separate from login Security Config.

`GET /api/profile` includes the saved optional display timezone. Existing profile
updates may include `display_timezone`: omission preserves the preference, explicit
null resets it, and a validated IANA region identifier saves it. Email behaviour
is preserved. Invalid stored zones never silently default.

Profile exposes the personal preference and a separate admin/superadmin business
control outside Security Config. Device detection is a suggestion only. Pending
requests disable duplicate submits; errors remain visible; a revision conflict
preserves the selected zone and requires an explicit saved-settings refresh.

Consumption JSON includes `timezone`, `timezone_revision`, `start_date`, `end_date`,
`start_utc`, `end_utc`. All-history bounds are null. CSV uses business-local instants
with offsets and a zone-labelled header. Optional `expected_timezone_revision`
rejects a stale export with 409; the frontend supplies the loaded report revision.

Public domain timestamp fields now use fixed-width RFC 3339 UTC (`.ffffffZ`).
Response shape/IDs/quantities and calendar dates stay unchanged. SQL console
results and audit details remain opaque; they are not domain timestamp contracts.
Invalid stored instants produce a sanitised operational error rather than a guessed
instant. Legacy SQLite writes remain UTC without offsets until the gated storage
migration. No production setting or timestamp cell was changed during development.

Date predicates compare normalised UTC instants through `utc_instant` on the read
connection. SQLite julianday rounds sub-second values at midnight, so it is not
used for day boundaries or instant ordering. Each request has a single policy
snapshot; each local boundary is independently resolved through ZoneInfo.

Movement/activity list JSON shapes are preserved. `X-Report-Time-Context` carries
the same metadata as consumption, and the browser captures it alongside each
loaded dataset for date-filter labels and CSV times. Activity statistics add the
metadata directly. History and comprehensive CSV creation/confirmation times use
the dataset business snapshot rather than the viewer's display preference.

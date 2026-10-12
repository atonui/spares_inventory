# Organisation and personal timezone policy

The current app is still single-organisation. Migration 4 adds business timezone
settings with default `Africa/Nairobi`, revision 1, an explicit UTC update time,
and updating actor. Nullable `users.display_timezone` means organisation default.
This does not add tenant isolation or change existing report boundaries yet.

`GET /api/timezone-context` returns the active user's organisation identity,
business timezone, effective display timezone and settings revision. The context
resolver checks an active account and returns an immutable value. Future reporting
routes will resolve it once inside their read transaction so a setting change
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

The UI controls and report/client formatting are the next coordinated release.
Until those routes consume the context, changing the business setting does not
change existing Nairobi report code. Do not advertise dynamic report timezone
support before that release. No production setting is changed by this PR; the
schema upgrade preserves stock, session expiry and historical timestamp cells.

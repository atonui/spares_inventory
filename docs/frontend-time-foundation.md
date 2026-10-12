# Frontend temporal foundation

`static/temporal.js` defines `InventoryTime` for the coordinated API/client timezone
release. It is intentionally not loaded by current screens yet: existing API
responses still include legacy naive strings, and the strict parser does not
guess their timezone. This foundation adds no live display or reporting change.

| Function | Contract |
| --- | --- |
| `parseInstant(value)` | Explicit RFC 3339 instant to epoch milliseconds; invalid/naive values return NaN |
| `formatInstant(value, zone)` | Gregorian `YYYY-MM-DD HH:mm:ss UTC±HH:mm` display using the explicit IANA zone; invalid values return `Unknown` |
| `formatDate(value)` | Valid `YYYY-MM-DD` unchanged; no browser timezone conversion |
| `isValidZone(zone)` | Region-style IANA identifier or UTC; rejects bare abbreviations and host-specific posix/right namespaces |
| `today(zone, instant?)` | Calendar date in the explicitly supplied business zone |
| `addDays(date, count)` / `daysBetween(first, last)` | Calendar arithmetic independent of device timezone or real elapsed DST hours |

`formatInstant` includes the actual offset so repeated local hours remain
distinguishable. UTC zero is displayed as `UTC`. Historical offsets containing
seconds may be emitted by Intl. Locale/calendar/numbering are fixed for this
initial consistent format; future display localisation must preserve semantics.

The parser matches the backend profile: uppercase T/Z, colon-delimited offsets,
seconds and up to six fractional digits, valid Gregorian dates, no leap seconds,
and representable UTC years 1–9999. Numeric browser instants have millisecond
precision; original API values are not rewritten. Local wall dates outside the
supported year range produce `Unknown`, not misleading BCE/overflow years.

Calendar display/validation does not instantiate Date. Calendar arithmetic uses
a synthetic UTC axis only for adding/subtracting plain dates, not interpreting
them as events or calculating elapsed real-world time. Report consumers must
pass response `timezone`; personal views pass effective display timezone. Browser
detection must remain a suggestion, never the reporting policy.

On 12 October 2026 the owner confirmed that existing timestamp values were
generated only by the app. Repository history contains SQLite CURRENT_TIMESTAMP
defaults from the initial commit and UTC Python expiry writers. This is new
provenance evidence for the upcoming field-by-field backend adapter review; this
PR does not change manifest policies, rewrite timestamps or claim current backup
readiness. A fresh snapshot remains required before the storage cutover.

The unused formatter is split from the coordinated release so it can be reviewed
independently without a partially upgraded client/API contract. API normalisation,
business-zone date boundaries, profile/business controls and consumer wiring
remain the next coordinated implementation stage.

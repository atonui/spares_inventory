# Frontend temporal foundation

`static/temporal.js` defines `InventoryTime` and is now loaded before the inventory,
profile and superadmin consumers in the coordinated API/client timezone release.
API responses emit explicit UTC; frontend code never guesses a naive value's zone.

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

Personal event displays use the effective zone from `/api/timezone-context`.
Consumption and superadmin audit use the zone captured in the report response,
including after a personal preference or business setting changes. CSV exports
supply the report revision; a changed business revision returns 409 and requires
refresh. Equipment reminders use business-calendar today without converting due dates.

Profile has separate personal and administrator business settings. Device timezone
is offered as a suggestion; only an explicit choice saves it. Missing context has
visible retry feedback and does not silently fall back to Nairobi or device time.
Stock data can still load while timezone context is unavailable.

Browsers may accept IANA identifier case or aliases that differ from the server;
server validation is authoritative for saves. UTC offsets in displayed instants
make DST repeated hours distinguishable. Cache versions are updated together.

No current production snapshot or storage cutover readiness is implied. The old
supplied snapshot is dated; a fresh standalone backup remains a separate gate.

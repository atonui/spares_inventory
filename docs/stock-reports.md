# Consumption reports and work-order history

Reports are read-only and require an active signed-in user. Admin and superadmin users can report on all consumption; other users see only events they recorded, regardless of who owns the work order. The same access rules apply to JSON, CSV and historical filter choices.

Reports default to the last 30 calendar days in Africa/Nairobi. Select All dates for older history. Start and end dates are inclusive local dates; stored UTC timestamps are converted for display. Filters support part, source store, recording engineer (administrators), and an exact work-order number. Archived entities remain available when they have visible consumption history. Names use current catalog values.

Only consume movements count. Transfers, imports, additions, adjustments and allocations do not count as consumption. Totals and part/work-order summaries cover all matching events. The event list has 100 rows per page; CSV exports every matching event without a page limit and protects text cells against spreadsheet formula interpretation. Exports read a fresh snapshot, so concurrent consumption can change results since the screen was refreshed.

Select a work order in the summary to view its consumption within the selected date, part and store filters. This integrates the existing internal work-order and movement records. It does not synchronize another work-order application, reserve stock, track repairs, or infer costs without price data.

No schema migration or inventory changes are required. Deployment adds Reports to navigation. Check the deployed layout on desktop and mobile; automated UI tests exercise report methods but do not render a browser.

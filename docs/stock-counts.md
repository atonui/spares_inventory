# Physical stock counts

Open a store's inventory and choose **Count Stock**. The button follows the existing stock-edit permissions: admins/superadmins, the assigned store owner, and authenticated staff for central stores. The server checks permissions again at preview and confirmation.

The sheet fetches current balances directly from the server. Enter the physical quantity for each allocation counted. Blank entries stay unchanged; zero explicitly means an empty allocation. Work-order allocations remain separate from unallocated stock. Count each physical unit once under its actual allocation; this workflow does not redistribute reservations. Stock in transit is excluded until its receipt or return is confirmed through the transfer workflow.

Choose **Preview count** to review the before/after quantities and differences. Every correction requires a reason. Preview makes no stock changes. **Back to counts** lets you edit entries and generate a new preview. **Confirm physical count** saves the exact preview and records the confirming account, time, store, allocation, quantities, and reasons. All balances, movement entries, and audit evidence commit together. Verified unchanged entries are recorded without generating zero-quantity movements.

Stock changes during counting invalidate the sheet or preview, even if a movement returns the quantity to its previous balance. New/deleted rows also invalidate it. Use **Restart with fresh balances** and recount; this discards the current entries after confirmation. Sheets and previews expire after 30 minutes each. Enter at most 1,000 allocations per batch. Counts must be whole numbers between zero and 2,147,483,647.

Drafts are held in the open page; they are not saved between reloads. The person confirming is the recorded approver; there is no separate approval queue. Unexpected physical stock without an existing inventory allocation should first be identified and added through the existing stock-add flow with its correct allocation, then counted from a fresh sheet.

Counts appear in Activity Logs under `confirm_stock_count`, with details available for review/export. Staff can see their own activity; admins and superadmins can review all activity. Correction movements retain their work order and include the before/after quantities and reason in their notes. Existing activity-log cleanup still applies to count evidence.

## Deployment and checks

Merge and deploy normally on Railway, then refresh open tabs. This change adds no database schema or environment settings and leaves existing quantities unchanged until a user confirms a count. It requires the merged transfer and archive/integrity changes already on main.

Run `python -m pytest -q` and `node --test regression_tests/*.cjs`. Count tests cover read-only previews, zero/omitted entries, preserved allocations/thresholds, actor binding, permissions and CSRF, stale/reversed movements, in-transit stock, concurrent confirmation, large previews, audit rollback, activity visibility, and UI confirmation/error handling. Browser visual verification is separate from these API and application-method checks.

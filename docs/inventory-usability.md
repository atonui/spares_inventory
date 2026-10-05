# Inventory usability

Main navigation now separates everyday Inventory, Stores, Parts catalog, Equipment and Movement history from the expandable Management actions. The current view is labelled. Returning to Inventory preserves the search and store filter; Clear filters resets them explicitly.

Find stock accepts part numbers, description words, store names and work-order references. Spaces at the start/end are ignored, words can appear in any order, and missing descriptions do not break search. A store filter combines with the search and uses store IDs, so stores with identical names stay separate. Open store shows that store's allocations, with a separate local search. Store exports and store totals also use IDs. Store CSV export includes the full store, while Current View export follows the main inventory filters.

Inventory and store stock tables become labelled rows at phone widths, preserving quantity, store/work-order context and authorized actions. Other tables retain horizontal scrolling with every column visible. The previous global mobile rule that hid columns three and five has been removed. Stock actions follow existing permissions; unauthorized store views show Read only. No permissions, endpoints, database schema, quantities or allocation rules change.

Refresh failures retain the last loaded stock and warn that it may be out of date. A successful retry removes its own refresh error while preserving unrelated errors. Empty stock and filtered no-results states are distinguished. Navigation and feedback remain visible during loading.

## Deployment and verification

Deploy normally on Railway and refresh open tabs. The HTML versions both CSS and JavaScript to load the new assets. No settings or database migration are required.

Run `python -m pytest -q`, `node --test regression_tests/*.cjs`, `node --check static/script.js`, and `git diff --check`. Application-method tests exercise multiword search, missing descriptions, same-name store isolation, store exports/totals, filter-preserving navigation, store-local search, and failure/recovery feedback. Browser visual and assistive-technology verification was unavailable in the development environment.

After deployment, check the Inventory and store views at desktop and phone widths: search `solid drive`, select a store, open it, clear its local search, and return to Inventory. Confirm quantities/work orders remain visible and buttons usable. Check an account without edit access sees Read only. Test keyboard focus, the Management disclosure, and the export menu. Verify narrow-screen counts and transfers remain usable through their existing workflows before making any physical stock changes.

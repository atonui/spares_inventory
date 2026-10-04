# Stock Validation Implementation Plan

Goal: reject invalid stock requests and prevent ordinary admins from changing privileged roles without changing existing balances or store-access rules.
Architecture: preserve the deployed FastAPI/SQLite app and enforce constraints in request models and existing user routes. No schema or UI changes.
Scope: positive integer receipt/transfer/consumption quantities; nonnegative integer adjustments; same-store transfer rejection; validated role names; only superadmins may assign superadmin or edit a superadmin account through ordinary user routes.

- [ ] Add isolated API regression tests; observe failures on deployed code.
- [ ] Implement minimal validation and role protection in main.py.
- [ ] Verify valid existing workflows, unauthorized requests, and no writes on rejected requests.
- [ ] Test using a disposable restored backup and run the complete suite.
- [ ] Commit on a separate branch and prepare a reviewable PR; do not deploy or reconcile stock.

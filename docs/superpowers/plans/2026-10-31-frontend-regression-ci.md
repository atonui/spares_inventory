# Frontend Regression CI Recovery

**Goal:** Clear the 15 existing Node failures and run the complete Node suite on every push and pull request.

**Scope:** Restore keyboard behavior already covered by failing tests; update obsolete test fixtures and asset contracts. Preserve the approved layout, icons, and application authorization.

- [x] Reproduce all 15 failures on merged main (860 passed, 15 failed).
- [x] Restore Export Escape/focus handling and its expanded-state target.
- [x] Restore the skip link and keyboard access to all three CSV inputs using existing CSS.
- [x] Update script/style cache-version expectations, async password/CSRF response fixtures, and email-change feature state inventory.
- [x] Add a Node regression job alongside generated-CSS verification.
- [ ] Verify the entire Node suite, generated CSS, and PostgreSQL backend workflow.
- [ ] Review and open the next PR.

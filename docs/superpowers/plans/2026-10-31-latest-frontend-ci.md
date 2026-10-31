# Latest Frontend CI Recovery

**Goal:** Clear the five Node test failures and stale generated CSS on main 96bf3bc after PRs 311–312.

**Scope:** Tests and generated assets only. Preserve the approved platform-admin redirect and button UI.

- [x] Inspect current CI logs and reproduce outdated auth mocks and asset expectations.
- [x] Return /api/me JSON and current-user values from mocks; retain CSRF-failure read access and duplicate-login assertions.
- [x] Cover platform-only redirects from session restoration, password login, and inventory bootstrap without tenant requests.
- [x] Refresh console cache-version expectations and regenerate CSS.
- [ ] Verify full Node, CSS, and backend CI and complete independent review.

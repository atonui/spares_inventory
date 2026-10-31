# PostgreSQL CI Recovery Plan

**Goal:** Complete the backend regression suite without test-created transaction lock hangs.

**Scope:** Test fixtures and CI only; no production settings or application behavior changes.

- [ ] Reproduce the existing member-removal test failure with PostgreSQL lock_timeout=5s and statement_timeout=60s in disposable CI.
- [ ] Commit setup mutations before invoking endpoints through independent connections; preserve membership, session and activity-history assertions.
- [ ] Review adjacent tests for the same transaction boundary error and fix only confirmed failures.
- [ ] Keep the 15-minute job deadline, remove first-failure truncation, and emit Python stack diagnostics for stalls.
- [ ] Run the full PostgreSQL backend suite and report every remaining failure.
- [ ] Review the diff and open a PR with exact verification evidence.

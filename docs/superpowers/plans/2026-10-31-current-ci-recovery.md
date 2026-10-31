# Current Main CI Recovery

**Goal:** Clear every failure reproduced on merged main 6dc00c8 after PRs 304–307.

**Scope:** Test fixtures/contracts and generated CSS; do not modify production schema migrations, runtime authorization, settings, or approved UI.

- [x] Inspect latest full CI logs: 13 backend failures, 4 Node failures, stale generated superadmin CSS.
- [x] Remove numeric SQL-position coupling from migration-20 cleanup tests; continue testing owner-preservation guard and membership cleanup.
- [x] Compare full migration runs with registered versions, and choose unknown future versions above the registry maximum.
- [x] Use a valid email fixture and assert platform-only principals cannot enter tenant scope.
- [x] Refresh approved platform-console asset/copy expectations and restrict shared-icon checks to the shared sprite.
- [x] Regenerate minified superadmin CSS from its checked-in source.
- [ ] Run complete Node, generated CSS, and PostgreSQL 17 workflows on the same commit.
- [ ] Independent review and PR handoff.

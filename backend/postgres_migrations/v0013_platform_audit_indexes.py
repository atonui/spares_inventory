"""Version 13: index the platform audit listing and common filters."""

VERSION = 13
NAME = "platform_audit_indexes"

# The reader always orders by created_at/id and filters by one or more exact
# actor, organization, action, or result values. These B-tree indexes support
# the ordered scan and the most common selective filters without indexing JSON.
SQL = (
    "CREATE INDEX idx_platform_audit_created ON platform_audit_events(created_at DESC, id DESC)",
    "CREATE INDEX idx_platform_audit_actor_created ON platform_audit_events(actor_user_id, created_at DESC, id DESC)",
    "CREATE INDEX idx_platform_audit_org_created ON platform_audit_events(organization_id, created_at DESC, id DESC)",
    "CREATE INDEX idx_platform_audit_action_created ON platform_audit_events(action, created_at DESC, id DESC)",
)

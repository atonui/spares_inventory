"""Version 3: transaction-local organization policies for tenant tables."""

VERSION = 3
NAME = "tenant_policies"
TENANT_TABLES = (
    "stores",
    "store_types",
    "parts",
    "work_orders",
    "inventory",
    "movements",
    "stock_transfers",
    "equipment",
    "equipment_history",
    "activity_logs",
    "organization_settings",
    "company_announcements",
    "announcement_dismissals",
)
SQL = tuple(
    f"""CREATE POLICY tenant_organization_scope ON {table}
        USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)"""
    for table in TENANT_TABLES
)

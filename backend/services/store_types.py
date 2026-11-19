"""Default store types every new company starts with (PostgreSQL)."""

# (type_code, type_name, description, display_order). 'central' matters to
# access rules: managers and engineers may change stock in central stores.
DEFAULT_STORE_TYPES = (
    ("office", "Office/Warehouse", "Main office or warehouse location", 1),
    ("customer_site", "Customer Site", "Equipment at customer location", 2),
    ("engineer", "Engineer Personal", "Parts assigned to field engineer", 3),
    ("fe_consignment", "FE Consignment", "Field engineer consignment stock", 4),
    ("admin", "Administration", "Administrative storage", 5),
    ("warehouse", "Warehouse", "General warehouse storage", 6),
    ("central", "Central store", "Shared stock any member can manage", 7),
)


def seed_default_store_types(conn, organization_id) -> int:
    """Add any missing default types for one company; existing types are kept as they are."""
    added = 0
    for type_code, type_name, description, display_order in DEFAULT_STORE_TYPES:
        added += conn.execute(
            """INSERT INTO store_types (organization_id, type_code, type_name, description, display_order)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (organization_id, type_code) DO NOTHING""",
            (organization_id, type_code, type_name, description, display_order),
        ).rowcount
    return added

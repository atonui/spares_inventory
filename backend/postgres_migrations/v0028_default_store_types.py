"""Version 28: companies without any store types get the default set.

Companies created before this release started with no store types, so their
admins could not create a store. Companies that already defined their own
types are left unchanged. This list is frozen here on purpose; the live default
set for new companies is backend/services/store_types.py.
"""

VERSION = 28
NAME = "default_store_types"

SQL = (
    """INSERT INTO store_types (organization_id, type_code, type_name, description, display_order)
       SELECT o.id, d.type_code, d.type_name, d.description, d.display_order
       FROM organizations AS o
       CROSS JOIN (VALUES
           ('office', 'Office/Warehouse', 'Main office or warehouse location', 1),
           ('customer_site', 'Customer Site', 'Equipment at customer location', 2),
           ('engineer', 'Engineer Personal', 'Parts assigned to field engineer', 3),
           ('fe_consignment', 'FE Consignment', 'Field engineer consignment stock', 4),
           ('admin', 'Administration', 'Administrative storage', 5),
           ('warehouse', 'Warehouse', 'General warehouse storage', 6),
           ('central', 'Central store', 'Shared stock any member can manage', 7)
       ) AS d (type_code, type_name, description, display_order)
       WHERE NOT EXISTS (SELECT 1 FROM store_types AS t WHERE t.organization_id = o.id)""",
)

"""Compatibility entry point for consumption-report helpers and registration."""
from backend.routes.reports import BASE, csv_cell, create_stock_report_router


def register_stock_report_routes(app, *, get_connection, current_user, require_active):
    """Register the report router using the original integration interface."""
    app.include_router(create_stock_report_router(
        get_connection=get_connection, current_user=current_user, require_active=require_active,
    ))


# Legacy Python callers historically requested Nairobi explicitly by this helper.
# HTTP reports resolve their organisation context and never call this adapter.
from backend.temporal import validate_zone
from backend.temporal_contract import stored_instant
NAIROBI=validate_zone('Africa/Nairobi')


def local_timestamp(value):
    if not value: return None
    try: return stored_instant(value).astimezone(NAIROBI).isoformat()
    except ValueError: return None

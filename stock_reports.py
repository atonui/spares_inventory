"""Compatibility entry point for consumption-report helpers and registration."""
from backend.routes.reports import BASE, NAIROBI, csv_cell, local_timestamp, create_stock_report_router


def register_stock_report_routes(app, *, get_connection, current_user, require_active):
    """Register the report router using the original integration interface."""
    app.include_router(create_stock_report_router(
        get_connection=get_connection, current_user=current_user, require_active=require_active,
    ))

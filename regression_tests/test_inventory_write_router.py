"""Inventory write route extraction keeps the public API contract in place."""
from fastapi.routing import APIRoute

import main


WRITE_ROUTES = {
    ("POST", "/api/inventory/consume"),
    ("POST", "/api/inventory/import-balances"),
    ("POST", "/api/inventory/add"),
    ("PUT", "/api/inventory/update"),
    ("POST", "/api/inventory/transfer"),
    ("POST", "/api/inventory/transfers/{transfer_id}/receive"),
    ("POST", "/api/inventory/transfers/{transfer_id}/return"),
}


def test_inventory_write_routes_are_registered_from_write_router():
    routes = []
    for route in main.app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods:
                if (method, route.path) in WRITE_ROUTES:
                    routes.append((method, route))
    assert {(method, route.path) for method, route in routes} == WRITE_ROUTES
    for _, route in routes:
        endpoint = getattr(route.endpoint, "__wrapped__", route.endpoint)
        assert endpoint.__module__ == "backend.routes.inventory_writes"
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        assert main.get_current_user in dependencies
        assert main.verify_csrf in dependencies


def test_inventory_write_request_models_are_reexported_from_main():
    from backend.schemas import inventory_writes

    for name in (
        "AddStockRequest",
        "ImportBalanceRow",
        "ImportBalancesRequest",
        "UpdateStockRequest",
        "TransferConfirmationRequest",
        "TransferStockRequest",
        "ConsumeStockRequest",
    ):
        assert getattr(main, name) is getattr(inventory_writes, name)


def test_inventory_write_factory_is_import_inert():
    import sys

    previous = sys.modules.get("main")
    sys.modules.pop("main", None)
    try:
        import backend.routes.inventory_writes  # noqa: F401
        import backend.schemas.inventory_writes  # noqa: F401
        assert "main" not in sys.modules
    finally:
        if previous is not None:
            sys.modules["main"] = previous

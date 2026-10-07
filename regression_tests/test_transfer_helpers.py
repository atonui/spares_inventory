import pytest
from fastapi import HTTPException


@pytest.mark.parametrize('role,user_id,expected', [
    ('admin', 9, (True, True)), ('superadmin', 9, (True, True)),
    ('engineer', 2, (True, False)), ('engineer', 1, (False, True)),
    ('engineer', 9, (False, False)),
])
def test_transfer_permissions_preserve_ownership_rules(role, user_id, expected):
    from backend.services.transfer_helpers import transfer_permissions

    row = dict(dest_owner=2, dest_type='car', created_by=1, source_owner=1)
    assert transfer_permissions({'role': role}, row, user_id) == expected


def test_unassigned_central_store_accepts_receipt():
    from backend.services.transfer_helpers import transfer_permissions

    row = dict(dest_owner=None, dest_type='central', created_by=1, source_owner=1)
    assert transfer_permissions({'role': 'engineer'}, row, 9) == (True, False)


def test_completion_rejects_unconfirmed_physical_action_before_transaction():
    from types import SimpleNamespace
    from backend.services.transfer_helpers import complete_transfer

    with pytest.raises(HTTPException) as error:
        complete_transfer(1, SimpleNamespace(confirmed=False), 1, 'received',
                          session_token='token', authenticated_write_transaction=None,
                          permission_checker=None, balance_snapshot=None,
                          add_inventory_quantity=None, record_stock_audit=None,
                          change_after=None)
    assert (error.value.status_code, error.value.detail) == (
        400, 'Physical receipt or return must be confirmed')

"""Stock services on a borrowed PostgreSQL connection, under company RLS."""
import psycopg
import pytest
from fastapi import HTTPException
import main
from regression_tests.postgres_app import ORG_A


@pytest.fixture
def conn(stock_database):
    """Runtime-role connection in company A with the former SQLite service seed.

    The company context is session-level so it survives the rollbacks these
    tests use to prove nothing was committed.
    """
    owner = stock_database.db
    owner.execute("""INSERT INTO stores(id,organization_id,name,type,assigned_user_id) VALUES
        (1,%(a)s,'Central','central',NULL),(2,%(a)s,'Car 3','car',3),(3,%(a)s,'Car 4','car',4)""", {'a': ORG_A})
    owner.execute("INSERT INTO parts(id,organization_id,part_number) VALUES(1,%s,'PART')", (ORG_A,))
    owner.execute("INSERT INTO work_orders(id,organization_id,work_order_number,assigned_engineer_id) VALUES(7,%s,'WO-7',3)", (ORG_A,))
    owner.execute("""INSERT INTO inventory(id,organization_id,store_id,part_id,work_order_id,quantity,updated_at) VALUES
        (11,%(a)s,1,1,NULL,10,'2000-01-01T00:00:00.000000Z'),(12,%(a)s,2,1,NULL,5,'2000-01-01T00:00:00.000000Z'),
        (13,%(a)s,2,1,7,8,'2000-01-01T00:00:00.000000Z')""", {'a': ORG_A})
    owner.commit()
    c = stock_database.connect()
    c.execute("SELECT set_config('app.organization_id', %s, false)", (str(ORG_A),))
    c.commit()
    try:
        yield c
    finally:
        c.close()


def in_transaction(conn):
    return conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE


def quantity(conn, inventory_id):
    row = conn.execute('SELECT quantity FROM inventory WHERE id=%s', (inventory_id,)).fetchone()
    return row and row['quantity']


@pytest.mark.parametrize('table,identifier', [('users', 3), ('stores', 2), ('parts', 1)])
@pytest.mark.parametrize('damage', ['missing', 'archived'])
def test_active_record_rejections_preserve_connection(conn, stock_database, table, identifier, damage):
    from backend.services.stock_access import require_active_record
    if damage == 'missing':
        identifier = 999
    else:
        owner = stock_database.db
        owner.execute(f"UPDATE {table} SET archived_at='2026-01-01T00:00:00.000000Z' WHERE id=%s", (identifier,))
        owner.commit()
    with pytest.raises(HTTPException) as caught:
        require_active_record(conn, table, identifier)
    assert caught.value.status_code == 400
    assert caught.value.detail == (f'{table} record does not exist' if damage == 'missing'
                                   else f'{table} record is archived; restore it first')
    assert conn.execute('SELECT 1 AS one').fetchone()['one'] == 1


@pytest.mark.parametrize('table,identifier', [('users', 3), ('stores', 2), ('parts', 1)])
def test_active_record_accepts_existing_active(conn, table, identifier):
    from backend.services.stock_access import require_active_record
    require_active_record(conn, table, identifier)
    with pytest.raises(ValueError, match='Unsupported active record type'):
        require_active_record(conn, 'system_logs', 1)
    assert conn.execute('SELECT 1 AS one').fetchone()['one'] == 1


def test_other_companys_records_are_missing_to_the_active_record_check(conn, stock_database):
    from backend.services.stock_access import require_active_record
    owner = stock_database.db
    owner.execute("INSERT INTO stores(id,organization_id,name,type) VALUES(50,%s,'Elsewhere','central')",
                  ('00000000-0000-4000-8000-00000000000b',))
    owner.commit()
    with pytest.raises(HTTPException) as caught:
        require_active_record(conn, 'stores', 50)
    assert caught.value.detail == 'stores record does not exist'


def test_allocated_identity_is_reused_without_committing(conn):
    from backend.services.inventory import add_inventory_quantity
    assert add_inventory_quantity(conn, 2, 1, 2, 7) == 13
    assert quantity(conn, 13) == 10
    assert quantity(conn, 12) == 5
    assert conn.execute('SELECT COUNT(*) AS n FROM inventory').fetchone()['n'] == 3
    assert in_transaction(conn)
    conn.rollback()
    assert quantity(conn, 13) == 8


def test_unallocated_identity_and_timestamp_are_updated(conn):
    from backend.services.inventory import add_inventory_quantity
    assert add_inventory_quantity(conn, 1, 1, 3, None) == 11
    row = conn.execute('SELECT quantity,updated_at FROM inventory WHERE id=11').fetchone()
    assert row['quantity'] == 13 and row['updated_at'] != '2000-01-01T00:00:00.000000Z'
    assert conn.execute('SELECT COUNT(*) AS n FROM inventory').fetchone()['n'] == 3
    assert in_transaction(conn)
    conn.rollback()
    row = conn.execute('SELECT quantity,updated_at FROM inventory WHERE id=11').fetchone()
    assert (row['quantity'], row['updated_at']) == (10, '2000-01-01T00:00:00.000000Z')


def test_new_inventory_row_is_returned_but_not_committed(conn):
    from backend.services.inventory import add_inventory_quantity
    new_id = add_inventory_quantity(conn, 3, 1, 4, None)
    row = conn.execute('SELECT organization_id,store_id,part_id,quantity,work_order_id FROM inventory WHERE id=%s',
                       (new_id,)).fetchone()
    assert row == {'organization_id': ORG_A, 'store_id': 3, 'part_id': 1, 'quantity': 4, 'work_order_id': None}
    assert in_transaction(conn)
    conn.rollback()
    assert conn.execute('SELECT id FROM inventory WHERE id=%s', (new_id,)).fetchone() is None


@pytest.mark.parametrize('table,identifier', [('stores', 1), ('parts', 1)])
@pytest.mark.parametrize('damage', ['missing', 'archived'])
def test_inventory_rejects_inactive_records_without_committing(conn, stock_database, table, identifier, damage):
    from backend.services.inventory import add_inventory_quantity
    store, part = 1, 1
    if damage == 'archived':
        owner = stock_database.db
        owner.execute(f"UPDATE {table} SET archived_at='2026-01-01T00:00:00.000000Z' WHERE id=%s", (identifier,))
        owner.commit()
    elif table == 'stores':
        store = 999
    else:
        part = 999
    with pytest.raises(HTTPException) as caught:
        add_inventory_quantity(conn, store, part, 3, None)
    assert caught.value.status_code == 400
    assert in_transaction(conn)
    assert quantity(conn, 11) == 10
    conn.rollback()


def test_access_wrapper_preserves_store_organization_scope():
    from uuid import uuid4
    from backend.services.principals import AuthenticatedPrincipal

    organization_id = uuid4()
    other_organization_id = uuid4()
    principal = AuthenticatedPrincipal(9, organization_id, "engineer", False)

    main.require_stock_access(
        None, principal, "central", None, store_organization_id=organization_id
    )
    with pytest.raises(HTTPException) as caught:
        main.require_stock_access(
            None, principal, "central", None, store_organization_id=other_organization_id
        )
    assert caught.value.status_code == 403

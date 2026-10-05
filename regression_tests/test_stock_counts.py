"""Real API checks for allocation-safe, previewed physical counts."""
import json
import sqlite3

import pytest
import main
from regression_tests.test_stock_safety import api


def seed(api):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(975,'Count Store','car',3),(976,'Other','car',4)")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(975,'COUNT','Count Part')")
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(975,'COUNT-WO')")
        c.execute("INSERT INTO inventory(id,store_id,part_id,quantity,work_order_id,min_threshold) VALUES(975,975,975,10,NULL,2),(976,975,975,3,'975',1),(977,976,975,7,NULL,0)")
    api[2]['id'] = 3


def sheet(api):
    response = api[0].get('/api/inventory/count-sheet/975')
    assert response.status_code == 200, response.text
    return response.json()


def preview(api, rows=None, token=None):
    return api[0].post('/api/inventory/count-preview', json={
        'sheet_token': token or sheet(api)['sheet_token'],
        'rows': rows or [{'inventory_id':975,'counted_quantity':8,'reason':'Two missing on shelf'},
                         {'inventory_id':976,'counted_quantity':4,'reason':'One extra reserved unit'}]})


def confirm(api, result):
    return api[0].post('/api/inventory/count-confirm', json={'preview_token':result['preview_token'],'confirmed':True})


def test_count_sheet_keeps_allocations_separate_and_preview_is_read_only(api):
    seed(api)
    result = sheet(api)
    assert [(r['inventory_id'],r['quantity'],r['work_order']) for r in result['rows']] == [(975,10,None),(976,3,'COUNT-WO')]
    p = preview(api)
    assert p.status_code == 200
    assert [(r['before_quantity'],r['counted_quantity'],r['difference']) for r in p.json()['rows']] == [(10,8,-2),(3,4,1)]
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT SUM(quantity) FROM inventory WHERE store_id=975').fetchone()[0] == 13
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0] == 0


def test_confirmation_preserves_allocations_thresholds_and_records_exact_audit(api):
    seed(api)
    result = preview(api).json()
    response = confirm(api,result)
    assert response.status_code == 200, response.text
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT id,quantity,work_order_id,min_threshold FROM inventory WHERE store_id=975 ORDER BY id').fetchall() == [(975,8,None,2),(976,4,'975',1)]
        assert c.execute('SELECT quantity FROM inventory WHERE id=977').fetchone()[0] == 7
        assert c.execute('SELECT quantity,movement_type,work_order_id,created_by FROM movements ORDER BY id').fetchall() == [(2,'remove',None,3),(1,'add',975,3)]
        audit = c.execute("SELECT user_id,details FROM activity_logs WHERE action='confirm_stock_count'").fetchone()
        assert audit[0] == 3
        details = json.loads(audit[1])
        assert [(r['inventory_id'],r['before_quantity'],r['counted_quantity'],r['reason']) for r in details['rows']] == [(975,10,8,'Two missing on shelf'),(976,3,4,'One extra reserved unit')]
        assert 'Two missing on shelf' in c.execute('SELECT notes FROM movements ORDER BY id').fetchone()[0]
    assert confirm(api,result).status_code == 409


def test_omitted_rows_are_untouched_and_zero_is_a_valid_count(api):
    seed(api)
    p = preview(api,[{'inventory_id':975,'counted_quantity':0,'reason':'Shelf empty'}])
    assert confirm(api,p.json()).status_code == 200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=975').fetchone()[0] == 0
        assert c.execute('SELECT quantity FROM inventory WHERE id=976').fetchone()[0] == 3


@pytest.mark.parametrize('stage',['preview','confirm'])
def test_movements_during_count_reject_even_if_balance_returns_to_original(api,stage):
    seed(api)
    token = sheet(api)['sheet_token']
    p = preview(api,token=token).json() if stage == 'confirm' else None
    assert api[0].put('/api/inventory/update',json={'inventory_id':975,'new_quantity':9}).status_code == 200
    assert api[0].put('/api/inventory/update',json={'inventory_id':975,'new_quantity':10}).status_code == 200
    response = confirm(api,p) if p else preview(api,token=token)
    assert response.status_code == 409
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=975').fetchone()[0] == 10
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='confirm_stock_count'").fetchone()[0] == 0


@pytest.mark.parametrize('rows',[
    [{'inventory_id':975,'counted_quantity':8,'reason':'   '}],
    [{'inventory_id':975,'counted_quantity':True,'reason':'Bad'}],
    [{'inventory_id':975,'counted_quantity':1.5,'reason':'Bad'}],
    [{'inventory_id':975,'counted_quantity':-1,'reason':'Bad'}],
    [{'inventory_id':975,'counted_quantity':8,'reason':'Missing'},{'inventory_id':975,'counted_quantity':7,'reason':'Duplicate'}],
    [{'inventory_id':977,'counted_quantity':8,'reason':'Other store'}],
])
def test_invalid_counts_cannot_produce_a_preview(api,rows):
    seed(api)
    assert preview(api,rows).status_code in (400,422)


def test_no_change_counts_need_no_reason_but_confirmation_is_not_replayable(api):
    seed(api)
    p = preview(api,[{'inventory_id':975,'counted_quantity':10,'reason':''}])
    assert p.status_code == 200
    assert confirm(api,p.json()).status_code == 200
    assert confirm(api,p.json()).status_code == 409
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0] == 0


def test_count_permissions_rechecked_and_tokens_bound_to_actor(api):
    seed(api)
    p = preview(api).json()
    api[2]['id'] = 4
    assert api[0].get('/api/inventory/count-sheet/975').status_code == 403
    assert confirm(api,p).status_code == 403
    api[2]['id'] = 3
    with sqlite3.connect(api[1]) as c:
        c.execute('UPDATE stores SET assigned_user_id=4 WHERE id=975')
    assert confirm(api,p).status_code == 403


def test_count_confirmation_requires_csrf_and_explicit_acknowledgement(api):
    seed(api)
    p = preview(api).json()
    assert api[0].post('/api/inventory/count-confirm',json={'preview_token':p['preview_token'],'confirmed':False}).status_code == 400
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert confirm(api,p).status_code == 403


def test_count_tokens_cannot_be_tampered_with(api):
    seed(api)
    p = preview(api).json()
    assert api[0].post('/api/inventory/count-confirm',json={'preview_token':p['preview_token']+'tampered','confirmed':True}).status_code == 400


def test_failed_audit_rolls_back_all_count_balances_and_movements(api):
    seed(api)
    p = preview(api).json()
    with sqlite3.connect(api[1]) as c:
        c.execute("CREATE TRIGGER fail_count BEFORE INSERT ON activity_logs WHEN NEW.action='confirm_stock_count' BEGIN SELECT RAISE(ABORT,'count audit failed'); END")
    with pytest.raises(sqlite3.IntegrityError):
        confirm(api,p)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE store_id=975 ORDER BY id').fetchall() == [(10,),(3,)]
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0] == 0


def test_dispatched_stock_is_excluded_and_count_does_not_receive_it(api):
    seed(api)
    transfer = api[0].post('/api/inventory/transfer',json={'inventory_id':975,'to_store_id':976,'quantity':2})
    assert transfer.status_code == 200
    assert sheet(api)['rows'][0]['quantity'] == 8
    p = preview(api,[{'inventory_id':975,'counted_quantity':8,'reason':''}])
    assert confirm(api,p.json()).status_code == 200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=977').fetchone()[0] == 7
        assert c.execute('SELECT status FROM stock_transfers').fetchone()[0] == 'in_transit'


def test_count_token_expiry_requires_fresh_count(api,monkeypatch):
    from itsdangerous.timed import TimestampSigner
    seed(api)
    token = sheet(api)['sheet_token']
    now = TimestampSigner.get_timestamp
    monkeypatch.setattr(TimestampSigner,'get_timestamp',lambda self:now(self)+1801)
    assert preview(api,token=token).status_code == 400


def test_new_stock_row_during_count_invalidates_confirmation(api):
    seed(api)
    p = preview(api).json()
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(976,'NEW-COUNT','New')")
        c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(975,976,1)')
    assert confirm(api,p).status_code == 409


def test_two_simultaneous_confirmations_apply_corrections_once(api):
    from concurrent.futures import ThreadPoolExecutor
    seed(api)
    p = preview(api).json()
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _:confirm(api,p),range(2)))
    assert sorted(r.status_code for r in responses) == [200,409]
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0] == 2
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='confirm_stock_count'").fetchone()[0] == 1


@pytest.mark.parametrize('actor',[1,2,3,4])
def test_count_uses_existing_store_permissions(api,actor):
    seed(api)
    api[2]['id'] = actor
    assert api[0].get('/api/inventory/count-sheet/975').status_code == (403 if actor==4 else 200)
    with sqlite3.connect(api[1]) as c:
        c.execute("UPDATE stores SET type='central',assigned_user_id=NULL WHERE id=975")
    assert api[0].get('/api/inventory/count-sheet/975').status_code == 200


@pytest.mark.parametrize('table,identifier',[('users',3),('stores',975)])
def test_archived_actor_or_store_cannot_confirm_count(api,table,identifier):
    seed(api)
    p = preview(api).json()
    with sqlite3.connect(api[1]) as c:
        c.execute(f'UPDATE {table} SET archived_at=CURRENT_TIMESTAMP WHERE id=?',(identifier,))
    assert confirm(api,p).status_code == 400


def test_count_confirmation_requires_authenticated_session(api):
    seed(api)
    p = preview(api).json()
    main.app.dependency_overrides.pop(main.get_current_user)
    assert confirm(api,p).status_code == 401


def test_staff_can_read_only_their_own_count_audit_and_admins_can_review_all(api):
    seed(api)
    p = preview(api).json()
    assert confirm(api,p).status_code == 200
    api[2]['id'] = 4
    records = api[0].get('/api/logs/activity',params={'action':'confirm_stock_count'}).json()
    assert records == []
    for actor in (1,2,3):
        api[2]['id'] = actor
        records = api[0].get('/api/logs/activity',params={'action':'confirm_stock_count'}).json()
        assert len(records) == 1
        assert records[0]['user_id'] == 3


def test_large_valid_preview_can_be_confirmed(api):
    import base64
    import random
    seed(api)
    ids = range(10000,11000)
    with sqlite3.connect(api[1]) as c:
        c.executemany('INSERT INTO parts(id,part_number,description) VALUES(?,?,?)',[(i,f'COUNT-{i}','Large count') for i in ids])
        c.executemany('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(?,975,?,1)',[(i,i) for i in ids])
    rng = random.Random(321)
    rows = [{'inventory_id':i,'counted_quantity':2,'reason':base64.b64encode(rng.randbytes(750)).decode()} for i in ids]
    p = preview(api,rows)
    assert p.status_code == 200
    assert len(p.json()['preview_token']) > 200000
    result = confirm(api,p.json())
    assert result.status_code == 200, result.text[:1000]
    assert result.json()['changed'] == 1000

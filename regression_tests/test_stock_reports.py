import csv
import io
import sqlite3
import pytest
import main
from regression_tests.test_stock_safety import api


def seed(api):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(970,'History Store','car',3)")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(970,'REPORT','Report Part'),(971,'=FORMULA','Formula part')")
        c.execute("INSERT INTO work_orders(id,work_order_number,assigned_engineer_id) VALUES(970,'REPORT-WO',4),(971,'OTHER-WO',3)")
        rows=[(970,970,2,'consume',970,3,'2026-10-04 20:59:59'),(970,970,3,'consume',970,3,'2026-10-04 21:00:00'),(970,970,4,'consume',970,4,'2026-10-05 20:59:59'),(970,970,5,'consume',971,3,'2026-10-05 21:00:00'),(970,970,99,'add',970,3,'2026-10-05 09:00:00'),(970,970,88,'remove',970,3,'2026-10-05 09:00:00'),(970,970,77,'transfer',970,3,'2026-10-05 09:00:00')]
        c.executemany('INSERT INTO movements(from_store_id,part_id,quantity,movement_type,work_order_id,created_by,created_at) VALUES(?,?,?,?,?,?,?)',rows)
    api[2]['id']=3


def report(api,query=''):
    response=api[0].get('/api/reports/consumption'+query)
    assert response.status_code==200,response.text
    return response.json()


def test_nairobi_day_is_inclusive_at_start_and_exclusive_at_next_midnight(api):
    seed(api);api[2]['id']=1
    result=report(api,'?start_date=2026-10-05&end_date=2026-10-05')
    assert result['totals']['quantity']==7
    assert result['totals']['events']==2
    assert [r['quantity'] for r in result['rows']]==[4,3]
    assert result['rows'][0]['recorded_at'].startswith('2026-10-05T23:59:59+03:00')


@pytest.mark.parametrize('actor,quantity',[(3,10),(4,4),(1,14),(2,14)])
def test_access_is_based_on_recorded_actor_not_work_order_assignment(api,actor,quantity):
    seed(api);api[2]['id']=actor
    result=report(api)
    assert result['totals']['quantity']==quantity
    assert result['scope']==('all' if actor in (1,2) else 'own')
    if actor in (3,4):assert all(r['engineer_id']==actor for r in result['rows'])


def test_non_admin_cannot_use_engineer_filter_to_read_another_users_consumption(api):
    seed(api)
    assert api[0].get('/api/reports/consumption?engineer_id=4').status_code==403
    assert api[0].get('/api/reports/consumption.csv?engineer_id=4').status_code==403


def test_work_order_filter_matches_exact_number_and_uses_own_consumption(api):
    seed(api)
    result=report(api,'?work_order_number=REPORT-WO')
    assert result['totals']['quantity']==5
    assert all(r['work_order']=='REPORT-WO' for r in result['rows'])
    assert report(api,'?work_order_number=REPORT')['totals']['quantity']==0


def test_archived_entities_remain_in_admin_history(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("UPDATE stores SET archived_at=CURRENT_TIMESTAMP WHERE id=970")
        c.execute("UPDATE parts SET archived_at=CURRENT_TIMESTAMP WHERE id=970")
        c.execute("UPDATE users SET archived_at=CURRENT_TIMESTAMP WHERE id=4")
        c.execute("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,created_by,created_at) VALUES(970,970,1,'consume',4,'2026-10-05 09:00:00')")
    api[2]['id']=1
    result=report(api)
    assert result['totals']['quantity']==15
    assert any(r['engineer_id']==4 and r['engineer_name']=='User 4' for r in result['rows'])


def test_totals_and_export_include_every_record_beyond_display_page(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.executemany("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,work_order_id,created_by,created_at) VALUES(970,970,1,'consume',970,3,'2026-10-05 09:00:00')",[()]*205)
    result=report(api,'?limit=100')
    assert len(result['rows'])==100
    assert result['totals']['events']==208 and result['totals']['quantity']==215
    assert sum(r['quantity'] for r in result['by_part'])==215
    response=api[0].get('/api/reports/consumption.csv?limit=1')
    assert response.status_code==200
    rows=list(csv.DictReader(io.StringIO(response.text.lstrip('\ufeff'))))
    assert len(rows)==208
    assert sum(int(r['Quantity']) for r in rows)==215
    next_page=report(api,'?limit=100&offset=100')
    assert {r['movement_id'] for r in result['rows']}.isdisjoint(r['movement_id'] for r in next_page['rows'])


@pytest.mark.parametrize('query',['?start_date=bad&end_date=2026-10-05','?start_date=2026-10-06&end_date=2026-10-05','?start_date=2026-10-05','?limit=0','?offset=-1'])
def test_invalid_filters_are_rejected(api,query):
    seed(api);assert api[0].get('/api/reports/consumption'+query).status_code==422


def test_exports_escape_spreadsheet_formulas_and_apply_same_filters(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,work_order_id,created_by,created_at,notes) VALUES(970,971,1,'consume',970,3,'2026-10-05 09:00:00','@formula')")
    response=api[0].get('/api/reports/consumption.csv?part_id=971')
    rows=list(csv.DictReader(io.StringIO(response.text.lstrip('\ufeff'))))
    assert len(rows)==1 and rows[0]['Part number']=="'=FORMULA" and rows[0]['Notes']=="'@formula"


def test_reports_are_read_only_and_require_authentication(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        before=[c.execute('SELECT * FROM '+t).fetchall() for t in ('inventory','movements','work_orders','activity_logs')]
    report(api);api[0].get('/api/reports/consumption.csv')
    with sqlite3.connect(api[1]) as c:assert [c.execute('SELECT * FROM '+t).fetchall() for t in ('inventory','movements','work_orders','activity_logs')]==before
    main.app.dependency_overrides.pop(main.get_current_user)
    assert api[0].get('/api/reports/consumption').status_code==401


def test_historical_filter_options_obey_report_scope(api):
    seed(api)
    result=report(api)
    assert [e['id'] for e in result['filter_options']['engineers']]==[3]
    with sqlite3.connect(api[1]) as c:
        c.execute('UPDATE stores SET archived_at=CURRENT_TIMESTAMP WHERE id=970')
        c.execute('UPDATE parts SET archived_at=CURRENT_TIMESTAMP WHERE id=970')
    api[2]['id']=2
    result=report(api)
    assert result['filter_options']['stores'][0]['id']==970
    assert result['filter_options']['parts'][0]['id']==970
    assert {e['id'] for e in result['filter_options']['engineers']}=={3,4}

def test_unrepresentable_local_date_returns_validation_error(api):
    for endpoint in ['/api/reports/consumption','/api/reports/consumption.csv']:
        assert api[0].get(endpoint,params={'start_date':'0001-01-01','end_date':'0001-01-02'}).status_code == 422

"""Read-only consumption reports with actor-scoped access and complete exports."""
import csv
import io
from contextlib import closing
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo
from fastapi import Depends, HTTPException, Query
from fastapi.responses import Response

NAIROBI = ZoneInfo('Africa/Nairobi')
BASE = '''FROM movements m LEFT JOIN stores s ON s.id=m.from_store_id
    LEFT JOIN parts p ON p.id=m.part_id LEFT JOIN users u ON u.id=m.created_by
    LEFT JOIN work_orders wo ON wo.id=m.work_order_id'''


def local_timestamp(value):
    if not value: return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z','+00:00'))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(NAIROBI).isoformat()
    except ValueError:
        return None


def csv_cell(value):
    if value is None: return ''
    if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@')): return "'"+value
    return value


def register_stock_report_routes(app, *, get_connection, current_user, require_active):
    def filters(start_date: date | None = None, end_date: date | None = None,
                part_id: int | None = Query(default=None,gt=0), store_id: int | None = Query(default=None,gt=0),
                engineer_id: int | None = Query(default=None,gt=0),
                work_order_number: str | None = Query(default=None,max_length=200),
                limit: int = Query(default=100,ge=1,le=200), offset: int = Query(default=0,ge=0)):
        if (start_date is None)!=(end_date is None):
            raise HTTPException(422,'Provide both start and end dates, or neither for all history')
        if start_date and (end_date<start_date or end_date==date.max):
            raise HTTPException(422,'End date must be on or after start date and before year 10000')
        number=work_order_number.strip() if work_order_number is not None else None
        if number=='': raise HTTPException(422,'Enter a work-order number or leave the filter unset')
        return dict(start_date=start_date,end_date=end_date,part_id=part_id,store_id=store_id,
                    engineer_id=engineer_id,work_order_number=number,limit=limit,offset=offset)

    def query_scope(conn,user_id,f):
        require_active(conn,'users',user_id)
        actor=conn.execute('SELECT role FROM users WHERE id=?',(user_id,)).fetchone()
        privileged=actor['role'] in ('admin','superadmin')
        conditions=["m.movement_type='consume'"];params=[]
        if not privileged:
            if f['engineer_id'] not in (None,user_id):
                raise HTTPException(403,'You can report only your own recorded consumption')
            conditions.append('m.created_by=?');params.append(user_id)
        elif f['engineer_id'] is not None:
            conditions.append('m.created_by=?');params.append(f['engineer_id'])
        if f['start_date']:
            try:
                start=datetime.combine(f['start_date'],time.min,NAIROBI).astimezone(timezone.utc)
                end=datetime.combine(f['end_date']+timedelta(days=1),time.min,NAIROBI).astimezone(timezone.utc)
            except OverflowError:
                raise HTTPException(422,'Date range cannot be represented in UTC')
            conditions.extend(['julianday(m.created_at)>=julianday(?)','julianday(m.created_at)<julianday(?)'])
            params.extend([start.isoformat(),end.isoformat()])
        for key,column in [('part_id','m.part_id'),('store_id','m.from_store_id'),('work_order_number','wo.work_order_number')]:
            if f[key] is not None: conditions.append(column+'=?');params.append(f[key])
        return ' WHERE '+' AND '.join(conditions),params,'all' if privileged else 'own'

    def event_rows(conn,where,params,limit=None,offset=0):
        sql='''SELECT m.id AS movement_id,m.quantity,m.part_id,p.part_number,p.description,
            m.from_store_id AS store_id,s.name AS store_name,m.created_by AS engineer_id,u.name AS engineer_name,
            m.work_order_id,wo.work_order_number AS work_order,m.created_at,m.notes '''+BASE+where+' ORDER BY julianday(m.created_at) DESC,m.id DESC'
        if limit is not None: sql+=' LIMIT ? OFFSET ?';params=[*params,limit,offset]
        rows=[dict(r) for r in conn.execute(sql,params)]
        for row in rows: row['recorded_at']=local_timestamp(row['created_at'])
        return rows

    @app.get('/api/reports/consumption')
    async def consumption(f: dict = Depends(filters),user_id: int = Depends(current_user)):
        with closing(get_connection()) as conn:
            conn.execute('BEGIN')
            where,params,scope=query_scope(conn,user_id,f)
            totals=dict(conn.execute('SELECT COUNT(*) AS events,COALESCE(SUM(m.quantity),0) AS quantity,COUNT(DISTINCT m.part_id) AS parts '+BASE+where,params).fetchone())
            by_part=[dict(r) for r in conn.execute('SELECT m.part_id,p.part_number,p.description,SUM(m.quantity) AS quantity,COUNT(*) AS events '+BASE+where+' GROUP BY m.part_id,p.part_number,p.description ORDER BY quantity DESC,m.part_id',params)]
            by_work_order=[dict(r) for r in conn.execute('SELECT m.work_order_id,wo.work_order_number AS work_order,SUM(m.quantity) AS quantity,COUNT(*) AS events '+BASE+where+' GROUP BY m.work_order_id,wo.work_order_number ORDER BY quantity DESC,m.work_order_id',params)]
            history_filters={**f, 'start_date':None,'end_date':None,'part_id':None,'store_id':None,'engineer_id':None,'work_order_number':None}
            history_where,history_params,_=query_scope(conn,user_id,history_filters)
            filter_options={
                'parts':[dict(r) for r in conn.execute('SELECT DISTINCT p.id,p.part_number,p.description '+BASE+history_where+' AND p.id IS NOT NULL ORDER BY p.part_number,p.id',history_params)],
                'stores':[dict(r) for r in conn.execute('SELECT DISTINCT s.id,s.name '+BASE+history_where+' AND s.id IS NOT NULL ORDER BY s.name,s.id',history_params)],
                'engineers':[dict(r) for r in conn.execute('SELECT DISTINCT u.id,u.name '+BASE+history_where+' AND u.id IS NOT NULL ORDER BY u.name,u.id',history_params)]}
            return {'filter_options':filter_options,'scope':scope,'timezone':'Africa/Nairobi','totals':totals,'by_part':by_part,'by_work_order':by_work_order,
                    'rows':event_rows(conn,where,params,f['limit'],f['offset']),'limit':f['limit'],'offset':f['offset']}

    @app.get('/api/reports/consumption.csv')
    async def consumption_csv(f: dict = Depends(filters),user_id: int = Depends(current_user)):
        with closing(get_connection()) as conn:
            conn.execute('BEGIN')
            where,params,_=query_scope(conn,user_id,f)
            rows=event_rows(conn,where,params)
        output=io.StringIO(newline='');writer=csv.writer(output)
        writer.writerow(['Movement ID','Recorded time (Africa/Nairobi)','Part number','Description','Quantity','Source store','Engineer','Work order','Notes'])
        for r in rows:
            writer.writerow([csv_cell(v) for v in [r['movement_id'],r['recorded_at'] or 'Unknown',r['part_number'],r['description'],r['quantity'],r['store_name'],r['engineer_name'],r['work_order'],r['notes']]])
        return Response('\ufeff'+output.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="consumption_report.csv"','Cache-Control':'no-store'})

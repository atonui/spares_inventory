"""One-time approved reconciliation. Default: preview; --apply writes after checks."""
import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ACTION = 'reconcile_inventory_20261005'
# store, part number, expected (row id, quantity), final total
GROUPS = [
    (2, '10003508102', [(13,1),(44,1)], 2),
    (2, '110527511', [(54,1),(69,2)], 3),
    (4, '5550005170', [(250,4),(260,4)], 4),
    (4, '6713007570', [(i,4) for i in range(262,273)], 4),
    (4, '671363670', [(273,4),(274,4),(275,4)], 4),
    (4, '6714936270', [(258,4),(259,4)], 4),
    (4, '7212592770', [(244,4),(245,4)], 4),
]

def run(db, actor_id, apply=False):
    db = Path(db).resolve(strict=True)
    conn = sqlite3.connect(db, timeout=30)
    conn.row_factory = sqlite3.Row
    backup = None
    try:
        # Reserved writer lock prevents writes between validation and commit.
        conn.execute('BEGIN IMMEDIATE')
        actor = conn.execute('SELECT name,role FROM users WHERE id=?',(actor_id,)).fetchone()
        if not actor or actor['role'] != 'superadmin':
            raise ValueError('Actor must be an existing superadmin user ID')
        if conn.execute('SELECT 1 FROM activity_logs WHERE action=?',(ACTION,)).fetchone():
            raise ValueError('This reconciliation was already applied; no changes made')
        expected_stores = {2:'411',4:'Nakuru',9:'Garissa'}
        for sid, name in expected_stores.items():
            row = conn.execute('SELECT name FROM stores WHERE id=?',(sid,)).fetchone()
            if not row or row['name'] != name:
                raise ValueError('Store identity differs from reviewed backup')
        plan = []
        for sid, part, expected, final in GROUPS:
            rows = conn.execute('SELECT i.id,i.quantity FROM inventory i JOIN parts p ON p.id=i.part_id WHERE i.store_id=? AND p.part_number=? AND i.work_order_id IS NULL ORDER BY i.id',(sid,part)).fetchall()
            if [tuple(row) for row in rows] != expected:
                raise ValueError(f'Stock changed for store {sid}, part {part}; stopping')
            plan.append({'store':expected_stores[sid],'part':part,'before':sum(q for _,q in expected),'after':final,'kept_id':expected[0][0],'removed_ids':[i for i,_ in expected[1:]]})
        garissa = conn.execute('SELECT i.id,i.quantity,p.part_number,p.description FROM inventory i JOIN parts p ON p.id=i.part_id WHERE i.store_id=9 AND p.part_number=? AND i.work_order_id IS NULL ORDER BY i.id',('110661203',)).fetchall()
        if [tuple(row) for row in garissa] != [(464,3,'110661203','Drive Nut, Half'),(504,10,'110661203','Drive Nut, Half')]:
            raise ValueError('Garissa stock or part description changed; stopping')
        if conn.execute('SELECT 1 FROM parts WHERE part_number=?',('110661103',)).fetchone():
            raise ValueError('Solid drive nut already exists; review before applying')
        # Do not silently break any future references to inventory row IDs.
        for table in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            safe = table[0].replace('"','""')
            if any(row[2]=='inventory' for row in conn.execute(f'PRAGMA foreign_key_list("{safe}")')):
                raise ValueError('Inventory references exist; reconciliation needs review')
        if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Database integrity check failed')
        plan.append({'store':'Garissa','row_id':504,'quantity':10,'from_part':'110661203','to_part':'110661103','description':'Drive Nut, Solid'})
        if not apply:
            return {'mode':'preview','changes':plan}
        directory = db.parent / 'reconciliation_backups'
        directory.mkdir(mode=0o700,exist_ok=True)
        backup = directory / ('before_reconciliation_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')+'.db')
        # Separate reader can snapshot while the reserved writer lock is held.
        fd = os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.close(fd)
        with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as source, sqlite3.connect(backup) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Backup integrity check failed')
        for (_,_,expected,final), item in zip(GROUPS,plan):
            conn.execute('UPDATE inventory SET quantity=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(final,expected[0][0]))
            conn.executemany('DELETE FROM inventory WHERE id=?',[(i,) for i,_ in expected[1:]])
        old = conn.execute("SELECT category,unit_cost FROM parts WHERE part_number='110661203'").fetchone()
        pid = conn.execute('INSERT INTO parts(part_number,description,category,unit_cost) VALUES(?,?,?,?)',('110661103','Drive Nut, Solid',old['category'],old['unit_cost'])).lastrowid
        conn.execute('UPDATE inventory SET part_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=504',(pid,))
        conn.execute('INSERT INTO activity_logs(user_id,username,action,resource_type,details,status) VALUES(?,?,?,?,?,?)',(actor_id,actor['name'],ACTION,'inventory',json.dumps({'changes':plan,'backup':str(backup)}),'success'))
        if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Post-change integrity check failed')
        conn.commit()
        return {'mode':'applied','backup':str(backup),'changes':plan}
    finally:
        conn.rollback()
        conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db',default=os.environ.get('DATABASE_URL','/data/inventory.db'))
    parser.add_argument('--actor-id',required=True,type=int)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    try:
        print(json.dumps(run(args.db,args.actor_id,args.apply),indent=2))
    except (ValueError,sqlite3.Error,OSError) as error:
        parser.exit(1,f'STOPPED: {error}\n')

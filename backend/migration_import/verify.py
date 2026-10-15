"""Reconciliation helpers for the SQLite to PostgreSQL import."""

from __future__ import annotations

from collections import Counter


TENANT_TABLES = (
    "stores", "store_types", "parts", "work_orders", "inventory", "movements",
    "stock_transfers", "equipment", "equipment_history", "activity_logs",
    "organization_invitations", "company_announcements", "announcement_dismissals",
)


def verify_import(source, target, organization_id, *, imported_counts, source_counts, revoked_sessions):
    """Return a sanitized reconciliation summary, raising on any mismatch."""
    target_counts = {}
    for table, expected in imported_counts.items():
        if table == "organisation_settings":
            actual = target.execute(
                "SELECT count(*) AS n FROM organization_settings WHERE organization_id=%s",
                (organization_id,),
            ).fetchone()["n"]
        elif table == "announcement_dismissals":
            actual = target.execute(
                "SELECT count(*) AS n FROM announcement_dismissals WHERE organization_id=%s",
                (organization_id,),
            ).fetchone()["n"]
        elif table == "system_announcement":
            actual = target.execute(
                "SELECT count(*) AS n FROM company_announcements WHERE organization_id=%s",
                (organization_id,),
            ).fetchone()["n"]
        elif table == "memberships":
            actual = target.execute(
                "SELECT count(*) AS n FROM organization_memberships WHERE organization_id=%s",
                (organization_id,),
            ).fetchone()["n"]
        elif table == "platform_admins":
            actual = target.execute("SELECT count(*) AS n FROM platform_admins").fetchone()["n"]
        elif table == "users":
            actual = target.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
        elif table == "system_settings":
            actual = target.execute("SELECT count(*) AS n FROM system_settings").fetchone()["n"]
        elif table == "system_logs":
            actual = target.execute("SELECT count(*) AS n FROM system_logs").fetchone()["n"]
        else:
            actual = target.execute(
                f"SELECT count(*) AS n FROM {table} WHERE organization_id=%s",
                (organization_id,),
            ).fetchone()["n"]
        target_counts[table] = actual
        if actual != expected:
            raise ValueError("Imported row counts do not reconcile")

    source_balance = source.execute(
        """SELECT s.id, p.id, i.work_order_id, sum(i.quantity) AS quantity
             FROM inventory i JOIN stores s ON s.id=i.store_id
             JOIN parts p ON p.id=i.part_id
             GROUP BY s.id, p.id, i.work_order_id ORDER BY s.id, p.id, i.work_order_id"""
    ).fetchall()
    target_balance = target.execute(
        """SELECT store_id, part_id, work_order_id, sum(quantity) AS quantity
             FROM inventory WHERE organization_id=%s
             GROUP BY store_id, part_id, work_order_id
             ORDER BY store_id, part_id, work_order_id""",
        (organization_id,),
    ).fetchall()
    normalize_balance = lambda row: (
        int(row[0]), int(row[1]), None if row[2] is None else int(row[2]), int(row[3])
    )
    target_values = [
        (row["store_id"], row["part_id"], row["work_order_id"], row["quantity"])
        for row in target_balance
    ]
    ordering = lambda item: (item[0], item[1], -1 if item[2] is None else item[2])
    if sorted(map(normalize_balance, source_balance), key=ordering) != sorted(
        map(normalize_balance, target_values), key=ordering
    ):
        raise ValueError("Inventory balance reconciliation failed")

    source_transfers = Counter(row[0] for row in source.execute(
        "SELECT status FROM stock_transfers GROUP BY status"
    ).fetchall()) if "stock_transfers" in source_counts else Counter()
    target_transfers = Counter(row["status"] for row in target.execute(
        "SELECT status FROM stock_transfers WHERE organization_id=%s GROUP BY status",
        (organization_id,),
    ).fetchall())
    if source_transfers != target_transfers:
        raise ValueError("Transfer state reconciliation failed")

    missing_memberships = target.execute(
        """SELECT count(*) AS n FROM users u
             LEFT JOIN organization_memberships m ON m.user_id=u.id AND m.organization_id=%s
             WHERE m.user_id IS NULL""", (organization_id,),
    ).fetchone()["n"]
    if missing_memberships:
        raise ValueError("Organization membership reconciliation failed")
    if target.execute("SELECT count(*) AS n FROM sessions WHERE is_active").fetchone()["n"]:
        raise ValueError("Imported database contains active sessions")
    if target.execute("SELECT count(*) AS n FROM users WHERE reset_token IS NOT NULL OR session_token IS NOT NULL").fetchone()["n"]:
        raise ValueError("Imported identities contain active credentials")
    if revoked_sessions != source_counts.get("sessions", 0):
        raise ValueError("Session revocation reconciliation failed")
    target.execute("SET CONSTRAINTS ALL IMMEDIATE")
    return {
        "source_counts": dict(source_counts),
        "target_counts": target_counts,
        "balances_checked": len(source_balance),
        "transfer_states": dict(source_transfers),
        "memberships_checked": target.execute(
            "SELECT count(*) AS n FROM organization_memberships WHERE organization_id=%s",
            (organization_id,),
        ).fetchone()["n"],
        "revoked_sessions": revoked_sessions,
    }

"""History endpoints operate inside the authenticated company context."""

import asyncio
import os
from datetime import date
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def migrated_tenant_schema(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    apply_postgres_migrations(postgres_schema[0])


def test_history_reads_are_company_scoped_and_postgres_compatible(postgres_schema, migrated_tenant_schema):
    from backend.routes.history import create_history_router
    from backend.routes.reports import create_stock_report_router
    from backend.routes.users import create_users_router
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.stock_access import require_active_record
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    org_a, user_a, token_a = seed_user(connection, role="owner")
    org_b, user_b, _token_b = seed_user(connection, role="admin")
    seeded_ids = []
    for org_id, user_id, suffix in ((org_a, user_a, "A"), (org_b, user_b, "B")):
        connection.execute(
            "INSERT INTO organization_settings(organization_id) VALUES (%s)", (org_id,)
        )
        part_id = connection.execute(
            "INSERT INTO parts(organization_id,part_number,description) VALUES (%s,%s,%s) RETURNING id",
            (org_id, f"HISTORY-{suffix}", "History part"),
        ).fetchone()["id"]
        store_id = connection.execute(
            "INSERT INTO stores(organization_id,name,type) VALUES (%s,%s,'warehouse') RETURNING id",
            (org_id, f"History store {suffix}"),
        ).fetchone()["id"]
        movement_id = connection.execute(
            """INSERT INTO movements(organization_id,part_id,from_store_id,quantity,movement_type,
                       created_by,created_at) VALUES (%s,%s,%s,3,'consume',%s,'2026-05-01T12:00:00.000000Z')
               RETURNING id""",
            (org_id, part_id, store_id, user_id),
        ).fetchone()["id"]
        connection.execute(
            """INSERT INTO activity_logs(organization_id,user_id,username,action,status,created_at)
               VALUES (%s,%s,%s,'consume_stock','success','2026-05-01T12:00:00.000000Z')""",
            (org_id, user_id, f"User {suffix}"),
        )
        seeded_ids.append((movement_id, part_id))

    role = "history_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL(
        "GRANT SELECT ON users,sessions,organization_memberships,platform_admins,organizations,activity_logs,"
        "movements,stock_transfers,stores,parts,work_orders,organization_settings TO {}"
    ).format(sql.Identifier(role)))
    connection.commit()

    def scoped_connection():
        scoped = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        scoped.commit()
        return scoped

    router = create_history_router(
        get_connection=scoped_connection,
        authenticated_writer=lambda principal, session, **kwargs: authenticated_write_transaction(
            scoped_connection, user_id=principal, session_token=session, **kwargs
        ),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
        admin_guard=lambda *_args: False,
        activity_log=lambda *_args, **_kwargs: None,
        error_log=lambda *_args, **_kwargs: None,
    )
    request = type("RequestStub", (), {"cookies": {"session_token": token_a}})()
    try:
        movement_endpoint = next(route.endpoint for route in router.routes if route.path == "/api/movements")
        activity_endpoint = next(route.endpoint for route in router.routes if route.path == "/api/logs/activity")
        stats_endpoint = next(route.endpoint for route in router.routes if route.path == "/api/logs/activity/stats")
        movements = asyncio.run(movement_endpoint(user_id=user_a, request=request))
        activity = asyncio.run(activity_endpoint(user_id=user_a, request=request))
        stats = asyncio.run(stats_endpoint(user_id=user_a, request=request))
        assert [row["id"] for row in movements] == [seeded_ids[0][0]]
        assert movements[0]["part_number"] == "HISTORY-A"
        assert [row["username"] for row in activity] == ["User A"]
        assert stats["total_activities"] == 1
        assert stats["by_action"] == [{"action": "consume_stock", "count": 1}]

        reports = create_stock_report_router(
            get_connection=scoped_connection,
            current_user=lambda: None,
            require_active=require_active_record,
        )
        report_endpoint = next(route.endpoint for route in reports.routes if route.path == "/api/reports/consumption")
        csv_endpoint = next(route.endpoint for route in reports.routes if route.path == "/api/reports/consumption.csv")
        filters = {"start_date": date(2026, 5, 1), "end_date": date(2026, 5, 1), "part_id": None, "store_id": None,
                   "engineer_id": None, "work_order_number": None, "limit": 100, "offset": 0}
        report = asyncio.run(report_endpoint(f=filters, user_id=user_a, request=request))
        csv_report = asyncio.run(csv_endpoint(
            f=filters, user_id=user_a, request=request, expected_timezone_revision=1
        ))
        assert report["totals"] == {"events": 1, "quantity": 3, "parts": 1}
        assert [row["part_number"] for row in report["rows"]] == ["HISTORY-A"]
        assert "HISTORY-A" in csv_report.body.decode("utf-8-sig")
        assert "HISTORY-B" not in csv_report.body.decode("utf-8-sig")

        users_router = create_users_router(
            get_connection=scoped_connection,
            authenticated_writer=lambda *_args, **_kwargs: None,
            current_user=lambda: None,
            csrf_dependency=lambda: None,
            user_management_guard=lambda *_args, **_kwargs: None,
            archive_admin_guard=lambda *_args, **_kwargs: None,
            archive_service=lambda *_args, **_kwargs: None,
            password_hash=lambda value: value,
            endpoint_log=lambda *_args, **_kwargs: lambda endpoint: endpoint,
            mutation_activity=lambda *_args, **_kwargs: None,
        )
        users_endpoint = next(route.endpoint for route in users_router.routes if route.path == "/api/users")
        users = asyncio.run(users_endpoint(user_id=user_a, request=request))
        assert [(row["id"], row["role"]) for row in users] == [(user_a, "owner")]
    finally:
        connection.rollback()
        connection.execute("RESET ROLE")
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        connection.commit()

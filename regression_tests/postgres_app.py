"""Shared PostgreSQL fixture that runs the real application against a private schema.

Use it for HTTP-level tests instead of a SQLite file:

    def test_example(tenant_api):
        tenant_api.as_actor("engineer")
        response = tenant_api.client.get("/api/stores")

What it provides:
- A freshly migrated private schema (dropped after the test).
- The app connects as a restricted runtime role, like production: a non-owner,
  NOBYPASSRLS role with table privileges only, so row-level security applies.
- Real authentication and CSRF checks: `as_actor` sets the session cookie and a
  valid CSRF token for that session. Nothing is overridden.
- Two companies. Company A ("tenant") has fixed IDs that mirror the old SQLite
  fixture; company B ("other") exists for isolation checks.
- `db`: an owner connection (bypasses RLS) for seeding and inspecting rows.
  Commit after seeding; the app uses its own connections.
"""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row

ORG_A = UUID("00000000-0000-4000-8000-00000000000a")
ORG_B = UUID("00000000-0000-4000-8000-00000000000b")

# token name -> (user id, organization, company role); None role = platform admin.
ACTORS = {
    "admin": (1, ORG_A, "admin"),
    "owner": (2, ORG_A, "owner"),
    "engineer": (3, ORG_A, "engineer"),
    "manager": (4, ORG_A, "manager"),
    "other": (5, ORG_B, "owner"),
    "platform": (6, None, None),
}


def actor_token(name: str) -> str:
    return f"{name}-token"


def _seed(conn) -> None:
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    expires = serialize_instant(utc_now() + timedelta(days=1))
    for org, name, slug in ((ORG_A, "Tenant A", "tenant-a"), (ORG_B, "Tenant B", "tenant-b")):
        conn.execute("INSERT INTO organizations(id,name,slug) VALUES (%s,%s,%s)", (org, name, slug))
        # Company creation also creates the company's settings row (services/invitations.py).
        conn.execute("INSERT INTO organization_settings (organization_id) VALUES (%s)", (org,))
    for name, (user_id, org, role) in ACTORS.items():
        conn.execute(
            "INSERT INTO users(id,email,name,password_hash) OVERRIDING SYSTEM VALUE VALUES (%s,%s,%s,'unused')",
            (user_id, f"{name}@example.test", name.title()),
        )
        if role is None:
            conn.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (user_id,))
        else:
            conn.execute(
                "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
                (org, user_id, role),
            )
        conn.execute(
            "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
            (user_id, hash_session_credential(actor_token(name)), expires),
        )
    # Company A: same IDs and shapes as the former SQLite session_api fixture.
    conn.execute(
        """INSERT INTO stores(id,organization_id,name,type,assigned_user_id) OVERRIDING SYSTEM VALUE VALUES
           (1,%(a)s,'Warehouse','central',NULL),(2,%(a)s,'Car','engineer',3),(3,%(a)s,'Empty','central',NULL)""",
        {"a": ORG_A},
    )
    conn.execute(
        """INSERT INTO parts(id,organization_id,part_number,description,category,unit_cost) OVERRIDING SYSTEM VALUE VALUES
           (1,%(a)s,'PART','Test part','test',0),(2,%(a)s,'EMPTY','Empty part','test',0)""",
        {"a": ORG_A},
    )
    conn.execute(
        "INSERT INTO inventory(id,organization_id,store_id,part_id,quantity) OVERRIDING SYSTEM VALUE VALUES (1,%s,1,1,10)",
        (ORG_A,),
    )
    # New companies get no store types on PostgreSQL; seed the former SQLite defaults
    # plus 'central', which stock-access rules treat specially.
    from backend.database import STORE_TYPES
    for org in (ORG_A, ORG_B):
        for code, name, description, active, order in (*STORE_TYPES, ("central", "Central store", "Shared central stock", 1, 7)):
            conn.execute(
                """INSERT INTO store_types(organization_id,type_code,type_name,description,is_active,display_order)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (org, code, name, description, bool(active), order),
            )
    conn.execute("INSERT INTO store_types(organization_id,type_code,type_name) VALUES (%s,'unused','Unused')", (ORG_A,))
    conn.execute(
        """INSERT INTO equipment(id,organization_id,equipment_name,make,model,serial_number,assigned_user_id)
           OVERRIDING SYSTEM VALUE VALUES (1,%s,'Meter','Maker','M1','SERIAL',3)""",
        (ORG_A,),
    )
    # Company B: its own rows with distinct IDs, never visible to company A.
    conn.execute(
        "INSERT INTO stores(id,organization_id,name,type) OVERRIDING SYSTEM VALUE VALUES (101,%s,'Other warehouse','central')",
        (ORG_B,),
    )
    conn.execute(
        """INSERT INTO parts(id,organization_id,part_number,description,category,unit_cost) OVERRIDING SYSTEM VALUE VALUES
           (101,%s,'OTHER','Other company part','test',0)""",
        (ORG_B,),
    )
    conn.execute(
        "INSERT INTO inventory(id,organization_id,store_id,part_id,quantity) OVERRIDING SYSTEM VALUE VALUES (101,%s,101,101,7)",
        (ORG_B,),
    )
    # Keep identity sequences ahead of the fixed IDs used above.
    for table in ("users", "stores", "parts", "inventory", "equipment"):
        conn.execute(
            sql.SQL("SELECT setval(pg_get_serial_sequence({}, 'id'), 1000)").format(sql.Literal(table))
        )


@pytest.fixture
def tenant_database(postgres_schema):
    """Migrated, seeded private schema plus a factory for runtime-role connections."""
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from regression_tests.postgres_fixtures import postgres_test_dsn

    owner, schema = postgres_schema
    apply_postgres_migrations(owner)
    _seed(owner)
    role = "app_runtime_" + uuid4().hex
    owner.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role)))
    owner.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
    owner.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)))
    owner.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)))
    owner.commit()

    def connect():
        conn = psycopg.connect(postgres_test_dsn(), row_factory=dict_row, connect_timeout=5)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        conn.commit()
        return conn

    try:
        yield SimpleNamespace(db=owner, connect=connect, schema=schema, role=role)
    finally:
        owner.rollback()
        owner.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        owner.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        owner.commit()


@pytest.fixture
def tenant_api(tenant_database, monkeypatch):
    """The real FastAPI app, connected to the private schema as the runtime role."""
    from fastapi.testclient import TestClient

    import main

    monkeypatch.setattr(main, "get_db_connection", tenant_database.connect)
    # The schema is already migrated; skip the startup migration of main.DATABASE.
    monkeypatch.setattr(main, "init_db", lambda: None)
    with TestClient(main.app) as client:
        def as_actor(name: str):
            token = actor_token(name)
            client.cookies.set("session_token", token)
            client.headers["X-CSRF-Token"] = main.generate_csrf_token(token)
            return client

        def as_bearer(name: str):
            client.cookies.clear()
            client.headers.pop("X-CSRF-Token", None)
            client.headers["Authorization"] = f"Bearer {actor_token(name)}"
            return client

        as_actor("admin")
        yield SimpleNamespace(
            client=client, db=tenant_database.db, connect=tenant_database.connect,
            as_actor=as_actor, as_bearer=as_bearer, actors=ACTORS, org_a=ORG_A, org_b=ORG_B,
        )
    main.app.dependency_overrides.clear()


def database_state(db) -> dict:
    """Every application table's rows, ordered by primary key, for rollback checks.

    Ignores sessions.last_activity, which authentication touches on every request.
    """
    tables = [row["table_name"] for row in db.execute(
        """SELECT table_name FROM information_schema.tables
           WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
           ORDER BY table_name"""
    ).fetchall()]
    state = {}
    for table in tables:
        columns = [row["column_name"] for row in db.execute(
            """SELECT column_name FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = %s ORDER BY ordinal_position""",
            (table,),
        ).fetchall() if not (table == "sessions" and row["column_name"] == "last_activity")]
        query = sql.SQL("SELECT {} FROM {} ORDER BY 1").format(
            sql.SQL(", ").join(map(sql.Identifier, columns)), sql.Identifier(table))
        state[table] = [tuple(row.values()) for row in db.execute(query).fetchall()]
    db.commit()
    return state


def fail_inserts(db, table: str, message: str) -> None:
    """Make every INSERT into `table` raise `message`, to prove a write rolls back."""
    function = sql.Identifier(f"fail_{table}_insert")
    db.execute(sql.SQL(
        "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION {}; END $$"
    ).format(function, sql.Literal(message)))
    db.execute(sql.SQL("CREATE TRIGGER {} BEFORE INSERT ON {} FOR EACH ROW EXECUTE FUNCTION {}()").format(
        sql.Identifier(f"fail_{table}_insert"), sql.Identifier(table), function))
    db.commit()

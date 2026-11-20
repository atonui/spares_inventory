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
- `legacy_db`: an autocommitting owner connection with a sqlite3-like surface
  ('?' placeholders, positional rows); rows it inserts default to company A.
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


def _seed(conn, *, with_catalog: bool = True) -> None:
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
    # Company creation seeds the default store types (services/store_types.py).
    from backend.services.store_types import seed_default_store_types
    for org in (ORG_A, ORG_B):
        seed_default_store_types(conn, org)
    if with_catalog:
        _seed_catalog(conn)
    _advance_identities(conn)


def _seed_catalog(conn) -> None:
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


def _advance_identities(conn) -> None:
    """Start every identity sequence at 1000 so fixed test IDs never collide with app inserts."""
    for row in conn.execute(
        """SELECT table_name, column_name FROM information_schema.columns
           WHERE table_schema = current_schema() AND is_identity = 'YES'"""
    ).fetchall():
        conn.execute(
            sql.SQL("SELECT setval(pg_get_serial_sequence({}, {}), GREATEST(1000, (SELECT max({}) FROM {})))").format(
                sql.Literal(row["table_name"]), sql.Literal(row["column_name"]),
                sql.Identifier(row["column_name"]), sql.Identifier(row["table_name"]))
        )


SEED_ORGANIZATION_SETTING = "test.seed_organization_id"


def _default_seed_organization(conn) -> None:
    """Rows a test inserts directly default to company A.

    The default reads a setting only the test's own connections set. The app's
    runtime connections never set it, so an app insert that omits
    organization_id still fails, exactly as it would in production.
    """
    for row in conn.execute(
        """SELECT table_name FROM information_schema.columns
           WHERE table_schema = current_schema() AND column_name = 'organization_id'
             AND table_name IN (SELECT table_name FROM information_schema.tables
                                WHERE table_schema = current_schema() AND table_type = 'BASE TABLE')"""
    ).fetchall():
        conn.execute(sql.SQL(
            "ALTER TABLE {} ALTER COLUMN organization_id SET DEFAULT NULLIF(current_setting({}, true), '')::uuid"
        ).format(sql.Identifier(row["table_name"]), sql.Literal(SEED_ORGANIZATION_SETTING)))


def _make_database(owner, schema, *, with_catalog: bool):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    apply_postgres_migrations(owner)
    _seed(owner, with_catalog=with_catalog)
    _default_seed_organization(owner)
    # Test-only helper: the current instant in the app's canonical text format.
    owner.execute("""CREATE FUNCTION canonical_now() RETURNS text LANGUAGE sql STABLE AS
        $$ SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') $$""")
    from regression_tests.postgres_fixtures import postgres_test_dsn

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

    owner.execute("SELECT set_config(%s, %s, false)", (SEED_ORGANIZATION_SETTING, str(ORG_A)))
    owner.commit()
    return SimpleNamespace(db=owner, connect=connect, schema=schema, role=role)


def _drop_runtime_role(owner, role) -> None:
    owner.rollback()
    owner.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
    owner.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
    owner.commit()


@pytest.fixture
def tenant_database(postgres_schema):
    """Migrated, seeded private schema plus a factory for runtime-role connections."""
    owner, schema = postgres_schema
    database = _make_database(owner, schema, with_catalog=True)
    try:
        yield database
    finally:
        _drop_runtime_role(owner, database.role)


@pytest.fixture
def stock_database(postgres_schema):
    """Like tenant_database, but company A has no stores, parts or stock yet."""
    owner, schema = postgres_schema
    database = _make_database(owner, schema, with_catalog=False)
    try:
        yield database
    finally:
        _drop_runtime_role(owner, database.role)


@pytest.fixture
def tenant_api(tenant_database, monkeypatch):
    """The real FastAPI app, connected to the private schema as the runtime role."""
    from fastapi.testclient import TestClient

    import main

    monkeypatch.setattr(main, "get_db_connection", tenant_database.connect)
    # The schema is already migrated; skip the startup migration of main.DATABASE.
    monkeypatch.setattr(main, "init_db", lambda: None)
    legacy_db = CompatDatabase(tenant_database.schema)
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
            legacy_db=legacy_db, as_actor=as_actor, as_bearer=as_bearer,
            actors=ACTORS, org_a=ORG_A, org_b=ORG_B,
        )
    legacy_db.close()
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


def fail_inserts(db, table: str, message: str, when: str | None = None, *, event: str = "INSERT") -> str:
    """Make writes to `table` raise `message`, to prove a request rolls back.

    `when` is an optional SQL condition on NEW (for example "NEW.action = 'x'"),
    the PostgreSQL form of a SQLite `WHEN` trigger clause. `event` may be
    INSERT, UPDATE or DELETE. Returns the trigger name, for DROP TRIGGER.
    """
    name = f"fail_{table}_{event.lower()}_{abs(hash((message, when))) % 10**8}"
    db.execute(sql.SQL(
        "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION {}; END $$"
    ).format(sql.Identifier(name), sql.Literal(message)))
    db.execute(sql.SQL("CREATE TRIGGER {} BEFORE {} ON {} FOR EACH ROW {} EXECUTE FUNCTION {}()").format(
        sql.Identifier(name), sql.SQL(event), sql.Identifier(table),
        sql.SQL(f"WHEN ({when})") if when else sql.SQL(""), sql.Identifier(name)))
    db.commit()
    return name


class CompatRow(tuple):
    """A row readable by position or by column name, like sqlite3.Row."""

    def __new__(cls, names, values):
        row = super().__new__(cls, values)
        row._names = names
        return row

    def __getitem__(self, key):
        if isinstance(key, str):
            return tuple.__getitem__(self, self._names.index(key))
        return tuple.__getitem__(self, key)

    def keys(self):
        return list(self._names)

    def values(self):
        return list(self)


def _compat_row_factory(cursor):
    names = [column.name for column in cursor.description or ()]
    return lambda values: CompatRow(names, values)


class CompatDatabase:
    """Owner connection with a sqlite3-like surface for porting seed/inspection code.

    Accepts '?' placeholders, autocommits each statement, returns CompatRow rows,
    and works as a no-op context manager (`with db as conn:`). Rows it inserts
    without an organization_id belong to company A (see _default_seed_organization).
    """

    def __init__(self, schema):
        from regression_tests.postgres_fixtures import postgres_test_dsn

        self._conn = psycopg.connect(postgres_test_dsn(), autocommit=True, row_factory=_compat_row_factory)
        self._conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        self._conn.execute("SELECT set_config(%s, %s, false)", (SEED_ORGANIZATION_SETTING, str(ORG_A)))

    @staticmethod
    def _statement(statement):
        from backend.database_sql import _postgres_placeholders
        return _postgres_placeholders(statement)

    def execute(self, statement, params=()):
        if isinstance(statement, str):
            statement = self._statement(statement)
        # No parameters means no placeholders, so a literal '%' (as in LIKE) stays literal.
        return self._conn.execute(statement, params or None)

    def executemany(self, statement, rows):
        with self._conn.cursor() as cursor:
            cursor.executemany(self._statement(statement), rows)
            return cursor

    def commit(self):
        """Statements autocommit; kept for code written against sqlite3."""

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


ACTOR_BY_ID = {user_id: name for name, (user_id, _org, _role) in ACTORS.items()}


@pytest.fixture
def stock_api(stock_database, monkeypatch):
    """Postgres replacement for the old SQLite `api` fixture: yields (client, db, current).

    Set current['id'] to act as another user (1 admin, 2 owner, 3 engineer,
    4 manager, 5 other company's owner). Each request is authenticated with that
    user's real session and CSRF token unless the test sends its own session cookie.
    current['csrf'] = False sends an invalid CSRF token; current['anonymous'] = True
    sends no session at all.
    """
    from fastapi.testclient import TestClient

    import main

    monkeypatch.setattr(main, "get_db_connection", stock_database.connect)
    monkeypatch.setattr(main, "init_db", lambda: None)
    db = CompatDatabase(stock_database.schema)
    current = {"id": 1}
    try:
        with TestClient(main.app) as client:
            def authenticate(request):
                cookie = request.headers.get("cookie", "")
                if "session_token=" in cookie or current.get("anonymous"):
                    return
                token = actor_token(ACTOR_BY_ID[current["id"]])
                request.headers["cookie"] = (cookie + "; " if cookie else "") + f"session_token={token}"
                if "x-csrf-token" not in request.headers:
                    request.headers["X-CSRF-Token"] = (
                        main.generate_csrf_token(token) if current.get("csrf", True) else "invalid-csrf-token")
            client.event_hooks["request"].append(authenticate)
            yield client, db, current
    finally:
        db.close()
        main.app.dependency_overrides.clear()

"""The shared Postgres app fixture enforces real auth, CSRF and tenant isolation."""


def test_actors_resolve_to_their_company_membership(tenant_api):
    for name in ("admin", "owner", "engineer", "manager"):
        me = tenant_api.as_actor(name).get("/api/me")
        assert me.status_code == 200, me.text
        assert me.json()["saas_mode"] is True
        assert me.json()["id"] == tenant_api.actors[name][0]


def test_company_rows_are_isolated_by_row_level_security(tenant_api):
    stores = tenant_api.as_actor("admin").get("/api/stores")
    assert stores.status_code == 200, stores.text
    assert {row["id"] for row in stores.json()} == {1, 2, 3}
    other = tenant_api.as_actor("other").get("/api/stores")
    assert {row["id"] for row in other.json()} == {101}


def test_runtime_role_cannot_bypass_row_level_security(tenant_api):
    with tenant_api.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM stores").fetchone()["n"] == 0
        assert conn.execute("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()["rolbypassrls"] is False


def test_cookie_writes_require_a_valid_csrf_token(tenant_api):
    client = tenant_api.as_actor("admin")
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/stores", json={"name": "New", "type": "central"}).status_code == 403
    tenant_api.as_actor("admin")
    created = client.post("/api/stores", json={"name": "New", "type": "central"})
    assert created.status_code in (200, 201), created.text
    assert tenant_api.db.execute("SELECT organization_id FROM stores WHERE name='New'").fetchone()["organization_id"] == tenant_api.org_a


def test_unknown_session_is_rejected(tenant_api):
    client = tenant_api.client
    client.cookies.set("session_token", "not-a-session")
    assert client.get("/api/stores").status_code == 401


def test_system_events_are_persisted_on_postgres(tenant_api):
    import main
    main.log_system_event("WARNING", "test", "Postgres system event", {"source": "regression"})
    row = tenant_api.db.execute(
        "SELECT level, component, message, details FROM system_logs WHERE component='test'"
    ).fetchone()
    assert row == {"level": "WARNING", "component": "test", "message": "Postgres system event",
                   "details": '{"source": "regression"}'}

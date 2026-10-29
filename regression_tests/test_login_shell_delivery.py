from fastapi.testclient import TestClient
from backend.app_bootstrap import create_inventory_app


def test_cookie_presence_selects_shell_without_granting_authentication(tmp_path):
    (tmp_path / "index.html").write_text("<!doctype html><title>Dashboard</title>")
    (tmp_path / "login.html").write_text("<!doctype html><title>Login</title>")
    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))
    with TestClient(app) as client:
        anonymous = client.get("/static/index.html")
        assert "Login" in anonymous.text
        assert anonymous.headers["cache-control"] == "no-cache"
        assert anonymous.headers["vary"] == "Cookie"
        # Even an invalid cookie only selects a shell; APIs still validate the session.
        client.cookies.set("session_token", "not-a-valid-session")
        dashboard = client.get("/static/index.html")
        assert "Dashboard" in dashboard.text
        assert dashboard.headers["vary"] == "Cookie"
        assert "Login" in client.get("/").text

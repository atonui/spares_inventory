from fastapi.testclient import TestClient
from backend.app_bootstrap import create_inventory_app


def test_css_requests_serve_generated_content_with_conditional_and_head_support(tmp_path):
    (tmp_path / "minified").mkdir()
    (tmp_path / "typography.css").write_text("/* source */ body { color: navy; }")
    generated = "body{color:navy} @font-face{src:url(fonts/inter.woff2)}"
    (tmp_path / "minified" / "typography.css").write_text(generated)
    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))
    with TestClient(app) as client:
        url = "/static/typography.css?v=release-1"
        response = client.get(url)
        assert response.status_code == 200
        assert response.text == generated
        assert response.headers["content-type"].startswith("text/css")
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
        head = client.head(url)
        assert head.content == b""
        assert head.headers["etag"] == response.headers["etag"]
        assert head.headers["content-length"] == response.headers["content-length"]
        assert client.get(url, headers={"If-None-Match": response.headers["etag"]}).status_code == 304


def test_css_without_generated_copy_falls_back_to_source(tmp_path):
    (tmp_path / "custom.css").write_text("body { color: navy; }")
    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/static/custom.css")
        assert response.status_code == 200
        assert response.text == "body { color: navy; }"
        assert response.headers["cache-control"] == "no-cache"
        assert client.get("/static/missing.css").status_code == 404

"""Configuration module can be loaded without constructing the app."""
import os
import subprocess
import sys
from pathlib import Path


def test_config_module_is_import_inert_and_rejects_wildcard_cors(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "PYTHONPATH": str(root) + os.pathsep + os.environ.get("PYTHONPATH", ""),
        "DATABASE_URL": "inventory.db",
        "SECRET_KEY": "test-only",
        "SMTP_SERVER": "localhost",
        "SMTP_PORT": "1025",
        "SMTP_USERNAME": "test",
        "SMTP_PASSWORD": "test",
        "FRONTEND_URL": "http://testserver",
        "CSRF_SECRET": "test-only",
        "CORS_ALLOWED_ORIGINS": '["*"]',
    }
    code = """
import sys
from pydantic import ValidationError
from backend.config import Settings
assert 'main' not in sys.modules
try:
    Settings()
except ValidationError as exc:
    assert 'wildcards are not allowed' in str(exc)
else:
    raise AssertionError('wildcard CORS origin accepted')
"""
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []


def test_main_reexports_settings_class_and_configured_values():
    import main
    from backend.config import Settings

    assert main.Settings is Settings
    assert main.DATABASE == main.settings.DATABASE_URL
    assert main.CSRF_SECRET == main.settings.CSRF_SECRET

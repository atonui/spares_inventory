"""Run tests with disposable settings and logs against PostgreSQL; never load repository secrets."""

# Shared PostgreSQL fixtures (postgres_schema, tenant_database, tenant_api).
pytest_plugins = ("regression_tests.postgres_fixtures", "regression_tests.postgres_app")
import base64
import os
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = tempfile.TemporaryDirectory()
os.chdir(RUNTIME.name)
Path('static').symlink_to(ROOT / 'static', target_is_directory=True)
for key, value in {
    # PostgreSQL only. Fixtures connect to private schemas in TEST_DATABASE_URL.
    'DATABASE_URL': os.environ.get('TEST_DATABASE_URL') or 'postgresql://localhost/unconfigured_test',
    'SECRET_KEY': 'test-only', 'CSRF_SECRET': 'test-only',
    'SMTP_SERVER': 'localhost', 'SMTP_PORT': '1025',
    'SMTP_USERNAME': 'test', 'SMTP_PASSWORD': 'test',
    'FRONTEND_URL': 'http://testserver',
    # Fresh random key per test run, same shape as production (openssl rand -base64 32).
    # Generated rather than committed so no key-shaped value lives in the repository.
    'NATIVE_REFRESH_ENCRYPTION_KEY': base64.b64encode(secrets.token_bytes(32)).decode(),
}.items():
    os.environ[key] = value
sys.path.insert(0, str(ROOT))
import main

# Never migrate the shared test database's public schema at app startup:
# each fixture applies the migrations to its own private schema.
main.init_db = lambda: None

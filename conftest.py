"""Run tests with disposable settings, logs and database; never load repository secrets."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = tempfile.TemporaryDirectory()
os.chdir(RUNTIME.name)
Path('static').symlink_to(ROOT / 'static', target_is_directory=True)
for key, value in {
    'DATABASE_URL': str(Path(RUNTIME.name) / 'test.db'),
    'SECRET_KEY': 'test-only', 'CSRF_SECRET': 'test-only',
    'SMTP_SERVER': 'localhost', 'SMTP_PORT': '1025',
    'SMTP_USERNAME': 'test', 'SMTP_PASSWORD': 'test',
    'FRONTEND_URL': 'http://testserver',
}.items():
    os.environ[key] = value
sys.path.insert(0, str(ROOT))
import main

main.init_db()

import sqlite3
import subprocess
import sys
import os
from pathlib import Path
from contextlib import closing
import pytest
from fastapi import HTTPException


def transaction():
    from backend.services.authenticated_transactions import authenticated_write_transaction
    return authenticated_write_transaction


def test_service_import_has_no_main_or_files(tmp_path):
    env={**os.environ,'PYTHONPATH':os.pathsep.join([str(Path(__file__).resolve().parents[1]),os.environ.get('PYTHONPATH','')])}
    code="import sys; import backend.services.session_access, backend.services.authenticated_transactions; assert 'main' not in sys.modules"
    result=subprocess.run([sys.executable,'-c',code],cwd=tmp_path,env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert list(tmp_path.iterdir())==[]

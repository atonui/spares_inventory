import logging
import sys


def test_setup_logging_creates_expected_application_loggers(tmp_path, monkeypatch):
    """Moving logging setup must keep the app/audit/error log contract intact."""
    monkeypatch.chdir(tmp_path)
    sys.modules.pop("backend.logging_config", None)
    root_logger = logging.getLogger()
    monkeypatch.setattr(root_logger, "handlers", [])

    from backend.logging_config import setup_logging

    configured = setup_logging()

    assert (tmp_path / "logs").is_dir()
    assert (tmp_path / "logs" / "app.log").exists()
    assert (tmp_path / "logs" / "audit.log").exists()
    assert (tmp_path / "logs" / "errors.log").exists()

    assert configured.logger is logging.getLogger("inventory_app")
    assert configured.audit_logger is logging.getLogger("audit")
    assert configured.error_logger is logging.getLogger("errors")
    assert configured.audit_logger.level == logging.INFO
    assert configured.error_logger.level == logging.ERROR
    assert any(
        isinstance(handler, logging.StreamHandler)
        and not hasattr(handler, "baseFilename")
        for handler in root_logger.handlers
    )

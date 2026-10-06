"""Application logging setup."""

from dataclasses import dataclass
import logging
import os
from logging.handlers import RotatingFileHandler


LOG_DIR = "logs"
MAX_LOG_BYTES = 10485760
BACKUP_COUNT = 10


@dataclass(frozen=True)
class ConfiguredLoggers:
    logger: logging.Logger
    audit_logger: logging.Logger
    error_logger: logging.Logger


def _has_file_handler(logger: logging.Logger, filename: str) -> bool:
    target = os.path.abspath(filename)
    return any(
        isinstance(handler, RotatingFileHandler)
        and os.path.abspath(handler.baseFilename) == target
        for handler in logger.handlers
    )


def _has_console_handler(logger: logging.Logger) -> bool:
    return any(
        isinstance(handler, logging.StreamHandler)
        and not isinstance(handler, logging.FileHandler)
        for handler in logger.handlers
    )


def _add_rotating_file_handler(
    logger: logging.Logger,
    filename: str,
    formatter: logging.Formatter,
    level: int | None = None,
) -> None:
    if _has_file_handler(logger, filename):
        return
    handler = RotatingFileHandler(
        filename,
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
    )
    handler.setFormatter(formatter)
    if level is not None:
        handler.setLevel(level)
    logger.addHandler(handler)


def setup_logging() -> ConfiguredLoggers:
    os.makedirs(LOG_DIR, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    _add_rotating_file_handler(root, f"{LOG_DIR}/app.log", formatter, logging.INFO)

    if not _has_console_handler(root):
        root.addHandler(logging.StreamHandler())

    logger = logging.getLogger("inventory_app")

    audit_logger = logging.getLogger("audit")
    _add_rotating_file_handler(
        audit_logger,
        f"{LOG_DIR}/audit.log",
        logging.Formatter("%(asctime)s - %(message)s"),
    )
    audit_logger.setLevel(logging.INFO)

    error_logger = logging.getLogger("errors")
    _add_rotating_file_handler(
        error_logger,
        f"{LOG_DIR}/errors.log",
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"),
    )
    error_logger.setLevel(logging.ERROR)

    return ConfiguredLoggers(
        logger=logger,
        audit_logger=audit_logger,
        error_logger=error_logger,
    )

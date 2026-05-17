"""
Структурированное логирование M.A.R.S. в файл и консоль.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "mars_audit.log"

_CONFIGURED = False


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Настраивает root-логгер: консоль + logs/mars_audit.log.
    Идемпотентен — повторный вызов не дублирует handlers.
    """
    global _CONFIGURED
    logger = logging.getLogger("mars")
    if _CONFIGURED:
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    _CONFIGURED = True
    logger.info("Логирование инициализировано: %s", LOG_FILE.resolve())
    return logger


def get_logger(name: str = "mars") -> logging.Logger:
    """Возвращает именованный логгер (после setup_logging)."""
    if not _CONFIGURED:
        setup_logging()
    return logging.getLogger(name)

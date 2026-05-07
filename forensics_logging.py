import logging
import os

_LOGGER = logging.getLogger("forensics")


def setup_forensics_logging():
    if _LOGGER.handlers:
        return _LOGGER
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics_tool.log")
    _LOGGER.setLevel(logging.INFO)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _LOGGER.addHandler(fh)
    return _LOGGER


def log_volatility(plugin: str, memory_file: str, message: str):
    setup_forensics_logging()
    _LOGGER.warning("plugin=%s dump=%s %s", plugin, memory_file, message)


def log_exception(context: str, exc: BaseException):
    setup_forensics_logging()
    _LOGGER.exception("%s: %s", context, exc)

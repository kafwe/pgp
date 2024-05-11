import logging
import sys


def configure():
    if "--debug" in sys.argv:
        log_level = logging.DEBUG
    else:
        log_level = logging.CRITICAL

    logging.basicConfig(level=log_level, format="%(message)s")


def get_logger():
    return logging.getLogger(__name__)


def log(msg: str):
    logging.getLogger(__name__).debug(msg)

import logging
import sys
import tests.tests as tests


if "--debug" in sys.argv:
    log_level = logging.DEBUG
else:
    log_level = logging.CRITICAL

logging.basicConfig(level=log_level, format="%(message)s")
logger = logging.getLogger(__name__)


def run():
    print("test key saving:", tests.test_key_saving())

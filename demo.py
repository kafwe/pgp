import logging
import sys


if "--debug" in sys.argv:
    log_level = logging.DEBUG
else:
    log_level = logging.CRITICAL

logging.basicConfig(level=log_level, format="%(message)s")
logger = logging.getLogger(__name__)


if __name__ == "__main__":
    print("Demo:")

import logging
import sys

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s: \n%(message)s"
)
logger = logging.getLogger(__name__)

if "--debug" in sys.argv:
    log_level = logging.DEBUG
else:
    log_level = logging.CRITICAL

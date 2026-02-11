from colorlog import ColoredFormatter
import logging
import warnings
from datetime import datetime

from config import LOGS_PATH

# Ignore specific weasyprint's deprecation warning
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message=".*'instantiateVariableFont' is deprecated; use fontTools.varLib.instancer.instantiateVariableFont instead for either full or partial instancing.*"
)

LOG_LEVEL = logging.DEBUG
LOGFORMAT = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
logging.root.setLevel(LOG_LEVEL)
formatter = ColoredFormatter(LOGFORMAT)
stream = logging.StreamHandler()
stream.setLevel(LOG_LEVEL)
stream.setFormatter(formatter)
log = logging.getLogger('pythonConfig')
log.setLevel(LOG_LEVEL)
log.addHandler(stream)


def init_file_logging() -> None:
    """
    Initialize file logging with a timestamped log file.
    """
    LOGS_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_handler = logging.FileHandler(LOGS_PATH / f"wcp-{timestamp}.log", encoding='utf-8')
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    log.addHandler(file_handler)

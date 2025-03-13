import os
from sys import stderr
from loguru import logger
from configs.config import LOG_LEVEL, LOG_FILE

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logger.remove()

logger_format = (
    "<cyan>{time:YYYY-MM-DD HH:mm:ss}</cyan> | "
    "<level>{level: ^8}</level> | "
    "<cyan>{function:^15}</cyan> | "
    "<level>{message}</level>"
)

logger.add(
    sink=stderr,
    format=logger_format,
    level=LOG_LEVEL,
    colorize=True
)

logger.add(
    sink=LOG_FILE,
    format=logger_format,
    level=LOG_LEVEL,
    rotation="15 MB",
    retention="7 days",
    enqueue=True
)

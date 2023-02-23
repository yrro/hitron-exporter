import enum
import logging
import os
from typing import Union


LOGGER = logging.getLogger(__name__)


class Host(enum.Enum):
    UNKNOWN = enum.auto()
    FLASK = enum.auto()
    GUNICORN = enum.auto()


def config_early() -> None:
    """
    Configure logging before anyone else has a chance. Try to obtain log level
    from our host environment.
    """

    level: Union[str, int]
    gunicorn_logger = logging.getLogger("gunicorn.error")
    if gunicorn_logger.handlers:
        host = Host.GUNICORN
        level = gunicorn_logger.level
    elif "FLASK_RUN_FROM_CLI" in os.environ:
        host = Host.FLASK
        if int(os.environ.get("FLASK_DEBUG", "0")):
            level = "DEBUG"
        else:
            level = "INFO"
    else:
        host = Host.UNKNOWN
        level = "INFO"

    logging.basicConfig(level=level)

    if host == Host.UNKNOWN:
        LOGGER.warning("Unknown host environment; default log level to INFO")

from logging import getLogger
from logging.config import dictConfig
import os

import flask


LOGGER = getLogger(__name__)


def config_early() -> None:
    """
    If we're running from the Flask development web server, configure logging before we
    import any other modules which might configure logging (e.g., ipalib).
    <https://flask.palletsprojects.com/en/2.2.x/logging/#basic-configuration>
    """

    if "FLASK_RUN_FROM_CLI" not in os.environ:
        return

    if getLogger().handlers:
        LOGGER.warning(
            "Resetting existing logging config (handlers were: %r)",
            getLogger().handlers,
        )

    if int(os.environ.get("FLASK_DEBUG", "0")):
        level = "INFO"
    else:
        level = "DEBUG"

    dictConfig(
        {
            "version": 1,
            "formatters": {
                "default": {
                    "format": "[%(levelname)s %(name)s] %(message)s",
                },
                "plain": {
                    "format": "%(message)s",
                },
            },
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "default",
                },
                "plain": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "plain",
                },
            },
            "root": {"level": level, "handlers": ["default"]},
            "loggers": {
                "werkzeug": {
                    "level": level,
                    "handlers": ["plain"],
                    "propagate": False,
                },
            },
        }
    )


def config(app: flask.Flask) -> None:
    gunicorn_logger = getLogger("gunicorn.error")
    if gunicorn_logger.handlers:
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.setLevel(gunicorn_logger.level)

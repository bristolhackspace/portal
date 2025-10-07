import logging
import os
import sys
import tomllib

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SITE_NAME="Portal",
        SECRET_KEY="dev",
        SQLALCHEMY_DATABASE_URI="postgresql+psycopg2://postgres:postgres@localhost:5432/portal",
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_file("config.toml", load=tomllib.load, text=False, silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    register_extensions(app)
    register_blueprints(app)
    configure_logger(app)

    return app


def register_extensions(app: Flask):
    ...


def register_blueprints(app: Flask):
    ...

def configure_logger(app):
    """Configure loggers."""
    handler = logging.StreamHandler(sys.stdout)
    if not app.logger.handlers:
        app.logger.addHandler(handler)
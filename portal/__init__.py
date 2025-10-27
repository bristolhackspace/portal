import logging
import os
import sys
import tomllib
from werkzeug.middleware.proxy_fix import ProxyFix

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SITE_NAME="Portal",
        SECRET_KEY="dev",
        SQLALCHEMY_DATABASE_URI="postgresql+psycopg2://postgres:postgres@localhost:5432/portal",
        SENDER_EMAIL="example@example.com"
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

    configure_logger(app)

    if app.config.get("REGISTER_EXTENSIONS", True):
        from . import extensions
        extensions.init_app(app)

    if app.config.get("REGISTER_VIEWS", True):
        from . import views
        views.init_app(app)

    from . import demo_data
    app.register_blueprint(demo_data.bp)

    if app.config.get("PROXY_FIX", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    return app




def configure_logger(app):
    """Configure loggers."""
    handler = logging.StreamHandler(sys.stdout)
    if not app.logger.handlers:
        app.logger.addHandler(handler)

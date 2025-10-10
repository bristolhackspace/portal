from flask import Flask, current_app
from flask.testing import FlaskClient
import pytest

from portal import create_app
from portal.extensions import db


@pytest.fixture()
def app() -> Flask:
    app = create_app(
        test_config=dict(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            REGISTER_EXTENSIONS=False,
            REGISTER_BLUEPRINTS=False,
        )
    )
    return app


@pytest.fixture()
def app_context(app):
    with app.app_context():
        yield current_app


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture()
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()

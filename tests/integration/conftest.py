from flask import Flask, current_app
from flask.testing import FlaskClient
import pytest

from portal import create_app
from portal.extensions import db


@pytest.fixture()
def app() -> Flask:
    app = create_app(
        test_config=dict(
            SQLALCHEMY_DATABASE_URI="postgresql+psycopg2://postgres:postgres@localhost:5432/portal_test",
            TEST_MAILER=True,
            DISCOURSE_CONNECT_SECRET="test secret",
            WTF_CSRF_ENABLED=False,
            API_SECRET="test secret",
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


@pytest.fixture(autouse=True)
def init_db(app: Flask, app_context: Flask):
    db.create_all()
    yield
    db.session.remove()
    db.drop_all()

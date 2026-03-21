from flask import Flask, current_app
from flask.testing import FlaskClient
import pytest

from portal import create_app
from portal.extensions import db


@pytest.fixture(scope="session")
def app() -> Flask:
    app = create_app(
        test_config=dict(
            SERVER_NAME="localhost",
            SQLALCHEMY_DATABASE_URI="postgresql+psycopg2://postgres:postgres@localhost:5432/portal_test",
            REGISTER_EXTENSIONS=False,
            REGISTER_VIEWS=False,
            TEST_MAILER=True,
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



@pytest.fixture(autouse=True, scope="session")
def init_db(app: Flask):
    db.init_app(app)
    with app.app_context():
        db.create_all()
    yield
    with app.app_context():
        db.drop_all()

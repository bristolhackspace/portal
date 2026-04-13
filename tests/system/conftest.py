from flask import Flask, current_app
from flask.testing import FlaskClient
import pytest

from portal import create_app
from portal.extensions import db
from portal.systems.authentication import Authentication
from portal.systems.cleanup import Cleanup
from portal.systems.discourse_connect import DiscourseConnect
from portal.systems.mailer import BaseMailer
from portal.systems.rate_limiter import RateLimiter
from portal.systems.session_manager import SessionManager


@pytest.fixture()
def app() -> Flask:
    app = create_app(
        test_config=dict(
            SERVER_NAME="localhost",
            SQLALCHEMY_DATABASE_URI="postgresql+psycopg2://postgres:postgres@localhost:5432/portal_test",
            REGISTER_EXTENSIONS=False,
            REGISTER_VIEWS=False,
            TEST_MAILER=True,
            DISCOURSE_CONNECT_SECRET="test secret",
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
def init_db(app: Flask, app_context: Flask):
    db.init_app(app)
    db.create_all()
    yield
    db.session.remove()
    db.drop_all()


@pytest.fixture()
def session_manager(init_db, app_context):
    return SessionManager(db, None, app_context)


@pytest.fixture()
def cleanup(app_context):
    return Cleanup(app_context)


@pytest.fixture()
def mailer(app_context):
    return BaseMailer.build(app_context)


@pytest.fixture()
def rate_limiter(init_db, app_context):
    return RateLimiter(db, app_context)


@pytest.fixture()
def authentication(mailer, rate_limiter, app_context, init_db):
    return Authentication(mailer, db, rate_limiter, app_context)


@pytest.fixture()
def discourse_connect(app_context):
    return DiscourseConnect(app_context)

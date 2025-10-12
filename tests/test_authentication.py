

import secrets
import uuid
import pytest
import typing
import yarl

from portal.extensions import db, authentication, mailer
from portal.models import AuthFlow, User
from portal.systems.mailer import _TestMailer


@pytest.fixture()
def init_mailer(app):
    mailer.init_app(app)

@pytest.fixture()
def init_authentication(app, init_db, init_mailer):
    authentication.magic_link_route = 'magic_mock'
    authentication.init_app(app)


@pytest.fixture(autouse=True)
def endpoints(app):
    @app.route("/magic_mock")
    def magic_mock():
        return "OK"


@pytest.fixture()
def user_model(app_context):
    user = User(display_name="Test User", email="example@example.com")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def session_secret():
    return secrets.token_urlsafe()


def test_send_magic_email(app, client, init_authentication, user_model):

    flow: AuthFlow|None = None

    @app.route("/login")
    def login():
        nonlocal flow
        flow = authentication.send_magic_email(user_model.email)
        return "OK"

    response = client.get("/login")

    cookie = client.get_cookie(authentication._state.cookie_name)
    assert cookie is not None
    id_, token = cookie.value.split(":")
    cookie_flow = db.session.get(AuthFlow, uuid.UUID(hex=id_))

    assert flow is not None
    flow = typing.cast(AuthFlow, flow)

    assert flow == cookie_flow
    assert cookie_flow.flow_token_hash == authentication.hash_token(token)

    test_mailer: _TestMailer = mailer._state
    assert len(test_mailer.captured_emails) == 1
    captured_email = test_mailer.captured_emails[0]
    assert captured_email.user == user_model
    assert captured_email.kwargs['flow'] == flow

    magic_url = yarl.URL(captured_email.kwargs['magic_url'])
    assert magic_url.query["id"] == flow.id.hex
    assert authentication.hash_token(magic_url.query["token"]) == flow.email_token_hash


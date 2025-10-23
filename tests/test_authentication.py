

from datetime import datetime, timedelta, timezone
import secrets
import uuid
from flask import request
import pytest
import typing
import yarl

from portal.extensions import db, authentication, mailer
from portal.helpers import hash_token
from portal.models import AuthFlow, User
from portal.systems.mailer import _TestMailer


@pytest.fixture()
def init_mailer(app):
    mailer.init_app(app)

@pytest.fixture()
def init_authentication(app, init_db, init_mailer):
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
def flow_token():
    return secrets.token_urlsafe()

@pytest.fixture()
def email_token():
    return secrets.token_urlsafe()

@pytest.fixture()
def flow_model(app_context, user_model, flow_token, email_token):
    flow = AuthFlow(
        id=uuid.uuid4(),
        user=user_model,
        flow_token_hash=hash_token(flow_token),
        email_token_hash=hash_token(email_token),
        visual_code=secrets.token_hex(2),
        expiry=datetime.now(timezone.utc) + timedelta(minutes=20)
    )
    db.session.add(flow)
    db.session.commit()
    return flow

@pytest.fixture()
def flow_cookie(
    client, app_context, init_authentication, flow_token, flow_model
):
    cookie_name = authentication._state.cookie_name
    cookie_val = f"{flow_model.id.hex}:{flow_token}"
    client.set_cookie(cookie_name, cookie_val)


def test_send_magic_email(app, client, init_authentication, user_model):

    @app.route("/login")
    def login():
        authentication.send_magic_email(user_model.email, "magic_mock")
        return "OK"

    response = client.get("/login")

    cookie = client.get_cookie(authentication._state.cookie_name)
    assert cookie is not None
    id_, token = cookie.value.split(":")
    cookie_flow = db.session.get(AuthFlow, uuid.UUID(hex=id_))

    assert cookie_flow is not None

    assert authentication.current_flow == cookie_flow
    assert cookie_flow.flow_token_hash == hash_token(token)

    test_mailer = typing.cast(_TestMailer, mailer._state)
    assert len(test_mailer.captured_emails) == 1
    captured_email = test_mailer.captured_emails[0]
    assert captured_email.user == user_model
    assert captured_email.kwargs['flow'] == cookie_flow

    magic_url = yarl.URL(captured_email.kwargs['magic_url'])
    assert magic_url.query["id"] == cookie_flow.id.hex
    assert hash_token(magic_url.query["token"]) == cookie_flow.email_token_hash


def test_verify_magic_link(app, client, init_authentication, flow_model, email_token):
    verified_flow: AuthFlow|None = None
    @app.route("/verify_magic")
    def verify_magic():
        nonlocal verified_flow
        verified_flow = authentication.verify_magic_link(request, commit=False)

    response = client.get("/verify_magic", query_string=dict(
        id=flow_model.id.hex,
        token=email_token
    ))

    assert verified_flow is not None
    verified_flow = typing.cast(AuthFlow, verified_flow)

    assert verified_flow == flow_model

def test_verify_magic_link_invalid_token(app, client, init_authentication, flow_model, email_token):
    verified_flow: AuthFlow|None = None
    @app.route("/verify_magic")
    def verify_magic():
        nonlocal verified_flow
        verified_flow = authentication.verify_magic_link(request, commit=False)

    response = client.get("/verify_magic", query_string=dict(
        id=flow_model.id.hex,
        token=email_token + "a"
    ))

    assert verified_flow is None


def test_verify_magic_link_expired(app, client, init_authentication, flow_model, email_token):
    flow_model.expiry = datetime.now(timezone.utc) - timedelta(seconds=10)
    db.session.commit()

    verified_flow: AuthFlow|None = None
    @app.route("/verify_magic")
    def verify_magic():
        nonlocal verified_flow
        verified_flow = authentication.verify_magic_link(request, commit=False)

    response = client.get("/verify_magic", query_string=dict(
        id=flow_model.id.hex,
        token=email_token
    ))

    assert verified_flow is None


def test_load_flow(app, client, init_authentication, flow_model, flow_cookie):
    loaded_flow: AuthFlow|None = None
    @app.route("/load_flow")
    def load_flow():
        nonlocal loaded_flow
        authentication.load_flow()
        loaded_flow = authentication.current_flow

    response = client.get("/load_flow")

    assert loaded_flow is not None
    loaded_flow = typing.cast(AuthFlow, loaded_flow)

    assert loaded_flow == flow_model
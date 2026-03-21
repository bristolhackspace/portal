from argon2 import PasswordHasher
from datetime import datetime, timedelta, timezone
import pytest
import typing
import uuid
import yarl

from portal.extensions import db
from portal.helpers import get_from_secure_uri, build_secure_uri
from portal.models import User, AuthFlow
from portal.systems.authentication import Authentication, FlowStep
from portal.systems.mailer import TestMailer

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
def flow_model(app_context, user_model):
    flow = AuthFlow(
        id=uuid.uuid4(),
        user=user_model,
        flow_token_hash="",
        email_otp_hash="",
        email_otp_attempts=0,
        expiry=datetime.now(timezone.utc) + timedelta(minutes=20)
    )
    db.session.add(flow)
    db.session.commit()
    return flow

@pytest.fixture()
def email_token(flow_model) -> tuple[str, str]:
    flow_id, token = build_secure_uri(flow_model, "email_token_hash")
    db.session.commit()
    return (flow_id, token)


@pytest.fixture()
def flow_cookie(
    client, app_context, authentication, flow_model
):
    cookie_name = authentication.cookie_name
    cookie_val = build_secure_uri(flow_model, "flow_token_hash")
    db.session.commit()
    client.set_cookie(cookie_name, cookie_val)


def test_begin_flow(app, client, authentication):
    @app.route("/login")
    def login():
        authentication.begin_flow(None)
        return "OK"

    response = client.get("/login")

    cookie = client.get_cookie(authentication.cookie_name)
    assert cookie is not None

    cookie_flow = get_from_secure_uri(db, AuthFlow, cookie.value, "flow_token_hash")
    assert cookie_flow is not None

    assert authentication.current_flow == cookie_flow


def test_send_magic_email(app, client, authentication, mailer, user_model):

    @app.route("/login")
    def login():
        authentication.send_magic_email(user_model.email, "magic_mock")
        return "OK"

    response = client.get("/login")

    cookie = client.get_cookie(authentication.cookie_name)
    assert cookie is not None

    cookie_flow = get_from_secure_uri(db, AuthFlow, cookie.value, "flow_token_hash")
    assert cookie_flow is not None

    assert authentication.current_flow == cookie_flow

    test_mailer = typing.cast(TestMailer, mailer)
    assert len(test_mailer.captured_emails) == 1
    captured_email = test_mailer.captured_emails[0]
    assert captured_email.user == user_model
    assert captured_email.kwargs['flow'] == cookie_flow
    otp = captured_email.kwargs['otp']

    ph = PasswordHasher()
    assert ph.verify(authentication.current_flow.email_otp_hash, captured_email.kwargs['otp']) == True

    magic_url = yarl.URL(captured_email.kwargs['magic_url'])
    assert magic_url.query["flow_id"] == cookie_flow.id.hex
    assert magic_url.query["otp"] == otp

def test_verify_otp(app, client, authentication, user_model, flow_cookie, flow_model):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    db.session.commit()

    @app.route("/verify")
    def verify():
        authentication.load_flow()
        assert authentication.verify_email_otp(otp) == True
        return "OK"

    response = client.get("/verify")
    assert response.status_code == 200

def test_fail_invalid_otp(app, client, authentication, user_model, flow_cookie, flow_model):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    db.session.commit()

    @app.route("/verify")
    def verify():
        authentication.load_flow()
        assert authentication.verify_email_otp("678124") == False
        return "OK"

    response = client.get("/verify")
    assert response.status_code == 200


def test_flow_next_step_no_flow(app, client, authentication, user_model, flow_cookie, flow_model):
    @app.route("/verify")
    def verify():
        assert authentication.flow_next_step() == FlowStep.NOT_STARTED
        return "OK"

    response = client.get("/verify")
    assert response.status_code == 200

def test_flow_next_step_not_started(app, client, authentication, user_model, flow_cookie, flow_model):
    @app.route("/verify")
    def verify():
        authentication.load_flow()
        assert authentication.flow_next_step() == FlowStep.NOT_STARTED
        return "OK"

    response = client.get("/verify")
    assert response.status_code == 200

def test_flow_next_step_verify_email(app, client, authentication, user_model, flow_cookie, flow_model):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    db.session.commit() 
    
    @app.route("/verify")
    def verify():
        authentication.load_flow()
        assert authentication.flow_next_step() == FlowStep.VERIFY_EMAIL
        return "OK"

    response = client.get("/verify")
    assert response.status_code == 200


def test_flow_next_step_finished(app, client, authentication, user_model, flow_cookie, flow_model):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    flow_model.email_verified = datetime.now(timezone.utc)
    db.session.commit()
    
    @app.route("/verify")
    def verify():
        authentication.load_flow()
        assert authentication.flow_next_step() == FlowStep.FINISHED
        return "OK"

    response = client.get("/verify")
    assert response.status_code == 200
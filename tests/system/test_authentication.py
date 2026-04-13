from argon2 import PasswordHasher
from datetime import datetime, timedelta, timezone
from flask import request
import pytest
import typing
import uuid
import yarl

from portal.extensions import db
from portal.helpers import get_from_secure_uri, build_secure_uri
from portal.models import Member, AuthFlow
from portal.models.authentication import FlowStep
from portal.systems.authentication import OtpValidationError
from portal.systems.mailer import TestMailer


@pytest.fixture(autouse=True)
def endpoints(app):
    @app.route("/magic_mock")
    def magic_mock():
        return "OK"


@pytest.fixture()
def member_model(init_db):
    member = Member(
        id=1,
        display_name="Test Member",
        email="example@example.com",
        username="test_username",
    )
    db.session.add(member)
    db.session.commit()
    return member


@pytest.fixture()
def flow_model(member_model):
    flow = AuthFlow(
        id=uuid.uuid4(),
        member=member_model,
        flow_token_hash="",
        email_otp_hash="",
        email_otp_attempts=0,
        expiry=datetime.now(timezone.utc) + timedelta(minutes=20),
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
def flow_cookie(client, app_context, authentication, flow_model):
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


def test_send_magic_email(app, client, authentication, mailer, member_model):

    @app.route("/login")
    def login():
        authentication.send_magic_email(member_model.email, "magic_mock")
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
    assert captured_email.member == member_model
    assert captured_email.kwargs["flow"] == cookie_flow
    otp = captured_email.kwargs["otp"]

    ph = PasswordHasher()
    assert (
        ph.verify(
            authentication.current_flow.email_otp_hash, captured_email.kwargs["otp"]
        )
        == True
    )

    magic_url = yarl.URL(captured_email.kwargs["magic_url"])
    assert magic_url.query["flow_id"] == cookie_flow.id.hex
    assert magic_url.query["otp"] == otp


def test_verify_otp(app, client, authentication, member_model, flow_cookie, flow_model):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    db.session.commit()

    verify_result = None

    @app.route("/verify")
    def verify():
        nonlocal verify_result
        flow = authentication.load_flow(request)
        verify_result = authentication.verify_email_otp(otp, flow)
        return "OK"

    response = client.get("/verify", query_string={"flow_id": flow_model.id.hex})
    assert verify_result == True


def test_fail_invalid_otp(
    app, client, authentication, member_model, flow_cookie, flow_model
):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    db.session.commit()

    @app.route("/verify")
    def verify():
        flow = authentication.load_flow(request)
        with pytest.raises(OtpValidationError):
            authentication.verify_email_otp("678124", flow)
        return "OK"

    response = client.get("/verify", query_string={"flow_id": flow_model.id.hex})


def test_flow_next_step_not_started(
    app, client, authentication, member_model, flow_cookie, flow_model
):
    flow_step = None

    @app.route("/verify")
    def verify():
        nonlocal flow_step
        flow = authentication.load_flow(request)
        flow_step = flow.next_step()
        return "OK"

    response = client.get("/verify", query_string={"flow_id": flow_model.id.hex})
    assert flow_step == FlowStep.NOT_STARTED


def test_flow_next_step_verify_email(
    app, client, authentication, member_model, flow_cookie, flow_model
):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    db.session.commit()

    flow_step = None

    @app.route("/verify")
    def verify():
        nonlocal flow_step
        flow = authentication.load_flow(request)
        flow_step = flow.next_step()
        return "OK"

    response = client.get("/verify", query_string={"flow_id": flow_model.id.hex})
    assert flow_step == FlowStep.VERIFY_EMAIL


def test_flow_next_step_finished(
    app, client, authentication, member_model, flow_cookie, flow_model
):
    ph = PasswordHasher()
    otp = "678123"
    flow_model.email_otp_hash = ph.hash(otp)
    flow_model.email_verified = datetime.now(timezone.utc)
    db.session.commit()

    flow_step = None

    @app.route("/verify")
    def verify():
        nonlocal flow_step
        flow = authentication.load_flow(request)
        flow_step = flow.next_step()
        return "OK"

    response = client.get("/verify", query_string={"flow_id": flow_model.id.hex})
    assert flow_step == FlowStep.FINISHED

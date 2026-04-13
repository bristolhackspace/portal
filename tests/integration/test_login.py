from typing import cast

import pytest
from yarl import URL
from werkzeug.test import TestResponse

from portal.extensions import db
from portal.extensions import hs
from portal.models import Member
from portal.models.authentication import AuthFlow
from portal.systems.mailer import TestMailer


@pytest.fixture()
def member_model(init_db):
    member = Member(
        id=1, display_name="Test Member", email="example@example.com", username="test"
    )
    db.session.add(member)
    db.session.commit()
    return member


@pytest.fixture()
def member_model_no_username(init_db):
    member = Member(id=2, display_name="Test Member 2", email="example2@example.com")
    db.session.add(member)
    db.session.commit()
    return member


def load_initial_login_page(client):
    # Load the email entry page
    response = client.get("/login/", follow_redirects=True)
    assert response.status_code == 200


def check_null_session():
    # Check we don't currently have a session
    session = hs.session_manager.current_session
    assert session == None


def request_and_verify_email(
    client, member_model
) -> tuple[TestMailer.EmailCapture, TestResponse]:
    # Submit the email of the test member
    response = client.post(
        "/login/", follow_redirects=True, data={"email": member_model.email}
    )
    assert response.status_code == 200

    # Check an email got sent with the correct details
    mailer = cast(TestMailer, hs.mailer)
    assert len(mailer.captured_emails) == 1
    email = mailer.captured_emails[0]
    assert email.member == member_model
    otp = email.kwargs["otp"]
    assert len(otp) == 6
    flow: AuthFlow = email.kwargs["flow"]
    assert flow.id.hex == response.request.args["flow_id"]
    return email, response


def check_valid_session(member_model: Member):
    # Check a session was created successfully
    session = hs.session_manager.current_session
    assert session != None
    assert session.member == member_model


def submit_otp_form(
    client, email: TestMailer.EmailCapture, prev_response: TestResponse
) -> TestResponse:
    otp = email.kwargs["otp"]
    # Submit the OTP found in the email. Pass through previous request args for the flow_id
    response = client.post(
        "/login/",
        follow_redirects=True,
        query_string=prev_response.request.args,
        data={"otp": otp},
    )
    assert response.status_code == 200

    return response


def submit_otp_url(client, email: TestMailer.EmailCapture) -> TestResponse:
    magic_url = URL(email.kwargs["magic_url"])

    # Submit the OTP found in the email. Pass through previous request args for the flow_id
    response = client.get(
        magic_url.path, query_string=magic_url.query, follow_redirects=True
    )
    assert response.status_code == 200

    return response


def submit_username(
    client, member_model: Member, prev_response: TestResponse
) -> TestResponse:
    username = "test_username"
    response = client.post(
        "/login/",
        follow_redirects=True,
        query_string=prev_response.request.args,
        data={"username": username},
    )
    assert response.status_code == 200

    assert member_model.username == username

    return response


def test_email_login_code(client, member_model):
    load_initial_login_page(client)
    check_null_session()
    email, response = request_and_verify_email(client, member_model)

    response = submit_otp_form(client, email, response)

    # Check we got redirected to the homepage
    assert response.request.path == "/"

    check_valid_session(member_model)


def test_email_login_magic_url(client, member_model):
    load_initial_login_page(client)
    check_null_session()
    email, response = request_and_verify_email(client, member_model)

    response = submit_otp_url(client, email)

    # Check we got redirected to the homepage
    assert response.request.path == "/"

    check_valid_session(member_model)


def test_email_login_set_username(client, member_model_no_username):
    load_initial_login_page(client)
    check_null_session()
    email, response = request_and_verify_email(client, member_model_no_username)

    response = submit_otp_form(client, email, response)

    # Check we haven't been redirected to the homepage yet
    assert response.request.path == "/login/"

    response = submit_username(client, member_model_no_username, response)

    # Check we got redirected to the homepage
    assert response.request.path == "/"

    check_valid_session(member_model_no_username)

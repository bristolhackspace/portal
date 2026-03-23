

from datetime import datetime, timedelta, timezone
import uuid

import pytest

from portal.extensions import db
from portal.helpers import build_secure_uri, get_from_secure_uri
from portal.models.member import Session, Member

@pytest.fixture()
def example_endpoint(app):
    @app.route("/example")
    def example():
        return "OK"

@pytest.fixture()
def member_model(init_db):
    member = Member(display_name="Test Member", email="example@example.com")
    db.session.add(member)
    db.session.commit()
    return member

@pytest.fixture()
def session_model(member_model):
    # We set now to a few seconds in the past so we can do some update checks
    now = datetime.now(timezone.utc) - timedelta(seconds=10)
    sess = Session(
        id=uuid.uuid4(),
        secret_hash="",
        member=member_model,
        created=now,
        last_active=now,
        last_auth=now,
    )
    db.session.add(sess)
    db.session.commit()
    return sess

@pytest.fixture()
def session_cookie(
    client, session_manager, session_model
):
    cookie_name = session_manager.cookie_name
    cookie_val = build_secure_uri(session_model, "secret_hash")
    db.session.commit()
    client.set_cookie(cookie_name, cookie_val)


def test_load_session(client, session_cookie, example_endpoint, session_model, session_manager):
    # We set an arbitrary authentication so the session doesn't get deleted
    session_model.last_email_auth = datetime.now(timezone.utc)
    db.session.commit()

    initial_last_active = session_model.last_active

    response = client.get("/example")

    assert session_manager.current_session == session_model
    # Check that last_active got updated
    assert session_model.last_active > initial_last_active


def test_keyfob_auth_context(client, session_cookie, example_endpoint, session_model, session_manager):
    session_model.last_keyfob_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"plastic"}


def test_keyfob_max_idle(client, session_cookie, example_endpoint, session_model, session_manager):
    long_time_ago = datetime.now(timezone.utc) - session_manager.keyfob_max_idle
    session_model.last_keyfob_auth = long_time_ago
    session_model.last_active = long_time_ago
    session_model.created = long_time_ago
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == set()
    assert session_manager.current_session == None


def test_recent_email_auth(client, session_cookie, example_endpoint, session_model, session_manager):
    session_model.last_email_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze", "silver"}


def test_recent_totp_auth(client, session_cookie, example_endpoint, session_model, session_manager):
    session_model.last_totp_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze", "silver", "gold"}


def test_recent_passkey_auth(client, session_cookie, example_endpoint, session_model, session_manager):
    session_model.last_passkey_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze", "silver", "gold"}


@pytest.mark.parametrize("auth_type", ["email", "totp", "passkey"])
def test_elevated_auth_expiry(
    client, session_cookie, example_endpoint, session_model, auth_type, session_manager
):
    some_time_ago = (
        datetime.now(timezone.utc) - session_manager.elevated_auth_expiry
    )
    setattr(session_model, f"last_{auth_type}_auth", some_time_ago)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze"}


@pytest.mark.parametrize("auth_type", ["email", "totp", "passkey"])
def test_login_max_idle(
    client, session_cookie, example_endpoint, session_model, auth_type, session_manager
):
    long_time_ago = datetime.now(timezone.utc) - session_manager.login_max_idle
    setattr(session_model, f"last_{auth_type}_auth", long_time_ago)
    session_model.last_active = long_time_ago
    session_model.created = long_time_ago
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == set()
    assert session_manager.current_session == None


@pytest.mark.parametrize("auth_type", ["email", "keyfob", "totp", "passkey"])
def test_authenticate_session(app, client, member_model, auth_type, session_manager):
    now = datetime.now(timezone.utc)

    @app.route("/example")
    def example():
        session_manager.authenticate_session(member_model, {auth_type: now})
        return "OK"

    response = client.get("/example")

    cookie = client.get_cookie(session_manager.cookie_name)
    assert cookie is not None
    session = get_from_secure_uri(db, Session, cookie.value, "secret_hash")
    assert session is not None
    assert getattr(session, f"last_{auth_type}_auth") == now

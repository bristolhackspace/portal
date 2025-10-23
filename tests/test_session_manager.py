from datetime import datetime, timedelta, timezone
import secrets
import uuid
import pytest

from portal.extensions import db, session_manager
from portal.helpers import hash_token
from portal.models import Session, User


@pytest.fixture()
def init_session_manager(app, init_db):
    session_manager.init_app(app)


@pytest.fixture()
def example_endpoint(app):
    @app.route("/example")
    def example():
        return "OK"


@pytest.fixture()
def user_model(app_context):
    user = User(display_name="Test User")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def session_secret():
    return secrets.token_urlsafe()


@pytest.fixture()
def session_model(user_model, session_secret, app_context):
    # We set now to a few seconds in the past so we can do some update checks
    now = datetime.now(timezone.utc) - timedelta(seconds=10)
    sess = Session(
        id=uuid.uuid4(),
        secret_hash=hash_token(session_secret),
        user=user_model,
        created=now,
        last_active=now,
    )
    db.session.add(sess)
    db.session.commit()
    return sess


@pytest.fixture()
def session_cookie(
    client, app_context, init_session_manager, session_secret, session_model
):
    cookie_name = session_manager._state.cookie_name
    cookie_val = f"{session_model.id.hex}:{session_secret}"
    client.set_cookie(cookie_name, cookie_val)


def test_load_session(client, session_cookie, example_endpoint, session_model):
    # We set an arbitrary authentication so the session doesn't get deleted
    session_model.last_email_auth = datetime.now(timezone.utc)
    db.session.commit()

    initial_last_active = session_model.last_active

    response = client.get("/example")

    assert session_manager.current_session == session_model
    # Check that last_active got updated
    assert session_model.last_active > initial_last_active


def test_keyfob_auth_context(client, session_cookie, example_endpoint, session_model):
    session_model.last_keyfob_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"plastic"}


def test_keyfob_max_idle(client, session_cookie, example_endpoint, session_model):
    long_time_ago = datetime.now(timezone.utc) - session_manager._state.keyfob_max_idle
    session_model.last_keyfob_auth = long_time_ago
    session_model.last_active = long_time_ago
    session_model.created = long_time_ago
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == set()
    assert session_manager.current_session == None


def test_recent_email_auth(client, session_cookie, example_endpoint, session_model):
    session_model.last_email_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze", "silver"}


def test_recent_totp_auth(client, session_cookie, example_endpoint, session_model):
    session_model.last_totp_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze", "silver", "gold"}


def test_recent_passkey_auth(client, session_cookie, example_endpoint, session_model):
    session_model.last_passkey_auth = datetime.now(timezone.utc)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze", "silver", "gold"}


@pytest.mark.parametrize("auth_type", ["email", "totp", "passkey"])
def test_elevated_auth_expiry(
    client, session_cookie, example_endpoint, session_model, auth_type
):
    some_time_ago = (
        datetime.now(timezone.utc) - session_manager._state.elevated_auth_expiry
    )
    setattr(session_model, f"last_{auth_type}_auth", some_time_ago)
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == {"bronze"}


@pytest.mark.parametrize("auth_type", ["email", "totp", "passkey"])
def test_login_max_idle(
    client, session_cookie, example_endpoint, session_model, auth_type
):
    long_time_ago = datetime.now(timezone.utc) - session_manager._state.login_max_idle
    setattr(session_model, f"last_{auth_type}_auth", long_time_ago)
    session_model.last_active = long_time_ago
    session_model.created = long_time_ago
    db.session.commit()

    response = client.get("/example")

    assert session_manager.current_context == set()
    assert session_manager.current_session == None


@pytest.mark.parametrize("auth_type", ["email", "keyfob", "totp", "passkey"])
def test_authenticate_session(app, client, init_session_manager, user_model, auth_type):
    now = datetime.now(timezone.utc)

    @app.route("/example")
    def example():
        session_manager.authenticate_session(user_model, {auth_type: now})
        return "OK"

    response = client.get("/example")

    cookie = client.get_cookie(session_manager._state.cookie_name)
    assert cookie is not None
    id_, secret = cookie.value.split(":")
    session = db.session.get(Session, uuid.UUID(hex=id_))
    assert session is not None
    assert session.secret_hash == hash_token(secret)
    assert getattr(session, f"last_{auth_type}_auth") == now

import hmac
import uuid

from datetime import datetime, timedelta, timezone
from flask import request
import pytest

from portal.extensions import db
from portal.models import Member
from portal.models.member import Session
from portal.systems.discourse_connect import (
    DiscourseConnectError,
    compute_sig,
    decode_sso,
    encode_sso,
)


@pytest.fixture()
def member_model(init_db):
    member = Member(id=1, display_name="Test Member", email="example@example.com")
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


def test_authenticate(app, client, session_model, discourse_connect):
    # Build a login request as if it was coming from a DiscourseConnect consumer
    sso = {"return_sso_url": "https://example.com/login", "nonce": "abc123"}
    sso_encoded = encode_sso(sso)
    sig = compute_sig(discourse_connect.secret, sso_encoded)

    redirect_url = None

    # Do the authentication with the above request and a premade session
    @app.route("/authenticate")
    def authenticate():
        nonlocal redirect_url
        redirect_url = discourse_connect.authenticate(request, session_model)
        return "OK"

    response = client.get(
        "/authenticate", query_string={"sso": sso_encoded.decode("utf-8"), "sig": sig}
    )

    # Check the request happened successfully
    assert redirect_url is not None

    # Check the path without the query is unmodified
    assert redirect_url.host == "example.com"
    assert redirect_url.scheme == "https"
    assert redirect_url.path == "/login"

    query = redirect_url.query

    sig = query["sig"]
    sso = query["sso"]
    # Check the response signature was generated correctly
    assert (
        hmac.compare_digest(
            compute_sig(discourse_connect.secret, sso.encode("utf-8")), sig
        )
        == True
    )

    # Check the response payload contains the right data
    sso_decoded = decode_sso(sso)
    assert sso_decoded["nonce"] == ["abc123"]
    assert sso_decoded["email"] == [session_model.member.email]
    assert sso_decoded["external_id"] == [session_model.member.get_sub()]
    assert sso_decoded["name"] == [session_model.member.display_name]


def test_authenticate_wrong_secret(app, client, session_model, discourse_connect):
    # Build a login request as if it was coming from a bad DiscourseConnect consumer
    sso = {"return_sso_url": "https://example.com/login", "nonce": "abc123"}
    sso_encoded = encode_sso(sso)
    sig = compute_sig("incorrect secret".encode("utf-8"), sso_encoded)

    # Do the authentication with the above request and a premade session
    @app.route("/authenticate")
    def authenticate():
        with pytest.raises(DiscourseConnectError):
            discourse_connect.authenticate(request, session_model)
        return "OK"

    response = client.get(
        "/authenticate", query_string={"sso": sso_encoded.decode("utf-8"), "sig": sig}
    )

    assert response.text == "OK"


def test_authenticate_missing_signature(app, client, session_model, discourse_connect):
    # Build a login request as if it was coming from a bad DiscourseConnect consumer
    sso = {"return_sso_url": "https://example.com/login", "nonce": "abc123"}
    sso_encoded = encode_sso(sso)

    # Do the authentication with the above request and a premade session
    @app.route("/authenticate")
    def authenticate():
        with pytest.raises(DiscourseConnectError):
            discourse_connect.authenticate(request, session_model)
        return "OK"

    response = client.get(
        "/authenticate", query_string={"sso": sso_encoded.decode("utf-8")}
    )

    assert response.text == "OK"

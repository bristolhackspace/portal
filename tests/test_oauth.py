import secrets
import uuid
import pytest
import typing

from portal.extensions import db, oauth
from portal.helpers import hash_token
from portal.models import OAuthClient, OAuthRequest
from portal.systems.oauth import OAuthError

@pytest.fixture()
def init_oauth(app, init_db):
    oauth.init_app(app)

@pytest.fixture()
def oauth_client(init_db, app_context) -> OAuthClient:
    client = OAuthClient(
        id=uuid.uuid4(),
        name="Demo client"
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture()
def request_secret():
    return secrets.token_urlsafe()

@pytest.fixture()
def oauth_request(oauth_client, request_secret) -> OAuthRequest:
    req = OAuthRequest(
        id=uuid.uuid4(),
        token_hash=hash_token(request_secret),
        client=oauth_client,
        response_type={"code"},
        scope={"openid", "email"},
        redirect_uri="http://example.com",
        state="123",
        nonce="abc",
        acr_values="bronze silver"
    )
    db.session.add(req)
    db.session.commit()
    return req


def test_capture_request(app, init_oauth, client, oauth_client):
    req: OAuthRequest|None = None

    @app.route("/example")
    def example():
        nonlocal req
        req = oauth.capture_request()
        return "OK"
    
    query_string = dict(
        scope="openid email",
        response_type="code",
        client_id=oauth_client.id.hex,
        redirect_uri="http://example.com",
        state="123",
        nonce="abc",
        acr_values="bronze silver"
    )

    response = client.get("/example", query_string=query_string)

    assert req is not None
    req = typing.cast(OAuthRequest, req)

    assert req.client == oauth_client
    assert req.scope == set(query_string["scope"].split())
    assert req.response_type == set(query_string["response_type"].split())
    assert req.redirect_uri == query_string["redirect_uri"]
    assert req.state == query_string["state"]
    assert req.nonce == query_string["nonce"]
    assert req.acr_values == query_string["acr_values"]


@pytest.mark.parametrize("missing_arg", ["scope", "response_type", "client_id", "redirect_uri"])
def test_invalid_request(app, init_oauth, client, oauth_client, missing_arg):
    @app.route("/example")
    def example():
        with pytest.raises(OAuthError) as exc_info:
            oauth.capture_request()
        assert exc_info.value.error == "invalid_request"
        return "OK"
    
    query_string = dict(
        scope="openid email",
        response_type="code",
        client_id=oauth_client.id.hex,
        redirect_uri="http://example.com"
    )

    del query_string[missing_arg]

    response = client.get("/example", query_string=query_string)


def test_capture_request_uri(app, init_oauth, client, request_secret, oauth_request):
    req: OAuthRequest|None = None

    @app.route("/example")
    def example():
        nonlocal req
        req = oauth.capture_request()
        return "OK"

    query_string = dict(
        request_uri=f"{oauth_request.id.hex}:{request_secret}",
        client_id=oauth_request.client.id.hex
    )

    response = client.get("/example", query_string=query_string)

    assert req is not None
    req = typing.cast(OAuthRequest, req)

    assert req == oauth_request

def test_build_redirect_uri(app, init_oauth, client, oauth_request):
    req: OAuthRequest|None = None

    @app.route("/example")
    def example():
        nonlocal req
        req = oauth.capture_request()
        return "OK"

    redirect_uri = oauth.build_redirect_url(oauth_request, "example")
    db.session.commit()

    response = client.get(redirect_uri)

    assert req is not None
    req = typing.cast(OAuthRequest, req)

    assert req == oauth_request
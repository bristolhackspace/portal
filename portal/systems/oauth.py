
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import jwt
import secrets
import urllib.parse
import uuid
from flask import Flask, Response, current_app, g, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
import yarl

from portal.helpers import build_secure_uri, get_from_secure_uri, hash_token
from portal.models import OAuthClient, OAuthRequest, OAuthResponse
from portal.systems.jwks import JWKs
from portal.systems.session_manager import SessionManager


class OAuthError(Exception):
    def __init__(self, error: str, error_description: str|None=None):
        super().__init__(error)
        self.error=error
        self.error_description=error_description


class _State:
    def __init__(self, app: Flask):
        self.id_token_expiry = self.as_timedelta(app.config.get("OAUTH_ID_TOKEN_EXPIRY", timedelta(hours=1)))

    @staticmethod
    def as_timedelta(value: int | float | timedelta) -> timedelta:
        if not isinstance(value, timedelta):
            value = timedelta(seconds=value)
        return value

class OAuth:
    def __init__(
        self,
        db: SQLAlchemy,
        app: Flask | None = None,
    ):
        self.db = db

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.oauth"] = _State(app)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.oauth"]
        return state

    def capture_request(self) -> OAuthRequest:
        request_uri = request.args.get("request_uri")
        if request_uri is not None:
            req = get_from_secure_uri(self.db, OAuthRequest, request_uri)
            if req is None:
                raise OAuthError("invalid_request", "Invalid request_uri")

            client_id = request.args.get("client_id")
            if client_id != req.client_id.hex:
                raise OAuthError("invalid_request", "Invalid request_uri")

            # We save these in case they are needed for an error response later
            g.oauth_redirect_uri = req.redirect_uri
            g.oauth_response_mode = req.response_mode

            return req

        # Client ID and redirect URI should be verified first as these may be used
        # in future OAuthErrors
        client_id = request.args.get("client_id")
        client = self.db.session.get(OAuthClient, uuid.UUID(hex=client_id)) if client_id else None
        if client is None:
            raise OAuthError("unauthorized_client", "client_id not recognised or unauthorized")

        allowed_redirect_uris = client.redirect_uris.split()
        redirect_uri = request.args.get("redirect_uri", allowed_redirect_uris[0])
        if redirect_uri not in allowed_redirect_uris:
            raise OAuthError("invalid_request", "Invalid redirect_uri")

        response_type = set(request.args.get("response_type", "").split())
        if response_type != {"code"}:
            raise OAuthError("unsupported_response_type", "Only 'code' response type is supported")

        response_mode = "query"

        # We save these in case they are needed for an error response later
        g.oauth_redirect_uri = redirect_uri
        g.oauth_response_mode = response_mode

        scope = set(request.args.get("scope", "").split())
        if not scope:
            raise OAuthError("invalid_request", "Missing scope parameter")

        state = request.args.get("state")
        nonce = request.args.get("nonce")
        acr_values = request.args.get("acr_values")

        req = OAuthRequest(
            id=uuid.uuid4(),
            token_hash="",
            client=client,
            response_type=response_type,
            response_mode=response_mode,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            nonce=nonce,
            acr_values=acr_values,
        )
        self.db.session.add(req)
        return req

    def build_redirect_url(self, req: OAuthRequest, route: str) -> str:
        request_uri = build_secure_uri(req)
        return url_for(route, request_uri=request_uri, client_id=req.client.id.hex)

    def authenticate_request(self, req: OAuthRequest, session_manager: SessionManager) -> str|None:
        current_session = session_manager.current_session
        if not current_session:
            return None

        req.session=current_session

        session_acr = session_manager.current_context

        if req.acr_values:
            for requested_acr in req.acr_values.split(req.acr_values):
                if requested_acr in session_acr:
                    return requested_acr
        elif "bronze" in session_acr:
            return "bronze"
        elif "plastic" in session_acr:
            return "plastic"
        else:
            return None


    def build_response(self, req: OAuthRequest, acr: str|None, jwks: JWKs) -> OAuthResponse:
        if req.session is None:
            raise ValueError("Request must be authenticated with a session")

        now = datetime.now(timezone.utc)
        signing_key = jwks.get_signing_key()

        params = {}

        id_token = {
            "iss": "http://localhost",
            "sub": f"user_{req.session.user.id}",
            "aud": [req.client.id.hex],
            "exp": int((now+self._state.id_token_expiry).timestamp()),
            "iat": int(now.timestamp()),
        }
        if req.nonce:
            id_token["nonce"] = req.nonce
        if acr:
            id_token["acr"] = acr

        response = OAuthResponse(
            id=uuid.uuid4(),
            token_hash="",
            id_token=jwt.encode(id_token, signing_key, headers={"kid": signing_key.key_id}),
            state=req.state
        )
        self.db.session.add(response)

        return response

    def process_response(self, resp: OAuthResponse) -> Response:
        redirect_uri = g.oauth_redirect_uri
        response_mode = g.oauth_response_mode

        url = yarl.URL(redirect_uri)
        code = build_secure_uri(resp)
        self.db.session.commit()
        query={"code":code}
        if resp.state:
            query["state"] = resp.state

        if response_mode == "query":
            url = url.update_query(**query)
            return make_response(redirect(str(url)))
        elif response_mode == "fragment":
            qs = urllib.parse.urlencode(query)
            url=url.with_fragment(qs)
            return make_response(redirect(str(url)))
        else:
            raise RuntimeError("Unknown response_mode")


    def handle_token_request(self) -> Response:
        authorization = request.headers.get("Authorization")
        client = None
        if authorization:
            parts = authorization.split()
            if len(parts) != 2:
                raise OAuthError("invalid_request", "Invalid Authorization header format")
            scheme, credential = parts
            if scheme != "Basic":
                raise OAuthError("invalid_request", "Unsupported Authorization scheme")
            credential = base64.urlsafe_b64decode(credential).decode("utf-8")
            client = get_from_secure_uri(self.db, OAuthClient, credential)
        elif "client_id" in request.args:
            client_id = request.args["client_id"]
            public_client = self.db.session.get(OAuthClient, uuid.UUID(hex=client_id))
            if public_client and public_client.secret_hash is None:
                client = public_client

        if client is None:
            raise OAuthError("access_denied", "Failed to authenticate client")

        allowed_redirect_uris = client.redirect_uris.split()
        grant_type=request.args.get("grant_type")
        redirect_uri=request.args.get("redirect_uri", allowed_redirect_uris[0])
        code=request.args.get("code", "")

        if redirect_uri not in allowed_redirect_uris:
            raise OAuthError("invalid_request", "Invalid redirect_uri")

        g.oauth_redirect_uri="redirect_uri"
        g.oauth_response_mode="json"

        resp = get_from_secure_uri(self.db, OAuthResponse, code)

        if resp is None:
            raise OAuthError("invalid_request", "Invalid or expired code")

        params = {}
        if resp.id_token:
            params["id_token"] = resp.id_token
        if resp.state:
            params["state"] = resp.state

        return make_response(params)

    def handle_error(self, error: OAuthError, template: str) -> Response:
        oauth_redirect_uri = g.get("oauth_redirect_uri")
        oauth_response_mode = g.get("oauth_response_mode", "query")

        if oauth_redirect_uri:
            url = yarl.URL(oauth_redirect_uri)
            query = {"error": error.error}
            if error.error_description:
                query["error_description"] = error.error_description
            if oauth_response_mode == "query":
                url = url.update_query(**query)
                return make_response(redirect(str(url)))
            elif oauth_response_mode == "fragment":
                qs = urllib.parse.urlencode(query)
                url=url.with_fragment(qs)
                return make_response(redirect(str(url)))
            elif oauth_response_mode == "json":
                return make_response(query)

        # Unable to handle as an OAuth error response. Show the error as a local page instead
        return make_response(render_template(template, error=error))
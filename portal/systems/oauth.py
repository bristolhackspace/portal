from datetime import datetime, timezone
from typing import Any
import typing
from authlib.oauth2.rfc6749 import (
    BaseGrant,
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    OAuth2Request,
    OAuth2Payload,
    AccessDeniedError
)
from authlib.oauth2 import OAuth2Error
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer as _AuthorizationServer
)
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request
from authlib.oidc.core import grants, UserInfo
import uuid
from flask import Flask, Request, Response, current_app, request as flask_req
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa

from portal.models import User, Session, OAuth2Client, Token, AuthorizationCode
from portal.systems.jwks import JWKs
from portal.systems.session_manager import SessionManager


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def save_authorization_code(self, code, request: "SessionOAuth2Request"):
        payload = typing.cast(OAuth2Payload, request.payload)
        nonce = payload.data.get('nonce')
        auth_code = AuthorizationCode(
            user=request.user,
            code=code,
            client=request.client,
            redirect_uri=payload.redirect_uri,
            scope=payload.scope,
            auth_time=request.session.last_auth if request.session else datetime.now(timezone.utc),
            nonce=nonce,
            acr=request.acr,
            amr=" ".join(request.session.calculate_amr()) if request.session else None
        )
        self.server.db.session.add(auth_code)
        self.server.db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        query = sa.select(AuthorizationCode).filter_by(
            code=code,
            client=client
        )
        item = self.server.db.session.execute(query).scalar_one_or_none()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        self.server.db.session.delete(authorization_code)
        self.server.db.session.commit()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


class OpenIDCode(grants.OpenIDCode):
    def __init__(self, server: "AuthorizationServer", require_nonce=False):
        super().__init__(require_nonce)
        self.server = server

    def exists_nonce(self, nonce, request):
        query = sa.select(AuthorizationCode).filter_by(
            nonce=nonce,
            client=request.client
        )
        item = self.server.db.session.execute(query).scalar_one_or_none()
        return bool(item)

    def get_jwt_config(self, grant):
        jwk = self.server.jwks.get_signing_key()
        return {
            'key': jwk.to_key(private=True),
            'alg': jwk.alg,
            'iss': 'https://portal.samp20.com',
            'exp': 3600
        }

    def generate_user_info(self, user: User, scope):
        return UserInfo(
            sub=user.get_sub(),
            name=user.display_name,
            email=user.email
        ).filter(scope)


class AuthContext:
    def __init__(self):
        pass

    def validate_auth_context(self, grant, redirect_uri):
        request: SessionOAuth2Request = grant.request
        if not request.acr:
            raise AccessDeniedError("Current authentication method inadequate")

    def __call__(self, grant):
        grant.register_hook(
            "after_validate_authorization_request_payload",
            self.validate_auth_context,
        )


class SessionOAuth2Request(FlaskOAuth2Request):
    def __init__(self, request: Request):
        super().__init__(request)
        self.session: Session|None = None
        self.acr: str|None = None


class AuthorizationServer(_AuthorizationServer):
    def __init__(self, app: Flask, db: SQLAlchemy, jwks: JWKs, session: SessionManager):
        super().__init__(app)
        self.db = db
        self.jwks = jwks
        self.session = session

    def create_oauth2_request(self, request):
        oauth_req = SessionOAuth2Request(flask_req)
        oauth_req.session = self.session.current_session
        payload = oauth_req.payload
        if payload:
            acr_values = payload.data.get("acr_values", "").split()
            oauth_req.acr = self.session.find_context(acr_values)
        return oauth_req

    def query_client(self, client_id: str):
        return self.db.session.get(OAuth2Client, uuid.UUID(hex=client_id))

    def save_token(self, token_data: dict[str, Any], request: OAuth2Request):
        token = Token(
            user=request.user,
            client=request.client,
            issued_at=datetime.now(timezone.utc),
            **token_data
        )

        self.db.session.add(token)
        self.db.session.commit()

class OAuth:
    def __init__(
        self,
        db: SQLAlchemy,
        jwks: JWKs,
        session: SessionManager,
        app: Flask | None = None,
    ):
        self.db = db
        self.jwks = jwks
        self.session = session

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        server = AuthorizationServer(app, self.db, self.jwks, self.session)
        server.register_grant(AuthorizationCodeGrant, [OpenIDCode(server, require_nonce=True), AuthContext()])
        app.extensions["hs.portal.oauth"] = server

    @property
    def _state(self) -> AuthorizationServer:
        state = current_app.extensions["hs.portal.oauth"]
        return state

    def get_consent_grant(self, user: User|None) -> BaseGrant:
        return self._state.get_consent_grant(end_user=user)

    def create_authorization_response(self, grant: BaseGrant, user: User|None) -> Response:
        return self._state.create_authorization_response(grant=grant, grant_user=user) # pyright: ignore[reportReturnType]

    def handle_error_response(self, error: OAuth2Error) -> Response:
        request = self._state.create_oauth2_request(None)
        return self._state.handle_error_response(request, error) # pyright: ignore[reportReturnType]

    def create_token_response(self) -> Response:
        return self._state.create_token_response() # pyright: ignore[reportReturnType]
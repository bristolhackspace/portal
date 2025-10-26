from datetime import datetime, timezone
from typing import Any
import typing
from authlib.oauth2.rfc6749 import (
    BaseGrant,
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    OAuth2Request,
    OAuth2Payload
)
from authlib.oauth2 import OAuth2Error
from authlib.integrations.flask_oauth2 import AuthorizationServer as _AuthorizationServer
import uuid
from flask import Flask, Response, current_app
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa

from portal.models import User, OAuth2Client, Token, AuthorizationCode


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        payload = typing.cast(OAuth2Payload, request.payload)
        auth_code = AuthorizationCode(
            user=request.user,
            code=code,
            client=request.client,
            redirect_uri=payload.redirect_uri,
            scope=payload.scope,
            auth_time=datetime.now(timezone.utc)
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

class AuthorizationServer(_AuthorizationServer):
    def __init__(self, app: Flask, db: SQLAlchemy):
        super().__init__(app)
        self.db = db

    def query_client(self, client_id: str):
        return self.db.session.get(OAuth2Client, uuid.UUID(hex=client_id))

    def save_token(self, token_data: dict[str, Any], request: OAuth2Request):
        token = Token(
            user=request.user,
            client=request.client,
            **token_data
        )

        self.db.session.add(token)
        self.db.session.commit()

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
        server = AuthorizationServer(app, self.db)
        server.register_grant(AuthorizationCodeGrant)
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
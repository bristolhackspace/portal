

from datetime import timedelta
import hashlib
import secrets
import uuid
from flask import Flask, current_app, request, url_for
from flask_sqlalchemy import SQLAlchemy

from portal.models import OAuthClient, OAuthRequest
from portal.systems.session_manager import SessionManager


class OAuthError(Exception):
    def __init__(self, error: str, error_description: str|None=None, redirect_uri: str|None=None, response_mode: str|None=None):
        super().__init__(error)
        self.error=error
        self.error_description=error_description


class _State:
    def __init__(self, app: Flask):
        pass

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
            parts = request_uri.split(":")
            if len(parts) != 2:
                raise OAuthError("invalid_request", "Invalid request_uri")
            id_, token = parts
            req = self.db.session.get(OAuthRequest, uuid.UUID(hex=id_))
            if req is None:
                raise OAuthError("invalid_request", "Invalid request_uri")
            if not secrets.compare_digest(self.hash_secret(token), req.token_hash):
                raise OAuthError("invalid_request", "Invalid request_uri")
            
            client_id = request.args.get("client_id")
            if client_id != req.client_id.hex:
                raise OAuthError("invalid_request", "Invalid request_uri")
            return req

        # Client ID and redirect URI should be verified first as these may be used
        # in future OAuthErrors
        client_id = request.args.get("client_id")
        client = self.db.session.get(OAuthClient, uuid.UUID(hex=client_id)) if client_id else None
        if client is None:
            raise OAuthError("unauthorized_client", "client_id not recognised or unauthorized")
        
        redirect_uri = request.args.get("redirect_uri")
        if redirect_uri is None:
            raise OAuthError("invalid_request", "Missing redirect_uri")
        # TODO validate redirect URI against client

        response_type = set(request.args.get("response_type", "").split())
        if response_type != {"code"}:
            raise OAuthError("unsupported_response_type", "Only 'code' response type is supported")

        response_mode = "query"

        scope = set(request.args.get("scope", "").split())
        if not scope:
            raise OAuthError("invalid_request", "Missing scope parameter", redirect_uri, response_mode)

        state = request.args.get("state")
        nonce = request.args.get("nonce")
        acr_values = request.args.get("acr_values")

        req = OAuthRequest(
            id=uuid.uuid4(),
            token_hash="",
            client=client,
            response_type=response_type,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            nonce=nonce,
            acr_values=acr_values,
        )
        self.db.session.add(req)
        return req
    
    def build_redirect_url(self, req: OAuthRequest, route: str) -> str:
        token = secrets.token_urlsafe()
        req.token_hash = self.hash_secret(token)
        request_uri = f"{req.id.hex}:{token}"
        return url_for(route, request_uri=request_uri, client_id=req.client.id.hex)
    
    def authenticate_request(self, req: OAuthRequest, session_manager: SessionManager) -> str|None:
        if not session_manager.current_session:
            return None
        
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

    @staticmethod
    def hash_secret(secret: str | bytes) -> str:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha256(secret).hexdigest()
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
import functools
import hashlib
import secrets
import typing
import uuid
from flask import (
    Flask,
    Request,
    Response,
    after_this_request,
    current_app,
    g,
    request,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa

from portal.models import AuthFlow, User
from portal.systems.mailer import Mailer
from portal.systems.session_manager import SessionManager


class FlowStep(Enum):
    INVALID = auto()
    VERIFY_EMAIL = auto()
    VERIFY_TOTP = auto()
    FINISHED = auto()


class _State:
    def __init__(self, app: Flask):
        self.flow_expiry = self.as_timedelta(
            app.config.get("AUTH_FLOW_EXPIRY", timedelta(minutes=10))
        )
        self.cookie_name: str = app.config.get("AUTH_FLOW_COOKIE_NAME", "flow_id")
        self.cookie_secure: bool = app.config.get("AUTH_FLOW_COOKIE_SECURE", False)

    @staticmethod
    def as_timedelta(value: int | float | timedelta) -> timedelta:
        if not isinstance(value, timedelta):
            value = timedelta(seconds=value)
        return value


class Authentication:
    def __init__(
        self,
        mailer: Mailer,
        db: SQLAlchemy,
        magic_link_route: str,
        app: Flask | None = None,
    ):
        self.mailer = mailer
        self.db = db
        self.magic_link_route = magic_link_route

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.mail_auth"] = _State(app)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.mail_auth"]
        return state

    def send_magic_email(self, email: str) -> AuthFlow:
        query = sa.select(User).filter(User.email == email)
        user = self.db.session.execute(query).scalar_one_or_none()

        now = datetime.now(timezone.utc)

        flow_token = secrets.token_urlsafe()
        email_token = secrets.token_urlsafe()

        flow = AuthFlow(
            id=uuid.uuid4(),
            user=user,
            flow_token_hash=self.hash_token(flow_token),
            email_token_hash=self.hash_token(email_token),
            visual_code=secrets.token_hex(2),
            expiry=now + self._state.flow_expiry,
        )

        magic_url = url_for(
            self.magic_link_route, id=flow.id.hex, token=email_token, _external=True
        )

        self.db.session.add(flow)
        self.db.session.commit()

        if user:
            self.mailer.send_email(
                user=user,
                template="emails/magic_link",
                subject="Your Login link",
                flow=flow,
                magic_url=magic_url,
            )

        after_this_request(functools.partial(self.set_flow_cookie, flow, flow_token))

        g.flow = flow

        return flow

    def set_flow_cookie(
        self, flow: AuthFlow, flow_token: str, response: Response
    ) -> Response:
        value = f"{flow.id.hex}:{flow_token}"
        response.set_cookie(
            key=self._state.cookie_name,
            value=value,
            max_age=None,
            httponly=True,
            secure=self._state.cookie_secure,
        )
        return response

    def load_flow(self):
        parts = request.cookies.get(self._state.cookie_name, "").split(":")
        if len(parts) != 2:
            return
        id_, secret = parts

        flow = self.db.session.get(AuthFlow, uuid.UUID(hex=id_))

        if flow is None:
            return

        if not secrets.compare_digest(flow.flow_token_hash, self.hash_token(secret)):
            return

        g.flow = flow

    @property
    def current_flow(self) -> AuthFlow | None:
        return g.get("flow")

    def verify_magic_link(self, request: Request, commit: bool) -> AuthFlow | None:
        link_id = request.args.get("id")
        token = request.args.get("token", "")

        flow = self.db.session.get(AuthFlow, link_id)

        if not flow:
            return None

        if flow.expiry < datetime.now(timezone.utc):
            return None

        if not secrets.compare_digest(flow.email_token_hash, self.hash_token(token)):
            return None

        return flow

    def try_authenticate(self, session_manager: SessionManager) -> FlowStep:
        flow = self.current_flow

        if not flow:
            return FlowStep.INVALID

        flow_step = self._flow_next_step(flow)

        if flow_step != FlowStep.FINISHED:
            return flow_step

        auth_methods = {}

        if flow.email_verified:
            auth_methods["email"] = flow.email_verified

        if flow.totp_verified:
            auth_methods["totp"] = flow.totp_verified

        session_manager.authenticate_session(flow.user, methods=auth_methods)

        return flow_step

    def _flow_next_step(self, flow: AuthFlow) -> FlowStep:
        if not flow.email_verified:
            return FlowStep.VERIFY_EMAIL
        if flow.user and flow.user.totp_secret:
            if not flow.totp_verified:
                return FlowStep.VERIFY_TOTP
        return FlowStep.FINISHED

    @staticmethod
    def hash_token(secret: str | bytes) -> str:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha256(secret).hexdigest()

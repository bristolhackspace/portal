from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
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
    make_response,
    redirect,
    request,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa

from portal.helpers import build_secure_uri, get_from_secure_uri, hash_token
from portal.models import AuthFlow, User
from portal.systems.mailer import Mailer
from portal.systems.session_manager import SessionManager


class FlowStep(Enum):
    NOT_STARTED = auto()
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
        session_manager: SessionManager,
        app: Flask | None = None,
    ):
        self.mailer = mailer
        self.db = db
        self.session_manager = session_manager

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.mail_auth"] = _State(app)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.mail_auth"]
        return state

    def begin_flow(self, redirect_uri:str|None=None) -> AuthFlow:
        now = datetime.now(timezone.utc)

        flow = AuthFlow(
            id=uuid.uuid4(),
            flow_token_hash="",
            expiry=now + self._state.flow_expiry,
            redirect_uri=redirect_uri
        )

        flow_secure_uri = build_secure_uri(flow, "flow_token_hash")

        self.db.session.add(flow)
        self.db.session.commit()

        after_this_request(functools.partial(self.set_flow_cookie, flow_secure_uri))

        g.flow = flow
        return flow

    def send_magic_email(self, email: str, magic_link_route: str):
        flow = self.current_flow
        if flow is None:
            flow = self.begin_flow()

        query = sa.select(User).filter(User.email == email)
        user = self.db.session.execute(query).scalar_one_or_none()

        now = datetime.now(timezone.utc)

        otp = f"{secrets.randbelow(1000000):06d}"

        ph = PasswordHasher()

        flow.email_otp_hash = ph.hash(otp)

        flow_id = flow.id.hex
        flow.expiry=now + self._state.flow_expiry
        flow.user = user

        magic_url = url_for(
            magic_link_route, flow_id=flow_id, otp=otp, _external=True
        )

        self.db.session.commit()

        if user:
            self.mailer.send_email(
                user=user,
                template="emails/magic_link",
                subject="Your Login code",
                otp=otp,
                flow=flow,
                magic_url=magic_url,
            )

    def set_flow_cookie(
        self, flow_secure_uri: str, response: Response
    ) -> Response:
        response.set_cookie(
            key=self._state.cookie_name,
            value=flow_secure_uri,
            max_age=None,
            httponly=True,
            secure=self._state.cookie_secure,
        )
        return response

    def load_flow(self):
        flow_uri = request.cookies.get(self._state.cookie_name, "")
        flow = get_from_secure_uri(self.db, AuthFlow, flow_uri, attribute="flow_token_hash")

        if flow is None:
            return

        g.flow = flow

    @property
    def current_flow(self) -> AuthFlow | None:
        return g.get("flow")

    def verify_email_otp(self, otp: str) -> bool:
        flow = self.current_flow

        if not flow:
            return False

        if flow.expiry < datetime.now(timezone.utc):
            return False

        ph = PasswordHasher()

        try:
            ph.verify(flow.email_otp_hash, otp)
        except (VerificationError, InvalidHashError):
            return False

        flow.email_verified = datetime.now(timezone.utc)
        self.db.session.commit()

        return True

    def try_authenticate(self, default_redirect_route: str) -> FlowStep|Response:
        flow = self.current_flow

        if not flow:
            return FlowStep.NOT_STARTED

        flow_step = self._flow_next_step(flow)

        if flow_step != FlowStep.FINISHED:
            return flow_step

        auth_methods = {}

        if flow.email_verified:
            auth_methods["email"] = flow.email_verified

        if flow.totp_verified:
            auth_methods["totp"] = flow.totp_verified

        self.session_manager.authenticate_session(flow.user, methods=auth_methods)
        self.db.session.delete(flow)
        self.db.session.commit()

        response = redirect(flow.redirect_uri or default_redirect_route)
        response = make_response(response)
        response.delete_cookie(self._state.cookie_name)

        return response

    def _flow_next_step(self, flow: AuthFlow) -> FlowStep:
        if not flow.email_otp_hash:
            return FlowStep.NOT_STARTED
        if not flow.email_verified:
            return FlowStep.VERIFY_EMAIL
        if flow.user and flow.user.totp_secret:
            if not flow.totp_verified:
                return FlowStep.VERIFY_TOTP
        return FlowStep.FINISHED

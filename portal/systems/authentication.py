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

from portal.helpers import as_timedelta, build_secure_uri, get_from_secure_uri, hash_token
from portal.models import AuthFlow, User
from portal.systems.mailer import BaseMailer
from portal.systems.session_manager import SessionManager
from portal.systems.rate_limiter import RateLimiter


class FlowStep(Enum):
    NOT_STARTED = auto()
    VERIFY_EMAIL = auto()
    VERIFY_TOTP = auto()
    FINISHED = auto()


class Authentication:
    def __init__(
        self,
        mailer: BaseMailer,
        db: SQLAlchemy,
        session_manager: SessionManager,
        rate_limiter: RateLimiter,
        app: Flask,
    ):
        self.mailer = mailer
        self.db = db
        self.session_manager = session_manager
        self.rate_limiter = rate_limiter

        self.flow_expiry = as_timedelta(
            app.config.get("AUTH_FLOW_EXPIRY", timedelta(minutes=10))
        )
        self.cookie_name: str = app.config.get("AUTH_FLOW_COOKIE_NAME", "flow_id")
        self.cookie_secure: bool = app.config.get("AUTH_FLOW_COOKIE_SECURE", False)
        self.email_otp_max_attempts: int = app.config.get("AUTH_FLOW_EMAIL_OTP_MAX_ATTEMPTS", 4)


    def begin_flow(self, redirect_uri:str|None=None) -> AuthFlow:
        now = datetime.now(timezone.utc)

        flow = AuthFlow(
            id=uuid.uuid4(),
            flow_token_hash="",
            expiry=now + self.flow_expiry,
            email_otp_attempts=0,
            redirect_uri=redirect_uri
        )

        flow_secure_uri = build_secure_uri(flow, "flow_token_hash")

        self.db.session.add(flow)
        self.db.session.commit()

        after_this_request(functools.partial(self.set_flow_cookie, flow_secure_uri))

        g.flow = flow
        return flow

    def send_magic_email(self, email: str, magic_link_route: str):
        ip_rate_limit_key = None
        if request.remote_addr is not None:
            ip_addr = self.rate_limiter.normalise_ip(request.remote_addr)
            ip_rate_limit_key = f"email_send_ip_limit:{ip_addr}"
            self.rate_limiter.rate_limit(ip_rate_limit_key, 30, timedelta(hours=12))

        self.rate_limiter.rate_limit(slow_rate_limit_key(email), 5, timedelta(hours=12))
        self.rate_limiter.rate_limit(fast_rate_limit_key(email), 1, timedelta(minutes=1))

        flow = self.current_flow
        if flow is None:
            flow = self.begin_flow()

        flow.ip_rate_limit_key = ip_rate_limit_key

        query = sa.select(User).filter(User.email == email)
        user = self.db.session.execute(query).scalar_one_or_none()

        now = datetime.now(timezone.utc)

        otp = f"{secrets.randbelow(1000000):06d}"

        ph = PasswordHasher()

        flow.email_otp_hash = ph.hash(otp)

        flow_id = flow.id.hex
        flow.expiry=now + self.flow_expiry
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
            key=self.cookie_name,
            value=flow_secure_uri,
            max_age=None,
            httponly=True,
            secure=self.cookie_secure,
        )
        return response

    def load_flow(self):
        flow_uri = request.cookies.get(self.cookie_name, "")
        flow = get_from_secure_uri(self.db, AuthFlow, flow_uri, attribute="flow_token_hash")

        if flow is None:
            return

        g.flow = flow

    @property
    def current_flow(self) -> AuthFlow | None:
        return g.get("flow")

    def verify_email_otp(self, otp: str) -> bool:
        with self.db.session.begin(nested=True):
            flow = self.current_flow

            if not flow:
                return False

            flow.email_otp_attempts += 1
            if flow.email_otp_attempts > self.email_otp_max_attempts:
                return False

            if flow.expiry < datetime.now(timezone.utc):
                return False

            if not flow.email_otp_hash:
                return False

            ph = PasswordHasher()

            try:
                ph.verify(flow.email_otp_hash, otp)
            except (VerificationError, InvalidHashError):
                return False

            flow.email_verified = datetime.now(timezone.utc)
            if flow.ip_rate_limit_key:
                self.rate_limiter.reset_rate_limit(flow.ip_rate_limit_key, commit=False)

            if flow.user:
                self.rate_limiter.reset_rate_limit(slow_rate_limit_key(flow.user.email), commit=False)
                self.rate_limiter.reset_rate_limit(fast_rate_limit_key(flow.user.email), commit=False)


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
        response.delete_cookie(self.cookie_name)

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


def slow_rate_limit_key(email: str) -> str:
    return f"email_send_slow_limit:{email}"

def fast_rate_limit_key(email: str) -> str:
    return f"email_send_fast_limit:{email}"
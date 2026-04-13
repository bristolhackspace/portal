import functools
import secrets
import typing
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import (Flask, Request, Response, after_this_request, g,
                   request, url_for)
from flask_sqlalchemy import SQLAlchemy

from portal.helpers import (as_timedelta, build_secure_uri,
                            get_from_secure_uri)
from portal.models import AuthFlow, Member
from portal.systems.mailer import BaseMailer
from portal.systems.rate_limiter import RateLimiter


class OtpValidationError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)

class Authentication:
    def __init__(
        self,
        mailer: BaseMailer,
        db: SQLAlchemy,
        rate_limiter: RateLimiter,
        app: Flask,
    ):
        self.mailer = mailer
        self.db = db
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

    def send_magic_email(self, email: str, magic_link_route: str, flow: AuthFlow|None=None) -> AuthFlow:
        self.rate_limiter.rate_limit(fast_rate_limit_key(email), 1, timedelta(minutes=1))
        self.rate_limiter.rate_limit(slow_rate_limit_key(email), 5, timedelta(hours=12))

        ip_rate_limit_key = None
        if request.remote_addr is not None:
            ip_addr = self.rate_limiter.normalise_ip(request.remote_addr)
            ip_rate_limit_key = f"email_send_ip_limit:{ip_addr}"
            self.rate_limiter.rate_limit(ip_rate_limit_key, 30, timedelta(hours=12))

        if flow is None:
            flow = self.begin_flow()

        flow.ip_rate_limit_key = ip_rate_limit_key

        query = sa.select(Member).filter(Member.email == email)
        member = self.db.session.execute(query).scalar_one_or_none()

        now = datetime.now(timezone.utc)

        otp = f"{secrets.randbelow(1000000):06d}"

        ph = PasswordHasher()

        flow.email_otp_hash = ph.hash(otp)
        flow.email_otp_attempts = 0

        flow_id = flow.id.hex
        flow.expiry=now + self.flow_expiry
        flow.member = member

        magic_url = url_for(
            magic_link_route, flow_id=flow_id, otp=otp, _external=True
        )

        self.db.session.commit()

        if member:
            self.mailer.send_email(
                member=member,
                template="emails/magic_link",
                subject="Your Login code",
                otp=otp,
                flow=flow,
                magic_url=magic_url,
            )

        return flow

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

    def delete_flow_cookie(self, response: Response) -> Response:
        response.delete_cookie(self.cookie_name)
        return response

    def load_flow(self, request: Request) -> AuthFlow|None:
        flow_uri = request.cookies.get(self.cookie_name, "")
        flow = get_from_secure_uri(self.db, AuthFlow, flow_uri, attribute="flow_token_hash")
        if flow is None:
            return None
        if flow.id.hex != request.args.get("flow_id"):
            return None
        if flow.expiry < datetime.now(timezone.utc):
            return None
        return flow

    @property
    def current_flow(self) -> AuthFlow | None:
        return g.get("flow")

    def verify_email_otp(self, otp: str, flow: AuthFlow) -> typing.Literal[True]:
        try:
            flow.email_otp_attempts += 1
            if flow.email_otp_attempts > self.email_otp_max_attempts:
                raise OtpValidationError("Maximum attempts exceeded. Request another code to try again.")

            # It shouldn't actually be possible for this to fail due to the view checking
            # flow_next_step to decide whether to verify the OTP.
            if not flow.email_otp_hash:
                raise OtpValidationError("Email not sent yet")

            ph = PasswordHasher()

            try:
                ph.verify(flow.email_otp_hash, otp)
            except (VerificationError, InvalidHashError):
                raise OtpValidationError("Incorrect code. Check you are using the most recent email.")

            flow.email_verified = datetime.now(timezone.utc)
            if flow.ip_rate_limit_key:
                self.rate_limiter.reset_rate_limit(flow.ip_rate_limit_key, commit=False)

            if flow.member:
                self.rate_limiter.reset_rate_limit(slow_rate_limit_key(flow.member.email), commit=False)
                self.rate_limiter.reset_rate_limit(fast_rate_limit_key(flow.member.email), commit=False)

            return True
        finally:
            self.db.session.commit()

    def delete_flow(self, flow: AuthFlow, commit:bool=True):
        self.db.session.delete(flow)
        if commit:
            self.db.session.commit()

        after_this_request(self.delete_flow_cookie)


def slow_rate_limit_key(email: str) -> str:
    return f"email_send_slow_limit:{email}"

def fast_rate_limit_key(email: str) -> str:
    return f"email_send_fast_limit:{email}"
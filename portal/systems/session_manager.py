import functools
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from flask import Flask, Response, after_this_request, g, request
from flask_sqlalchemy import SQLAlchemy

from portal.helpers import as_timedelta, build_secure_uri, get_from_secure_uri
from portal.models import Member, Session
from portal.systems.audit import Audit
from portal.systems.cleanup import Cleanup


class SessionManager:
    def __init__(
        self, db: SQLAlchemy, cleanup: Cleanup | None, audit: Audit | None, app: Flask
    ):
        self.db = db
        self.cleanup = cleanup
        self.audit = audit

        self.cookie_name: str = app.config.get("HS_SESSION_NAME", "id")
        self.cookie_max_age = as_timedelta(
            app.config.get("HS_SESSION_MAX_AGE", timedelta(days=30))
        )
        self.cookie_secure: bool = app.config.get("HS_SESSION_SECURE", False)

        self.keyfob_max_idle = as_timedelta(
            app.config.get("HS_KEYFOB_MAX_IDLE", timedelta(minutes=20))
        )
        self.login_max_idle = as_timedelta(
            app.config.get("HS_LOGIN_MAX_IDLE", timedelta(days=30))
        )
        self.elevated_auth_expiry = as_timedelta(
            app.config.get("HS_ELEVATED_AUTH_EXPIRY", timedelta(minutes=20))
        )

        app.before_request(self.load_session)

        if self.cleanup:
            self.cleanup.register_callback("Session", self.cleanup_sessions)

    def load_session(self):
        session_uri = request.cookies.get(self.cookie_name, "")

        session = get_from_secure_uri(self.db, Session, session_uri, "secret_hash")
        if session is None:
            return

        contexts = self.calculate_auth_contexts(session)

        if contexts:
            session.last_active = datetime.now(timezone.utc)
            g.hs_session = session
            g.hs_session_ctx = contexts

            after_this_request(functools.partial(self.update_cookie, session_uri))
        else:
            self.db.session.delete(session)
        self.db.session.commit()

    def authenticate_session(self, member: Member, methods: dict[str, datetime]):
        """Create or authenticate a session using the provided methods

        If a session doesn't currently exist then a new one will be created with the provided member.

        The session will be updated with the authentication times provided in the methods.

        If the current session was for a different member then it will be logged out before creating a new one.

        :param member: Member to authenticate
        :param methods: Dictionary containing authentication method names and timestamps
        """

        if not methods:
            raise ValueError("Authentication methods cannot be empty")

        now = datetime.now(timezone.utc)

        session: Session | None = g.get("hs_session")
        # If the current session is for a different member then delete it
        if session and session.member != member:
            self.db.session.delete(session)
            self.db.session.commit()
            session = None

        new_session = False

        if session is None:
            session = Session(
                id=uuid.uuid4(),
                created=now,
                member=member,
                last_active=now,
                user_agent=request.user_agent.string,
            )
            self.db.session.add(session)
            g.hs_session = session
            latest_auth_time = datetime.fromtimestamp(0, timezone.utc)
            new_session = True
        else:
            latest_auth_time = session.last_auth

        # Rotate secret
        secure_uri = build_secure_uri(session, "secret_hash")

        loggable_methods = dict()
        for method, auth_time in methods.items():
            loggable_methods[method] = auth_time.timestamp()

            match method:
                case "email":
                    session.last_email_auth = auth_time
                case "keyfob":
                    session.last_keyfob_auth = auth_time
                case "totp":
                    session.last_totp_auth = auth_time
                case "passkey":
                    session.last_passkey_auth = auth_time
                case _:
                    raise ValueError(f"Invalid method {method}")

            if auth_time > latest_auth_time:
                latest_auth_time = auth_time

        session.last_auth = latest_auth_time

        self.db.session.commit()

        if self.audit:
            self.audit.log(
                "session",
                "authenticate",
                member,
                {"methods": loggable_methods, "new": new_session},
            )

        # TODO: remove update_cookie call from load_session as this will overwrite it
        after_this_request(functools.partial(self.update_cookie, secure_uri))

    def update_cookie(self, secure_uri: str, response: Response) -> Response:
        response.set_cookie(
            key=self.cookie_name,
            value=secure_uri,
            max_age=self.cookie_max_age,
            httponly=True,
            secure=self.cookie_secure,
        )
        return response

    def calculate_auth_contexts(self, session: Session) -> set[str]:
        """Calculate authentication contexts based on the current session state

        In general the contexts are as follows:
        * ``plastic`` for keyfob logins
        * ``bronze`` for regular logins of any age (within the ``HS_LOGIN_MAX_IDLE`` limit)
        * ``silver`` for recently authenticated single factor (email) logins
        * ``gold`` for recently authenticated two factor (TOTP/passkey) logins

        :param session: Session to get contexts for
        :returns: Set of contexts for this session
        """
        contexts = set()

        now = datetime.now(timezone.utc)

        if session.last_keyfob_auth:
            if now < session.last_active + self.keyfob_max_idle:
                contexts.add("plastic")

        if (
            session.last_email_auth
            or session.last_passkey_auth
            or session.last_totp_auth
        ):
            if now < session.last_active + self.login_max_idle:
                contexts.add("bronze")

        if (
            session.last_email_auth
            and now < session.last_email_auth + self.elevated_auth_expiry
        ):
            contexts.add("silver")

        if (
            session.last_totp_auth
            and now < session.last_totp_auth + self.elevated_auth_expiry
        ):
            contexts.add("silver")
            contexts.add("gold")

        if (
            session.last_passkey_auth
            and now < session.last_passkey_auth + self.elevated_auth_expiry
        ):
            contexts.add("silver")
            contexts.add("gold")

        return contexts

    @property
    def current_context(self) -> set[str]:
        return g.get("hs_session_ctx", set())

    @property
    def current_session(self) -> Session | None:
        return g.get("hs_session")

    def find_context(self, acr_values: list[str] | None) -> str | None:
        if not acr_values:
            acr_values = ["bronze", "plastic"]
        available = self.current_context
        for acr in acr_values:
            if acr in available:
                return acr
        return None

    def logout(self):
        sess = self.current_session
        if sess is None:
            return

        self.db.session.delete(sess)
        self.db.session.commit()

    def cleanup_sessions(self) -> int:
        deleted_count = 0
        query = sa.select(Session)
        sessions = self.db.session.execute(query).scalars()
        for session in sessions:
            if not self.calculate_auth_contexts(session):
                self.db.session.delete(session)
                deleted_count += 1
        self.db.session.commit()
        return deleted_count

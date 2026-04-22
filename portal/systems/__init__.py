from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from portal.systems.audit import Audit
from portal.systems.authentication import Authentication
from portal.systems.cleanup import Cleanup
from portal.systems.discourse_connect import DiscourseConnect
from portal.systems.mailer import BaseMailer
from portal.systems.rate_limiter import RateLimiter
from portal.systems.session_manager import SessionManager


class HackspaceSystems:
    def __init__(self, db: SQLAlchemy, app: Flask):
        self.db = db
        self.cleanup = Cleanup(app)
        self.audit = Audit(db, app)
        self.rate_limiter = RateLimiter(self.db, app)
        self.session_manager = SessionManager(self.db, self.cleanup, self.audit, app)
        self.mailer = BaseMailer.build(app)
        self.authentication = Authentication(
            self.mailer, self.db, self.rate_limiter, app
        )
        self.discourse_auth = DiscourseConnect(self.db, self.audit, app)

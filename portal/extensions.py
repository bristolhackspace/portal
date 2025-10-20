from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from portal import models
from portal.systems.authentication import Authentication
from portal.systems.jwks import JWKs
from portal.systems.mailer import Mailer
from portal.systems.session_manager import SessionManager

db = SQLAlchemy(metadata=models.Base.metadata)
session_manager = SessionManager(db)
mailer = Mailer()
authentication = Authentication(mailer, db)
jwks = JWKs(db)

def init_app(app: Flask):
    db.init_app(app)
    session_manager.init_app(app)
    mailer.init_app(app)
    authentication.init_app(app)
    jwks.init_app(app)
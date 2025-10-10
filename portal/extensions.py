from flask_sqlalchemy import SQLAlchemy

from portal import models
from portal.systems.mailer import Mailer
from portal.systems.session_manager import SessionManager

db = SQLAlchemy(metadata=models.Base.metadata)
session_manager = SessionManager(db)
mailer = Mailer()
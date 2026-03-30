from typing import cast

from flask import Flask, current_app
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.local import LocalProxy

from portal import models
from portal.systems import HackspaceSystems
from portal.helpers import timedelta_to_human

db = SQLAlchemy(metadata=models.Base.metadata)
migrate = Migrate(db=db)

# All Hackspace systems assume a valid application context. This
# proxy allows a global singleton to access these when an application
# context is present.
def get_hs_systems() -> HackspaceSystems:
    return current_app.extensions["hackspace"]

hs = cast(HackspaceSystems, LocalProxy(get_hs_systems))

def init_app(app: Flask):
    db.init_app(app)
    migrate.init_app(app)
    hs = HackspaceSystems(db, app)
    app.extensions["hackspace"] = hs
    app.jinja_env.globals["hs"] = hs
    app.jinja_env.filters["timedelta_to_human"] = timedelta_to_human
from typing import cast

from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.local import LocalProxy

from portal import models
from portal.systems import HackspaceSystems

db = SQLAlchemy(metadata=models.Base.metadata)

# All Hackspace systems assume a valid application context. This
# proxy allows a global singleton to access these when an application
# context is present.
def get_hs_systems() -> HackspaceSystems:
    return current_app.extensions["hackspace"]

hs = cast(HackspaceSystems, LocalProxy(get_hs_systems))

def init_app(app: Flask):
    db.init_app(app)
    app.extensions["hackspace"] = HackspaceSystems(db, app)
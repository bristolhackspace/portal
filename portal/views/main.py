from flask import Blueprint, redirect, render_template, url_for
import sqlalchemy as sa

from portal.middleware import login_required
from portal.extensions import db, hs
from portal.models import App

bp = Blueprint("main", __name__, url_prefix="/")

bp.before_request(login_required)

@bp.route("/")
def index():
    query = sa.select(App).order_by(App.order)
    apps = db.session.execute(query).scalars()

    return render_template("main/index.html.j2", apps=apps)
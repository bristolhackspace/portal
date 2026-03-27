from flask import Blueprint, redirect, render_template, url_for
import sqlalchemy as sa

from portal.decorators import login_required
from portal.extensions import db, hs
from portal.models import App

bp = Blueprint("main", __name__, url_prefix="/")

@bp.route("/")
@login_required
def index():
    query = sa.select(App).order_by(App.order)
    apps = db.session.execute(query).scalars()

    return render_template("main/index.html.j2", apps=apps)

@bp.route("/logout")
def logout():
    hs.session_manager.logout()
    return redirect(url_for(".index"))
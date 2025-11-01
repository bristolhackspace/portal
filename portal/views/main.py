from flask import Blueprint, render_template
import sqlalchemy as sa

from portal.extensions import db, session_manager
from portal.models import App

bp = Blueprint("main", __name__, url_prefix="/")

@bp.route("/")
def index():
    query = sa.select(App).order_by(App.order)
    apps = db.session.execute(query).scalars()

    return render_template("main/index.html.j2", apps=apps)

@bp.route("/logout")
def logout():
    session_manager.logout()
    return redirect(url_for(".index"))
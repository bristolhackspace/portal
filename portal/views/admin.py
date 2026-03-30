from flask import Blueprint, redirect, render_template, url_for, flash
from functools import partial
import sqlalchemy as sa

from portal.middleware import login_required
from portal.extensions import db, hs
from portal.models import RateLimit

bp = Blueprint("admin", __name__, url_prefix="/admin")

bp.before_request(partial(login_required, {"portal:admin"}))

@bp.route("/")
def index():
    return render_template("admin/index.html.j2")

@bp.route("/rate-limits")
def rate_limits():
    query = sa.select(RateLimit)
    rate_limits = db.session.execute(query).scalars()
    return render_template("admin/rate_limits.html.j2", rate_limits=rate_limits)

@bp.route("/rate-limits/delete/<key>")
def delete_rate_limit(key):
    stmt = sa.delete(RateLimit).where(RateLimit.key==key)
    db.session.execute(stmt)
    db.session.commit()
    flash(f"Rate limit '{key}' deleted")
    return redirect(url_for('.rate_limits'))
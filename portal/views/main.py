from typing import cast

import sqlalchemy as sa
from flask import Blueprint, render_template
from ua_parser import parse as ua_parse

from portal.extensions import db, hs
from portal.middleware import login_required
from portal.models import App, Session

bp = Blueprint("main", __name__, url_prefix="/")

bp.before_request(login_required)


@bp.route("/")
def index():
    query = sa.select(App).order_by(App.order)
    apps = db.session.execute(query).scalars().all()

    # apps.append(App(
    #     name="Account Management",
    #     description="Manage account details",
    #     url=url_for("main.manage", _external=True),
    #     new_tab=False
    # ))

    return render_template("main/index.html.j2", apps=apps)


@bp.route("/manage")
def manage():
    current_session = cast(Session, hs.session_manager.current_session)

    return render_template(
        "main/account_manage.html.j2",
        current_session=current_session,
        ua_parse=ua_parse,
    )

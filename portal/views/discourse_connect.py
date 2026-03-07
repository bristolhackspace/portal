from datetime import datetime, timezone
from flask import Blueprint, redirect, url_for, request

from portal.systems.discourse_connect import DiscourseConnectError
from portal.extensions import discourse, session_manager, authentication
from portal.decorators import login_required

bp = Blueprint("discourse_connect", __name__, url_prefix="/dc")

@bp.route("/authorize")
@login_required
def authorize():
    current_session = session_manager.current_session

    try:
        return discourse.authenticate(request)
    except DiscourseConnectError as ex:
        return render_template("error.html.j2", reason=ex.args[0])
        


    

    
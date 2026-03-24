from flask import Blueprint, redirect, render_template, request

from portal.systems.discourse_connect import DiscourseConnectError
from portal.extensions import hs
from portal.decorators import login_required

bp = Blueprint("discourse_connect", __name__, url_prefix="/dc")

@bp.route("/authorize")
@login_required
def authorize():
    current_session = hs.session_manager.current_session

    try:
        redirect_url = hs.discourse_auth.authenticate(request, current_session)
        return redirect(str(redirect_url), 302)
    except DiscourseConnectError as ex:
        return render_template("error.html.j2", reason=ex.args[0])






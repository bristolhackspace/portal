from flask import Blueprint, redirect, render_template, request

from portal.systems.discourse_connect import DiscourseConnectError
from portal.extensions import hs
from portal.middleware import login_required

bp = Blueprint("discourse_connect", __name__, url_prefix="/dc")

bp.before_request(login_required)

@bp.route("/session/sso_provider")
def authorize():
    current_session = hs.session_manager.current_session

    try:
        redirect_url = hs.discourse_auth.authenticate(request, current_session)
        return redirect(str(redirect_url), 302)
    except DiscourseConnectError as ex:
        return render_template("error.html.j2", reason=ex.args[0])






from flask import Blueprint, redirect, url_for

from portal.extensions import oauth, session_manager, authentication

bp = Blueprint("oauth", __name__, url_prefix="/oauth")

@bp.route("/authorize")
def authorize():
    req = oauth.capture_request()
    acr = oauth.authenticate_request(req, session_manager)
    if acr is None:
        redirect_uri = oauth.build_redirect_url(req, "oauth.authorize")
        authentication.begin_flow(redirect_uri)
        return redirect(url_for("login.index"))

    return redirect(req.redirect_uri)
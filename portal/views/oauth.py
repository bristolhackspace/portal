from flask import Blueprint, redirect, url_for

from portal.extensions import db, jwks, oauth, session_manager, authentication
from portal.systems.oauth import OAuthError

bp = Blueprint("oauth", __name__, url_prefix="/oauth")

@bp.route("/authorize")
def authorize():
    req = oauth.capture_request()
    acr = oauth.authenticate_request(req, session_manager)
    if acr is None:
        redirect_uri = oauth.build_redirect_url(req, "oauth.authorize")
        authentication.begin_flow(redirect_uri)
        db.session.commit()
        return redirect(url_for("login.index"))
    
    resp = oauth.build_response(req, acr, jwks)

    flask_response = oauth.process_response(resp)
    db.session.commit()
    return flask_response

@bp.route("/token")
def token():
    return oauth.handle_token_request()

@bp.route(".well-known/openid-configuration")
def openid_configuration():
    return {}

@bp.errorhandler(OAuthError)
def handle_oauth_error(e):
    return oauth.handle_error(e, "oauth/error.html.j2")
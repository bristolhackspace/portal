from authlib.oauth2 import OAuth2Error
from flask import Blueprint, redirect, url_for, request

from portal.extensions import db, jwks, oauth, session_manager, authentication

bp = Blueprint("oauth", __name__, url_prefix="/oauth")

@bp.route("/authorize")
def authorize():
    current_session = session_manager.current_session

    if current_session is None:
        authentication.begin_flow(request.url)
        return redirect(url_for("login.index"))

    try:
        grant = oauth.get_consent_grant(current_session.user)
    except OAuth2Error as error:
        return oauth.handle_error_response(error)

    return oauth.create_authorization_response(grant, current_session.user)


@bp.route("/token")
def issue_token():
    return oauth.create_token_response()

@bp.route(".well-known/openid-configuration")
def openid_configuration():
    return {}
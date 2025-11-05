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


@bp.route("/token", methods=["GET", "POST"])
def issue_token():
    return oauth.create_token_response()

@bp.route(".well-known/openid-configuration")
def openid_configuration():
    def external_url(endpoint: str):
        return url_for(endpoint, _external=True)

    return {
        "authorization_endpoint": external_url('.authorize'),
        "token_endpoint": external_url('.issue_token'),
        # "userinfo_endpoint": external_url('.userinfo_endpoint'),
        "jwks_uri": external_url('.certs'),
        "id_token_signing_alg_values_supported": [
            "HS256",
            "RS256"
        ],
        "issuer": oauth.issuer,
        "response_types_supported": [
            "code",
            # TODO check what it takes to support these too
            # "id_token",
            # "id_token token",
            # "code token",
            # "code id_token",
            # "code id_token token"
        ],
        "subject_types_supported": [
            "public"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic"
        ],
    }

@bp.route("certs")
def certs():
    return jwks.get_key_set().as_dict()
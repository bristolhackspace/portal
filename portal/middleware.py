from datetime import datetime, timezone
from flask import redirect, request, url_for, current_app
import secrets
from werkzeug import Response
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.exceptions import Unauthorized, Forbidden

from portal.extensions import hs

# Below are functions which can be used with the various Flask `before_request` hooks.

def login_required(claims:set[str]|list[str]|None=None) -> Response | None:
    current_session = hs.session_manager.current_session
    try:
            max_age = int(request.values.get("max_age", ""))
    except ValueError:
        max_age = None

    now = datetime.now(timezone.utc)

    if current_session is None or (max_age is not None and (now - current_session.last_auth).total_seconds() > max_age):
        flow = hs.authentication.begin_flow(request.url)
        return redirect(url_for("login.index", flow_id=flow.id.hex))

    if claims is None:
        claims = set()
    if not isinstance(claims, set):
        claims = set(claims)

    if not claims.issubset(current_session.member.claims):
        raise Forbidden()


def token_required() -> Response | None:
    api_secret = current_app.config["API_SECRET"]
    authorization = request.headers.get("Authorization", "")

    bearer = authorization.removeprefix("Bearer ")
    if bearer == authorization or not secrets.compare_digest(bearer, api_secret):
        raise Unauthorized(www_authenticate=WWWAuthenticate("bearer"))
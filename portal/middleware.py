from datetime import datetime, timezone
from flask import redirect, request, url_for
from werkzeug import Response

from portal.extensions import hs

# Below are functions which can be used with the various Flask `before_request` hooks.

def login_required() -> Response | None:
    current_session = hs.session_manager.current_session
    try:
            max_age = int(request.values.get("max_age", ""))
    except ValueError:
        max_age = None

    now = datetime.now(timezone.utc)

    if current_session is None or (max_age is not None and (now - current_session.last_auth).total_seconds() > max_age):
        flow = hs.authentication.begin_flow(request.url)
        return redirect(url_for("login.index", flow_id=flow.id.hex))


def token_required() -> Response | None:
    return
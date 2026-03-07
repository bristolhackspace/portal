from datetime import datetime, timezone
from flask import request, url_for
import functools

from portal.extensions import session_manager, authentication

def login_required(f):
    @functools.wraps(f)
    def wrapper_fn(*args, **kwargs):
        current_session = session_manager.current_session

        try:
            max_age = int(request.values.get("max_age", ""))
        except ValueError:
            max_age = None

        now = datetime.now(timezone.utc)

        if current_session is None or (max_age is not None and (now - current_session.last_auth).total_seconds() > max_age):
            authentication.begin_flow(request.url)
            return redirect(url_for("login.index"))
        return f(*args, **kwargs)
    return wrapper_fn
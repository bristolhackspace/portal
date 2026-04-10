from datetime import datetime, timezone
from flask import redirect, request, url_for
import functools

from portal.extensions import hs

def login_required(f):
    @functools.wraps(f)
    def wrapper_fn(*args, **kwargs):
        current_session = hs.session_manager.current_session

        try:
            max_age = int(request.values.get("max_age", ""))
        except ValueError:
            max_age = None

        now = datetime.now(timezone.utc)

        if current_session is None or (max_age is not None and (now - current_session.last_auth).total_seconds() > max_age):
            hs.authentication.begin_flow(request.url)
            return redirect(url_for("login.index"))
        return f(*args, **kwargs)
    return wrapper_fn

def token_required(f):
    @functools.wraps(f)
    def wrapper_fn(*args, **kwargs):
        return
    return wrapper_fn
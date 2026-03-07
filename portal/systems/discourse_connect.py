import base64
from flask import Flask, Request, redirect
import hashlib
import hmac
from urllib.parse import urlencode, parse_qs
from yarl import URL

class DiscourseConnectError(Exception):
    pass

class _State:
    def __init__(self, app: Flask):
        self.secret = app.config["DISCOURSE_CONNECT_SECRET"].encode("utf-8")

class DiscourseConnect:
    def __init__(self, session: SessionManager, app: Flask | None = None):
        self.session = session
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.discourse"] = _State(app)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.discourse"]
        return state

    def authenticate(self, request: Request) -> Response:
        # Extract sig and sso from request args
        sso = request.args.get("sso")
        sig = request.args.get("sig")

        secret = self._state.secret

        # Check the signature is valid
        digest = hmac.new(secret, sso, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sigest, sig):
            raise DiscourseConnectError("Invalid payload")

        # Extract arguments from sso
        qs = base64.b64decode(sso).decode("utf-8")
        args = parse_qs(qs)
        nonce = args["nonce"]
        return_sso_url = args["return_sso_url"]

        # Get current session details
        current_session = self.session.current_session
        user = current_session.user

        # Build response payload
        response_qs = urlencode({
            "nonce": nonce,
            "email": user.email,
            "external_id": user.get_sub(),
            "name": user.name,
        })

        # Encode and sign response
        response_encoded = base64.b64encode(response_qs.encode("utf-8"))
        response_digest = hmac.new(secret, response_encoded, hashlib.sha256).hexdigest()

        # Build redirect URL
        remote_url = URL(return_sso_url).with_query(
            {
                "sso": response_encoded.decode("utf-8"),
                "sig": response_digest,
            }
        )

        # Do the redirect
        return redirect(str(remote_url), 302)

        


        

        

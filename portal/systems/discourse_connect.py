import base64
from typing import cast
from flask import Flask, Request, redirect
import hashlib
import hmac
from urllib.parse import urlencode, parse_qs
from werkzeug import Response
from yarl import URL

from portal.models.user import Session
from portal.systems.session_manager import SessionManager

class DiscourseConnectError(Exception):
    pass


class DiscourseConnect:
    def __init__(self, session: SessionManager, app: Flask):
        self.session = session

        self.secret = app.config["DISCOURSE_CONNECT_SECRET"].encode("utf-8")

    def authenticate(self, request: Request) -> Response:
        # Extract sig and sso from request args
        sso = request.args.get("sso")
        sig = request.args.get("sig")

        if sso is None or sig is None:
            raise DiscourseConnectError("Invalid payload")

        secret = self.secret

        # Check the signature is valid
        digest = hmac.new(secret, sso.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(digest, sig):
            raise DiscourseConnectError("Invalid payload")

        # Extract arguments from sso
        qs = base64.b64decode(sso).decode("utf-8")
        args = parse_qs(qs)
        nonce = args["nonce"][0]
        return_sso_url = args["return_sso_url"][0]

        # Get current session details
        current_session = self.session.current_session
        if current_session is None:
            raise DiscourseConnectError("No valid session")
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








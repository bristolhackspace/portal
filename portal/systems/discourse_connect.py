import base64
import hashlib
import hmac
from typing import cast
from urllib.parse import parse_qs, urlencode

from flask import Flask, Request
from flask_sqlalchemy import SQLAlchemy
from yarl import URL

from portal.models.member import Session
from portal.systems.audit import Audit


class DiscourseConnectError(Exception):
    pass


def encode_sso(sso) -> bytes:
    query_string = urlencode(sso)
    return base64.b64encode(query_string.encode("utf-8"))


def decode_sso(sso: str) -> dict[str, list[str]]:
    qs = base64.b64decode(sso).decode("utf-8")
    return parse_qs(qs)


def compute_sig(secret: bytes, encoded_sso: bytes):
    return hmac.new(secret, encoded_sso, hashlib.sha256).hexdigest()


class DiscourseConnect:
    def __init__(self, db: SQLAlchemy, audit: Audit | None, app: Flask):
        self.db = db
        self.audit = audit
        self.secret = app.config["DISCOURSE_CONNECT_SECRET"].encode("utf-8")

    def authenticate(self, request: Request, session: Session) -> URL:
        # Extract sig and sso from request args
        sso = request.args.get("sso")
        sig = request.args.get("sig")

        if sso is None or sig is None:
            raise DiscourseConnectError("Invalid payload")

        secret = self.secret

        # Check the signature is valid
        digest = compute_sig(secret, sso.encode("utf-8"))
        if not hmac.compare_digest(digest, sig):
            raise DiscourseConnectError("Invalid payload")

        # Extract arguments from sso
        args = decode_sso(sso)
        nonce = args["nonce"][0]
        return_sso_url = URL(args["return_sso_url"][0])
        host = cast(str, return_sso_url.host)  # Return URL will always be absolute

        member = session.member
        roles = [role.name for role in member.roles]

        # Build response payload
        response = {
            "nonce": nonce,
            "email": member.email,
            "external_id": member.get_sub(),
            "name": member.display_name,
            "groups": ",".join(roles),
        }

        if member.username:
            response["username"] = member.username

        # Record client in session for logout purposes
        session.active_clients.add(host)
        self.db.session.commit()

        if self.audit:
            self.audit.log(
                "discourse_connect",
                "login",
                member,
                {"groups": roles, "destination": return_sso_url.host},
            )

        # Encode and sign response
        response_encoded = encode_sso(response)
        response_digest = compute_sig(secret, response_encoded)

        # Build redirect URL
        remote_url = return_sso_url.with_query(
            {
                "sso": response_encoded.decode("utf-8"),
                "sig": response_digest,
            }
        )

        # Do the redirect
        return remote_url

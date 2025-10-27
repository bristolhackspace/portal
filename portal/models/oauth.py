from datetime import datetime, timedelta, timezone
import secrets
from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin, list_to_scope, scope_to_list
from authlib.oidc.core import AuthorizationCodeMixin
from typing import Optional
from sqlalchemy import ForeignKey
from uuid import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from portal.helpers import hash_token
from portal.models.base import Base, PkModel, SpaceSeparatedSet, UTCDateTime
from portal.models.user import Session, User


class OAuth2Client(Base, ClientMixin):
    __tablename__ = "oauth2_client"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    name: Mapped[str]
    secret_hash: Mapped[str]
    redirect_uris: Mapped[str]
    scope: Mapped[set[str]] = mapped_column(SpaceSeparatedSet())


    def get_client_id(self):
        return self.id.hex

    def get_default_redirect_uri(self):
        return self.redirect_uris.split()[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = self.scope
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris.split()

    def check_client_secret(self, client_secret):
        secret_hash = hash_token(client_secret)
        return secrets.compare_digest(self.secret_hash, secret_hash)

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return method == "client_secret_basic"
        return True

    def check_response_type(self, response_type):
        #TODO: Configurable response types
        return response_type in {"code"}

    def check_grant_type(self, grant_type):
        return grant_type in {"authorization_code"}

class Token(PkModel, TokenMixin):
    __tablename__ = "token"

    client_id: Mapped[UUID] = mapped_column(ForeignKey("oauth2_client.id"))
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"))
    token_type: Mapped[str]
    access_token: Mapped[str] = mapped_column(unique=True)
    refresh_token: Mapped[Optional[str]] = mapped_column(index=True)
    scope: Mapped[str] = mapped_column(default="")
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime())
    access_token_revoked_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    refresh_token_revoked_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    expires_in: Mapped[int] = mapped_column(default=0)

    user: Mapped[Optional["User"]] = relationship()
    client: Mapped["OAuth2Client"] = relationship()

    def check_client(self, client) -> bool:
        return self.client == client

    def get_scope(self) -> str:
        return self.scope

    def get_expires_in(self) -> int:
        return self.expires_in

    def is_expired(self) -> bool:
        if not self.expires_in:
            return False

        expires_at = self.issued_at + timedelta(seconds=self.expires_in)
        return expires_at < datetime.now(timezone.utc)

    def is_revoked(self) -> bool:
        return bool(self.access_token_revoked_at or self.refresh_token_revoked_at)

    def get_user(self) -> User:
        return self.user

    def get_client(self) -> ClientMixin:
        return self.client


class AuthorizationCode(PkModel, AuthorizationCodeMixin):
    __tablename__ = "authorization_code"

    user_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"))

    code: Mapped[str] = mapped_column(unique=True)
    client_id: Mapped[UUID] = mapped_column(ForeignKey("oauth2_client.id"))
    redirect_uri: Mapped[str]
    response_type: Mapped[str] = mapped_column(default="")
    scope: Mapped[str]
    nonce: Mapped[Optional[str]]
    auth_time: Mapped[datetime] = mapped_column(UTCDateTime())
    acr: Mapped[Optional[str]]
    amr: Mapped[Optional[str]]

    code_challenge: Mapped[Optional[str]]
    code_challenge_method: Mapped[Optional[str]]

    user: Mapped["User"] = relationship()
    client: Mapped["OAuth2Client"] = relationship()

    def is_expired(self):
        return self.auth_time + timedelta(seconds=300) < datetime.now(timezone.utc)

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time.timestamp()

    def get_acr(self):
        return self.acr

    def get_amr(self):
        return self.amr.split() if self.amr else []

    def get_nonce(self):
        return self.nonce


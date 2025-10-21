from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key as generate_ec_private_key,
    SECP256R1,
    SECP384R1,
    SECP521R1
)
from datetime import datetime, timezone
import functools
from jwt import PyJWK
from jwt.algorithms import HMACAlgorithm, RSAAlgorithm, ECAlgorithm
import secrets
from typing import Any, Optional
import uuid
from zoneinfo import ZoneInfo
from flask import current_app
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func, expression
from sqlalchemy import JSON, Column, ForeignKey, Table, types
from uuid import UUID


Base = declarative_base()


@functools.cache
def local_timezone():
    zone = current_app.config.get("TIMEZONE", "Europe/London")
    return ZoneInfo(zone)


class UTCDateTime(types.TypeDecorator):

    impl = types.DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime, engine):
        if value is None:
            return
        if value.tzinfo is None:
            raise ValueError("Datetime must be timezone aware")

        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime, engine):
        if value is not None:
            return value.replace(tzinfo=timezone.utc)


class LocalDateTime(types.TypeDecorator):

    impl = types.DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime, engine):
        if value is None:
            return
        if value.tzinfo is None:
            zone = local_timezone()
            value = value.replace(tzinfo=zone)

        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime, engine):
        if value is not None:
            zone = local_timezone()
            return value.replace(tzinfo=timezone.utc).astimezone(zone)


class SpaceSeparatedSet(types.TypeDecorator):

    impl = types.String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value:
            return " ".join(value)
        else:
            return ""

    def process_result_value(self, value, dialect):
        if value:
            return set(value.split())
        else:
            return set()


class PkModel(Base):
    """Base model with a primary key column named ``id``."""

    __abstract__ = True

    id: Mapped[int] = mapped_column(primary_key=True, sort_order=-1)

user_role_association = Table(
    "user_role",
    Base.metadata,
    Column("user_id", ForeignKey("user.id"), primary_key=True),
    Column("role_id", ForeignKey("role.id"), primary_key=True),
)

class User(PkModel):
    __tablename__ = "user"

    display_name: Mapped[Optional[str]]
    email: Mapped[Optional[str]]
    totp_secret: Mapped[Optional[str]]

    sessions: Mapped[list["Session"]] = relationship(back_populates="user")
    roles: Mapped[list["Role"]] = relationship("Role", secondary=user_role_association)


class Session(Base):
    __tablename__ = "session"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    secret_hash: Mapped[str]
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    created: Mapped[datetime] = mapped_column(UTCDateTime())
    last_active: Mapped[datetime] = mapped_column(UTCDateTime())
    last_email_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_keyfob_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_totp_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_passkey_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())

    user: Mapped[User] = relationship(back_populates="sessions")


class AuthFlow(Base):
    __tablename__ = "auth_flow"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    flow_token_hash: Mapped[str]
    email_token_hash: Mapped[Optional[str]]
    # A code the user can visually check matches the one in the email
    visual_code: Mapped[Optional[str]]

    expiry: Mapped[datetime] = mapped_column(UTCDateTime())
    email_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    totp_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    redirect_uri: Mapped[Optional[str]]

    user: Mapped[Optional["User"]] = relationship()


class OAuthClient(Base):
    __tablename__ = "oauth_client"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    name: Mapped[str]


class Role(PkModel):
    __tablename__ = "role"

    name: Mapped[str]

    claim_sets: Mapped[list["ClaimSet"]] = relationship(back_populates="role")

class ClaimSet(PkModel):
    __tablename__ = "claim_set"

    role_id: Mapped[int] = mapped_column(
        ForeignKey("role.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    oauth_client_id: Mapped[int] = mapped_column(
        ForeignKey("oauth_client.id", onupdate="CASCADE", ondelete="CASCADE")
    )

    role: Mapped["Role"] = relationship(back_populates="claim_sets")
    oauth_client: Mapped["OAuthClient"] = relationship()


class JWK(Base):
    __tablename__ = "jwk"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    kty: Mapped[str]
    alg: Mapped[str] = mapped_column(server_default="")
    public_params: Mapped[dict[str, Any]] = mapped_column(JSON, server_default='{}')
    private_params: Mapped[dict[str, Any]] = mapped_column(JSON, server_default='{}')
    key_set: Mapped[str] = mapped_column(server_default="")
    created: Mapped[datetime] = mapped_column(UTCDateTime)


    @classmethod
    def new_from_alg(cls, alg: str) -> "JWK":
        if alg in ["HS256", "HS384", "HS512"]:
            return cls._new_hmac_key(alg)
        elif alg in ["RS256", "RS384", "RS512"]:
            return cls._new_rsa_key(alg)
        elif alg in ["ES256", "ES384", "ES512"]:
            return cls._new_ec_key(alg)
        else:
            raise ValueError("Unknown algorithm")

    @classmethod
    def _new_hmac_key(cls, alg: str) -> "JWK":
        key_size = int(alg[2:])//8
        k = secrets.token_bytes(key_size)
        jwk = HMACAlgorithm.to_jwk(k, as_dict=True)

        kty = jwk.pop("kty")

        return cls(
            id=uuid.uuid4(),
            kty=kty,
            alg=alg,
            private_params=jwk,
            created=datetime.now(tz=timezone.utc),
        )
    
    @classmethod
    def _new_rsa_key(cls, alg: str) -> "JWK":
        key = generate_rsa_private_key(65537, 2048)
        private_params = RSAAlgorithm.to_jwk(key, as_dict=True)

        public_params = {
            "n": private_params.pop("n"),
            "e": private_params.pop("e"),
            "key_ops": ["verify"]
        }
        kty = private_params.pop("kty")

        return cls(
            id=uuid.uuid4(),
            kty=kty,
            alg=alg,
            public_params=public_params,
            private_params=private_params,
            created=datetime.now(tz=timezone.utc),
        )
    
    @classmethod
    def _new_ec_key(cls, alg: str) -> "JWK":
        curve = {
            "ES256": SECP256R1,
            "ES384": SECP384R1,
            "ES512": SECP521R1
        }[alg]

        key = generate_ec_private_key(curve())
        public_params = ECAlgorithm.to_jwk(key, as_dict=True)
        private_params = {
            "d": public_params.pop("d")
        }
        kty = public_params.pop("kty")

        return cls(
            id=uuid.uuid4(),
            kty=kty,
            alg=alg,
            public_params=public_params,
            private_params=private_params,
            created=datetime.now(tz=timezone.utc),
        )
    
    def to_jwk_data(self, private: bool=False) -> dict[str, Any]:
        params = {
            "kid": self.id.hex,
            "alg": self.alg,
            "kty": self.kty
        }
        if self.public_params:
            params.update(self.public_params)
        if private:
            params.update(self.private_params)
        return params
    
    def to_pyjwk(self, private: bool=False) -> PyJWK:
        params = self.to_jwk_data(private)
        return PyJWK(params)
    
class OAuthRequest(Base):
    __tablename__ = "oauth_request"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    token_hash: Mapped[str]
    session_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("session.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("oauth_client.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    response_type: Mapped[set[str]] = mapped_column(SpaceSeparatedSet())
    scope: Mapped[set[str]] = mapped_column(SpaceSeparatedSet())
    state: Mapped[Optional[str]]
    redirect_uri: Mapped[str]
    nonce: Mapped[Optional[str]]
    acr_values: Mapped[Optional[str]]


    session: Mapped[Optional["Session"]] = relationship()
    client: Mapped["OAuthClient"] = relationship()

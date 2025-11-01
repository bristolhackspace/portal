import typing
from portal.models.base import Base, UTCDateTime

from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column
from authlib.jose import Key, JsonWebKey, OctKey, RSAKey

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any


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
        key_size = int(alg[2:])
        kid = uuid.uuid4()
        key: OctKey = JsonWebKey.generate_key("oct", key_size, is_private=True, options=dict(kid=kid.hex))

        return cls._save_key(alg, key)

    @classmethod
    def _new_rsa_key(cls, alg: str) -> "JWK":
        kid = uuid.uuid4()
        key: RSAKey = JsonWebKey.generate_key("RSA", 2048, is_private=True, options=dict(kid=kid.hex))

        return cls._save_key(alg, key)

    @classmethod
    def _new_ec_key(cls, alg: str) -> "JWK":
        curve = {
            "ES256": "P-256",
            "ES384": "P-384",
            "ES512": "P-521"
        }[alg]

        kid = uuid.uuid4()
        key: RSAKey = JsonWebKey.generate_key("EC", curve, is_private=True, options=dict(kid=kid.hex))

        return cls._save_key(alg, key)

    @classmethod
    def _save_key(cls, alg: str, key: Key):
        public_params = typing.cast(dict[str, Any], key.as_dict())
        private_params = typing.cast(dict[str, Any], key.as_dict(is_private=True))

        kty = private_params.pop("kty")
        kid = uuid.UUID(hex=private_params.pop("kid"))

        public_params.pop("kty")
        public_params.pop("kid")

        return cls(
            id=kid,
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

        if private:
            params.update(self.private_params)
        else:
            params.update(self.public_params)
        return params

    def to_key(self, private: bool=False) -> Key:
        params = self.to_jwk_data(private)
        return JsonWebKey.import_key(params)
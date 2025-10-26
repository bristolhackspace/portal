from portal.models.base import Base, UTCDateTime


from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1, generate_private_key as generate_ec_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key
from jwt import PyJWK
from jwt.algorithms import ECAlgorithm, HMACAlgorithm, RSAAlgorithm
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column


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
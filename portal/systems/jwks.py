

from datetime import datetime, timedelta, timezone
from typing import Any
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from jwt import PyJWK
import sqlalchemy as sa

from portal.models import JWK


class _State:
    def __init__(self, app: Flask):
        self.keys_to_keep = app.config.get("JWKS_KEYS_TO_KEEP", 3)
        self.refresh_interval = self.as_timedelta(app.config.get("JWKS_REFRESH_INTERVAL", timedelta(days=30)))
        self.signing_alg = app.config.get("JWKS_SIGNING_ALG", "RS256")

    @staticmethod
    def as_timedelta(value: int | float | timedelta) -> timedelta:
        if not isinstance(value, timedelta):
            value = timedelta(seconds=value)
        return value

class JWKs:
    def __init__(
        self,
        db: SQLAlchemy,
        app: Flask | None = None,
    ):
        self.db = db

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.jwks"] = _State(app)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.jwks"]
        return state
    
    def _create_new_key(self) -> JWK:
        jwk = JWK.new_from_alg(self._state.signing_alg)
        self.db.session.add(jwk)
        return jwk
    
    def get_signing_key(self) -> PyJWK:
        query = sa.select(JWK).order_by(JWK.created.desc()).limit(1)
        return self.db.session.execute(query).scalar_one().to_pyjwk(private=True)
    
    def get_jwks_json(self) -> dict[str, Any]:
        query = sa.select(JWK).order_by(JWK.created.desc())
        keys = list(self.db.session.execute(query).scalars())

        result = {"keys": []}

        for key in keys:
            result["keys"].append(key.to_jwk_data())
        return result

    def rotate_keys(self):
        query = sa.select(JWK).order_by(JWK.created.desc())
        keys = list(self.db.session.execute(query).scalars())

        now = datetime.now(timezone.utc)

        if len(keys) == 0 or keys[0].created < now - self._state.refresh_interval:
            keys.insert(0, self._create_new_key())

        keys_to_delete = keys[self._state.keys_to_keep:]
        for key in keys_to_delete:
            self.db.session.delete(key)
        
        self.db.session.commit()


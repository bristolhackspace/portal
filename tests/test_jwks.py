from datetime import datetime, timedelta, timezone
from flask import Flask
from jwt import PyJWK
import pytest
import secrets
import sqlalchemy as sa

from portal.extensions import db, jwks
from portal.models import JWK

@pytest.fixture()
def init_jwks(app, init_db):
    jwks.init_app(app)

@pytest.fixture()
def jwk(init_jwks, app_context) -> JWK:
    return jwks._create_new_key()

@pytest.fixture()
def keyset(init_jwks, app_context) -> list[JWK]:
    keys_to_keep = jwks._state.keys_to_keep
    refresh_interval = jwks._state.refresh_interval
    signing_alg = jwks._state.signing_alg

    epsilon = timedelta(seconds=2)
    now = datetime.now(timezone.utc) - epsilon

    keyset = []

    for i in range(1, keys_to_keep+1):
        jwk = JWK.new_from_alg(signing_alg)
        jwk.created = now - (refresh_interval * i)
        db.session.add(jwk)
        keyset.append(jwk)
    db.session.commit()
    return keyset

def assert_sign_verify(public_jwk: PyJWK, private_jwk: PyJWK):
    message = secrets.token_bytes()
    signature = private_jwk.Algorithm.sign(message, private_jwk.key)
    assert public_jwk.Algorithm.verify(message, public_jwk.key, signature) == True

def test_get_signing_key(app: Flask, jwk: JWK):
    signing_key = jwks.get_signing_key()

    assert_sign_verify(jwk.to_pyjwk(), signing_key)

def test_rotate_keys(app: Flask, keyset: list[JWK]):
    signing_alg = jwks._state.signing_alg
    initial_jwks = keyset

    jwks.rotate_keys()

    query = sa.select(JWK).order_by(JWK.created.desc())
    new_jwks = list(db.session.execute(query).scalars())

    assert new_jwks[1:] == initial_jwks[:-1]

    epsilon = timedelta(seconds=10)
    now = datetime.now(timezone.utc)

    assert new_jwks[0].created > now - epsilon
    assert new_jwks[0].alg == signing_alg


def test_get_jwks_json(app: Flask, keyset: list[JWK]):
    signing_alg = jwks._state.signing_alg

    key_json = jwks.get_jwks_json()

    keyset_ids = {k.id.hex for k in keyset}

    assert {k["kid"] for k in key_json["keys"]} == keyset_ids
    for k in key_json["keys"]:
        assert k["alg"] == signing_alg


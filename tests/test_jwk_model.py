from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask
from jwt import PyJWK
import pytest
import secrets

from portal.extensions import db
from portal.models import JWK

def assert_sign_verify(public_jwk: PyJWK, private_jwk: PyJWK):
    message = secrets.token_bytes()
    signature = private_jwk.Algorithm.sign(message, private_jwk.key)
    assert public_jwk.Algorithm.verify(message, public_jwk.key, signature) == True


RSA_ALGS = ["RS256", "RS384", "RS512"]
EC_ALGS = ["ES256", "ES384", "ES512"]
HMAC_ALGS = ["HS256", "HS384", "HS512"]
SYMMETRIC_ALGS = HMAC_ALGS
ASYMMETRIC_ALGS = RSA_ALGS + EC_ALGS
ALL_ALGS = SYMMETRIC_ALGS + ASYMMETRIC_ALGS

@pytest.mark.parametrize("alg", ALL_ALGS)
def test_new_from_alg(app: Flask, init_db, alg):
    jwk = JWK.new_from_alg(alg)
    private_jwk = jwk.to_pyjwk(private=True)

    if alg in SYMMETRIC_ALGS:
        public_jwk = private_jwk
    else:
        public_jwk = jwk.to_pyjwk()

    assert_sign_verify(public_jwk, private_jwk)

@pytest.mark.parametrize("alg", ALL_ALGS)
def test_save_load(app: Flask, init_db, app_context, alg):
    saved_jwk = JWK.new_from_alg(alg)
    db.session.add(saved_jwk)
    db.session.commit()

    saved_private_jwk = saved_jwk.to_pyjwk(private=True)
    if alg in SYMMETRIC_ALGS:
        saved_public_jwk = saved_private_jwk
    else:
        saved_public_jwk = saved_jwk.to_pyjwk()

    loaded_jwk = db.session.get_one(JWK, saved_jwk.id)

    loaded_private_jwk = loaded_jwk.to_pyjwk(private=True)
    if alg in SYMMETRIC_ALGS:
        loaded_public_jwk = loaded_private_jwk
    else:
        loaded_public_jwk = loaded_jwk.to_pyjwk()

    assert_sign_verify(saved_public_jwk, saved_private_jwk)
    assert_sign_verify(loaded_public_jwk, saved_private_jwk)
    assert_sign_verify(saved_public_jwk, loaded_private_jwk)
    assert_sign_verify(loaded_public_jwk, loaded_private_jwk)

import hashlib


def hash_token(secret: str | bytes) -> str:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha256(secret).hexdigest()
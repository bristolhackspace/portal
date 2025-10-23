import hashlib
import secrets
from typing import Literal, overload


def hash_token(secret: str | bytes) -> str:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).hexdigest()

@overload
def build_secure_uri(obj: object, attribute: str="token_hash", as_tuple: Literal[False]=False) -> str: ...

@overload
def build_secure_uri(obj: object, attribute: str="token_hash", as_tuple: Literal[True]=True) -> tuple[str,str]: ...

def build_secure_uri(obj: object, attribute: str="token_hash", as_tuple: bool=False) -> str|tuple[str,str]
    obj_id = obj.id.hex # type: ignore
    token = secrets.token_urlsafe()
    setattr(obj, attribute, hash_token(token))
    if as_tuple:
        return (obj_id, token)
    else:
        return f"{obj_id}:{token}"
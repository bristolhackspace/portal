import hashlib
import secrets
from typing import Literal, Type, TypeVar, Union, overload
import uuid

from flask_sqlalchemy import SQLAlchemy


def hash_token(secret: str | bytes) -> str:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).hexdigest()

@overload
def build_secure_uri(obj: object, attribute: str="token_hash", as_tuple: Literal[False]=False) -> str: ...

@overload
def build_secure_uri(obj: object, attribute: str="token_hash", as_tuple: Literal[True]=True) -> tuple[str,str]: ...

def build_secure_uri(obj: object, attribute: str="token_hash", as_tuple: bool=False) -> str|tuple[str,str]:
    obj_id = obj.id.hex # type: ignore
    token = secrets.token_urlsafe()
    setattr(obj, attribute, hash_token(token))
    if as_tuple:
        return (obj_id, token)
    else:
        return f"{obj_id}:{token}"

_O = TypeVar("_O", bound=object)

def get_from_secure_uri(db: SQLAlchemy, cls: Type[_O], uri: str, attribute: str="token_hash") -> _O|None:
    parts = uri.split(":")
    if len(parts) != 2:
        return None
    id_, token = parts
    instance = db.session.get(cls, uuid.UUID(hex=id_))
    if instance is None:
        return None
    if not secrets.compare_digest(hash_token(token), getattr(instance, attribute)):
        return None

    return instance
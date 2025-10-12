from datetime import datetime, timezone
import functools
from typing import Optional
from zoneinfo import ZoneInfo
from flask import current_app
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func, expression
from sqlalchemy import ForeignKey, types
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

        return value.astimezone(timezone.utc).replace(
            tzinfo=None
        )

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

        return value.astimezone(timezone.utc).replace(
            tzinfo=None
        )

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


class User(PkModel):
    __tablename__ = 'user'

    display_name: Mapped[Optional[str]]
    email: Mapped[Optional[str]]
    totp_secret: Mapped[Optional[str]]

    sessions: Mapped[list['Session']] = relationship(back_populates='user')


class Session(Base):
    __tablename__ = 'session'

    id: Mapped[UUID] = mapped_column(primary_key=True)
    secret_hash: Mapped[str]
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    created: Mapped[datetime] = mapped_column(UTCDateTime())
    last_active: Mapped[datetime] = mapped_column(UTCDateTime())
    last_email_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_keyfob_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_totp_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_passkey_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())

    user: Mapped[User] = relationship(back_populates='sessions')

class AuthFlow(Base):
    __tablename__ = 'auth_flow'

    id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id", onupdate="CASCADE", ondelete="CASCADE"))
    flow_token_hash: Mapped[str]
    email_token_hash: Mapped[str]
    visual_code: Mapped[str] # A code the user can visually check matches the one in the email

    expiry: Mapped[datetime] = mapped_column(UTCDateTime())
    email_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    totp_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())

    user: Mapped[Optional["User"]] = relationship()
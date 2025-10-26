from datetime import datetime, timezone
import functools
from flask import current_app
from zoneinfo import ZoneInfo
from sqlalchemy import types
from sqlalchemy.orm import Mapped, declarative_base, mapped_column


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
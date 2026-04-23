from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, IPv6Network, ip_address
from typing import cast

import sqlalchemy as sa
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import insert

from portal.models.rate_limit import RateLimit
from portal.systems.cleanup import Cleanup


class RateLimitError(Exception):
    def __init__(self, expiry: datetime):
        self.expiry = expiry
        super().__init__()


class RateLimiter:
    def __init__(self, db: SQLAlchemy, cleanup: Cleanup | None, app: Flask):
        self.db = db
        self.cleanup = cleanup

        if self.cleanup:
            self.cleanup.register_callback("rate_limits", self.cleanup_rate_limits)

    def rate_limit(
        self, key: str, limit: int, duration: timedelta | int, commit: bool = True
    ):
        now = datetime.now(timezone.utc)
        if not isinstance(duration, timedelta):
            duration = timedelta(seconds=duration)
        expiry = now + duration

        # Delete any expired rate limits first
        self.db.session.execute(
            sa.delete(RateLimit).where(
                sa.and_(RateLimit.key == key, RateLimit.expiry < now)
            )
        )

        stmt = insert(RateLimit).values(key=key, limit=limit, count=1, expiry=expiry)

        stmt = stmt.on_conflict_do_update(
            index_elements=[RateLimit.key], set_=dict(count=RateLimit.count + 1)
        ).returning(RateLimit)

        result = cast(RateLimit, self.db.session.scalars(stmt).first())

        if commit:
            self.db.session.commit()

        if result.count > result.limit:
            raise RateLimitError(result.expiry)

    def reset_rate_limit(self, key: str, commit: bool = True):
        query = sa.delete(RateLimit).where(RateLimit.key == key)
        self.db.session.execute(query)
        if commit:
            self.db.session.commit()

    def normalise_ip(self, ip: str | IPv4Address | IPv6Address) -> str:
        if isinstance(ip, str):
            ip = ip_address(ip)

        if isinstance(ip, IPv4Address):
            return str(ip)
        else:
            # Strip out the lower 64 bits as these are usually randomized
            ip = IPv6Network((ip, 64), False).network_address
            return str(ip)

    def cleanup_rate_limits(self) -> int:
        now = datetime.now(timezone.utc)
        query = sa.delete(RateLimit).where(RateLimit.expiry < now)
        result = self.db.session.execute(query)
        return result.rowcount  # pyright: ignore[reportAttributeAccessIssue]

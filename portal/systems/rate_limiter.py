from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from ipaddress import IPv4Address, IPv6Address, ip_address, IPv6Network
import sqlalchemy as sa

from portal.models.rate_limit import RateLimit

class RateLimitError:
    pass

class RateLimiter:
    def __init__(self, db: SQLAlchemy, app: Flask | None = None):
        self.db = db
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        pass

    def rate_limit(self, key: str, limit: int, duration: timedelta|int, commit:bool=True):
        now = datetime.now(timezone.utc)
        if not isinstance(duration, timedelta):
            duration = timedelta(seconds=duration)
        expiry = now + duration

        # Delete any expired rate limits first
        self.db.session.execute(delete(RateLimit).where(and_(
            RateLimit.key==key,
            RateLimit.expiry < now
        )))

        stmt = insert(RateLimit).values(
            key=key,
            limit=limit,
            count=1,
            expiry=expiry
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[RateLimit.key],
            set_=dict(
                count=RateLimit.count+1
            )
        ).returning(RateLimit)

        result = db.session.scalars(stmt).first()

        if commit:
            self.db.session.commit()

        if result.count > result.limit:
            raise RateLimitError()

    def reset_rate_limit(self, key: str, commit: bool=True):
        query = sa.delete(RateLimit).where(RateLimit.key==key)
        self.db.session.execute(query)
        if commit:
            self.db.session.commit()

            
    def normalise_ip(self, ip: str|IPv4Address|IPv6Address) -> str:
        if isinstance(ip, str):
            ip = ip_address(ip)

        if isinstance(ip, IPv4Address):
            return str(ip)
        else:
            # Strip out the lower 64 bits as these are usually randomized
            ip = IPv6Network((ip, 64), False).network_address
            return str(ip)


        

        

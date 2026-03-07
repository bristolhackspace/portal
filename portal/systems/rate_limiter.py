from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy

from portal.models.rate_limit import RateLimit

class RateLimiter:
    def __init__(self, db: SQLAlchemy, app: Flask | None = None):
        self.db = db
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        pass

    def rate_limit(self, key: str, count: int, duration: timedelta|int):
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

        return result.count < result.limit
            


        

        

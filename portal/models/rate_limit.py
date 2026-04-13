from datetime import datetime, timezone

from sqlalchemy.orm import Mapped, mapped_column

from portal.models.base import PkModel, UTCDateTime


class RateLimit(PkModel):
    __tablename__ = "rate_limit"

    key: Mapped[str] = mapped_column(index=True, unique=True)
    limit: Mapped[int]
    count: Mapped[int]
    expiry: Mapped[datetime] = mapped_column(UTCDateTime())

    def expires_in(self):
        now = datetime.now(timezone.utc)
        return self.expiry - now

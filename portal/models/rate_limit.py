from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from portal.models.base import Base, PkModel, UTCDateTime
from portal.models.role import Role


class RateLimit(PkModel):
    __tablename__ = "rate_limit"

    key: Mapped[str] = mapped_column(index=True, unique=True)
    limit: Mapped[int]
    count: Mapped[int]
    expiry: Mapped[datetime] = mapped_column(UTCDateTime())

    def expires_in(self):
        now = datetime.now(timezone.utc)
        return self.expiry - now
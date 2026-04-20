from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from portal.models.base import PkModel, UTCDateTime
from portal.models.member import Member


class AuditLog(PkModel):
    __tablename__ = "audit_log"

    logged_at: Mapped[datetime] = mapped_column(UTCDateTime)
    category: Mapped[str] = mapped_column()
    event: Mapped[str] = mapped_column()
    member_id: Mapped[Optional[int]] = mapped_column(ForeignKey("member.id"))
    data: Mapped[Optional[JSON]] = mapped_column(type_=JSON)

    member: Mapped[Optional["Member"]] = relationship()

    __table_args__ = (Index("ix_logged_at", "logged_at", postgresql_using="brin"),)

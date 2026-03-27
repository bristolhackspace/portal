from enum import Enum, auto
from typing import Optional
from portal.models.base import Base, UTCDateTime
from portal.models.member import Member


from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship


from datetime import datetime
from uuid import UUID


class FlowStep(Enum):
    NOT_STARTED = auto()
    VERIFY_EMAIL = auto()
    VERIFY_TOTP = auto()
    FINISHED = auto()

class AuthFlow(Base):
    __tablename__ = "auth_flow"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    member_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("member.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    flow_token_hash: Mapped[str]
    email_otp_hash: Mapped[Optional[str]]
    email_otp_attempts: Mapped[int]

    expiry: Mapped[datetime] = mapped_column(UTCDateTime())
    email_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    totp_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    redirect_uri: Mapped[Optional[str]]

    ip_rate_limit_key: Mapped[Optional[str]]

    member: Mapped[Optional["Member"]] = relationship()

    def next_step(self):
        if not self.email_otp_hash:
            return FlowStep.NOT_STARTED
        if not self.email_verified:
            return FlowStep.VERIFY_EMAIL
        if self.member and self.member.totp_secret:
            if not self.totp_verified:
                return FlowStep.VERIFY_TOTP
        return FlowStep.FINISHED
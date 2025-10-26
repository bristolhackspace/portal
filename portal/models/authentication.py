from typing import Optional
from portal.models.base import Base, UTCDateTime
from portal.models.user import User


from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship


from datetime import datetime
from uuid import UUID


class AuthFlow(Base):
    __tablename__ = "auth_flow"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    flow_token_hash: Mapped[str]
    email_token_hash: Mapped[Optional[str]]
    # A code the user can visually check matches the one in the email
    visual_code: Mapped[Optional[str]]

    expiry: Mapped[datetime] = mapped_column(UTCDateTime())
    email_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    totp_verified: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    redirect_uri: Mapped[Optional[str]]

    user: Mapped[Optional["User"]] = relationship()
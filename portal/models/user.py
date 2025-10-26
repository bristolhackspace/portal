from datetime import datetime
from typing import Optional
from uuid import UUID
from portal.models.role import Role
from sqlalchemy.orm import Mapped, mapped_column, relationship
from portal.models.base import Base, PkModel, UTCDateTime


from sqlalchemy import Column, ForeignKey, Table


user_role_association = Table(
    "user_role",
    Base.metadata,
    Column("user_id", ForeignKey("user.id"), primary_key=True),
    Column("role_id", ForeignKey("role.id"), primary_key=True),
)


class Session(Base):
    __tablename__ = "session"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    secret_hash: Mapped[str]
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    created: Mapped[datetime] = mapped_column(UTCDateTime())
    last_active: Mapped[datetime] = mapped_column(UTCDateTime())
    last_email_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_keyfob_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_totp_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_passkey_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())

    user: Mapped["User"] = relationship(back_populates="sessions")


class User(PkModel):
    __tablename__ = "user"

    display_name: Mapped[Optional[str]]
    email: Mapped[Optional[str]]
    totp_secret: Mapped[Optional[str]]

    sessions: Mapped[list["Session"]] = relationship(back_populates="user")
    roles: Mapped[list["Role"]] = relationship("Role", secondary=user_role_association)
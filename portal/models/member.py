from datetime import datetime, timezone, date
from typing import Optional
from uuid import UUID
from portal.models.role import Role
from sqlalchemy.orm import Mapped, mapped_column, relationship
from portal.models.base import Base, PkModel, UTCDateTime, LocalDateTime


from sqlalchemy import Column, ForeignKey, Table


member_role_association = Table(
    "member_role",
    Base.metadata,
    Column("member_id", ForeignKey("member.id"), primary_key=True),
    Column("role_id", ForeignKey("role.id"), primary_key=True),
)


class Session(Base):
    __tablename__ = "session"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    secret_hash: Mapped[str]
    member_id: Mapped[int] = mapped_column(ForeignKey("member.id"))
    created: Mapped[datetime] = mapped_column(UTCDateTime())
    last_active: Mapped[datetime] = mapped_column(LocalDateTime())
    last_auth: Mapped[datetime] = mapped_column(UTCDateTime())
    last_email_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_keyfob_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_totp_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    last_passkey_auth: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())
    
    user_agent: Mapped[Optional[str]]

    member: Mapped["Member"] = relationship(back_populates="sessions")

    def calculate_amr(self) -> set[str]:
        amr = set()

        if self.last_email_auth:
            amr.add("email")
        if self.last_totp_auth:
            amr.add("otp")
        if self.last_passkey_auth:
            amr.add("hwk")
        if self.last_keyfob_auth:
            amr.add("sc")

        if len(amr) >= 2 and ("otp" in amr or "hwk" in amr):
            amr.add("mfa")

        return amr


class Member(Base):
    __tablename__ = "member"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    display_name: Mapped[Optional[str]]
    email: Mapped[str]
    username: Mapped[Optional[str]]
    totp_secret: Mapped[Optional[str]]
    updated: Mapped[Optional[datetime]] = mapped_column(UTCDateTime())

    join_date: Mapped[Optional[date]]
    leave_date: Mapped[Optional[date]]

    sessions: Mapped[list["Session"]] = relationship(back_populates="member")
    roles: Mapped[list["Role"]] = relationship("Role", secondary=member_role_association)

    def get_sub(self):
        return f"{self.id}"

    @property
    def claims(self):
        claims = set()
        for role in self.roles:
            claims.update(role.claims)
        return claims
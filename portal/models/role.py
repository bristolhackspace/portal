from portal.models.oauth import OAuthClient
from sqlalchemy import ForeignKey
from portal.models.base import PkModel


from sqlalchemy.orm import Mapped, mapped_column, relationship


class ClaimSet(PkModel):
    __tablename__ = "claim_set"

    role_id: Mapped[int] = mapped_column(
        ForeignKey("role.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    oauth_client_id: Mapped[int] = mapped_column(
        ForeignKey("oauth_client.id", onupdate="CASCADE", ondelete="CASCADE")
    )

    role: Mapped["Role"] = relationship(back_populates="claim_sets")
    oauth_client: Mapped["OAuthClient"] = relationship()


class Role(PkModel):
    __tablename__ = "role"

    name: Mapped[str]

    claim_sets: Mapped[list["ClaimSet"]] = relationship(back_populates="role")
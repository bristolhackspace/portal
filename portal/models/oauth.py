from typing import Optional
from sqlalchemy import ForeignKey
from portal.models.base import Base, SpaceSeparatedSet


from sqlalchemy.orm import Mapped, mapped_column, relationship


from uuid import UUID

from portal.models.user import Session


class OAuthClient(Base):
    __tablename__ = "oauth_client"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    name: Mapped[str]
    secret_hash: Mapped[Optional[str]]
    redirect_uris: Mapped[str]


class OAuthRequest(Base):
    __tablename__ = "oauth_request"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    token_hash: Mapped[str]
    session_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("session.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("oauth_client.id", onupdate="CASCADE", ondelete="CASCADE")
    )
    response_type: Mapped[set[str]] = mapped_column(SpaceSeparatedSet())
    response_mode: Mapped[str]
    scope: Mapped[set[str]] = mapped_column(SpaceSeparatedSet())
    state: Mapped[Optional[str]]
    redirect_uri: Mapped[str]
    nonce: Mapped[Optional[str]]
    acr_values: Mapped[Optional[str]]


    session: Mapped[Optional["Session"]] = relationship()
    client: Mapped["OAuthClient"] = relationship()


class OAuthResponse(Base):
    __tablename__ = "oauth_response"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    token_hash: Mapped[str]

    id_token: Mapped[Optional[str]]
    state: Mapped[Optional[str]]
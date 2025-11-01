from sqlalchemy.orm import Mapped, mapped_column, relationship

from portal.models.base import PkModel

class App(PkModel):
    __tablename__ = "app"

    name: Mapped[str]
    description: Mapped[str]
    url: Mapped[str]
    order: Mapped[int] = mapped_column(server_default="0")
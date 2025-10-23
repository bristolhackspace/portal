import uuid
from flask import Blueprint

from portal.extensions import db, jwks
from portal.models import OAuthClient, User

bp = Blueprint('demo', __name__, cli_group=None)


@bp.cli.command("make-demo-data")
def make_demo_data():
    db.drop_all()
    db.create_all()

    demo_client = OAuthClient(
        id=uuid.UUID(hex="aaf36b4c-5e88-409f-863d-24f12f0ec111"),
        name="Demo client"
    )
    db.session.add(demo_client)

    demo_user = User(
        display_name="Demo User",
        email="example@example.com"
    )
    db.session.add(demo_user)

    jwks.rotate_keys()

    db.session.commit()
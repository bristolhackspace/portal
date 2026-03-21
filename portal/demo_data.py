import uuid
from flask import Blueprint

from portal.extensions import db
from portal.helpers import hash_token
from portal.models import User

bp = Blueprint('demo', __name__, cli_group=None)


@bp.cli.command("make-demo-data")
def make_demo_data():
    db.drop_all()
    db.create_all()

    demo_user = User(
        display_name="Demo User",
        email="example@example.com"
    )
    db.session.add(demo_user)

    db.session.commit()
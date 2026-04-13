
from flask import Blueprint

from portal.extensions import db
from portal.models import Member

bp = Blueprint('demo', __name__, cli_group=None)


@bp.cli.command("make-demo-data")
def make_demo_data():
    db.drop_all()
    db.create_all()

    demo_member = Member(
        id=0,
        display_name="Demo Member",
        email="example@example.com"
    )
    db.session.add(demo_member)

    db.session.commit()
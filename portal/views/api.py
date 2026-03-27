
from flask import Blueprint, request
from sqlalchemy.dialects.postgresql import insert
from werkzeug.exceptions import BadRequest

from portal.middleware import token_required
from portal.extensions import db
from portal.models.member import Member


bp = Blueprint("api", __name__, url_prefix="/api/v1")

bp.before_request(token_required)

@bp.route("/members/<int:member_id>", methods=["GET", "PUT"])
def member(member_id):
    if request.method == "GET":
        member = db.get_or_404(Member, member_id)
        return {
            "display_name": member.display_name,
            "email": member.email,
        }
    else:
        fields = request.json
        if not isinstance(fields, dict):
            raise BadRequest("Invalid JSON structure")

        stmt = insert(Member).values(
            id=member_id,
            **fields
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[Member.id],
            set_=fields
        )
        db.session.execute(stmt)
        db.session.commit()
        return "OK"
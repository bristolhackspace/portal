
from flask import Blueprint, request
from sqlalchemy.dialects.postgresql import insert
from werkzeug.exceptions import BadRequest

from portal.decorators import token_required
from portal.extensions import db
from portal.models.user import User


bp = Blueprint("api", __name__, url_prefix="/api/v1")

@bp.route("/members/<int:member_id>", methods=["GET", "PUT"])
@token_required
def member(member_id):
    if request.method == "GET":
        member = db.get_or_404(User, member_id)
        return {
            "display_name": member.display_name,
            "email": member.email,
        }
    else:
        fields = request.json
        if not isinstance(fields, dict):
            raise BadRequest("Invalid JSON structure")

        stmt = insert(User).values(
            id=member_id,
            **fields
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[User.id],
            set_=fields
        )
        db.session.execute(stmt)
        db.session.commit()
        return "OK"
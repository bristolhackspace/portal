
from datetime import datetime, timezone
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
            "updated": member.updated.timestamp(),
            "email": member.email,
        }
    else:
        fields = request.json
        if not isinstance(fields, dict):
            raise BadRequest("Invalid JSON structure")

        member_fields = {}
        display_name = fields.get("display_name")
        if display_name is not None:
            member_fields["display_name"] = display_name

        updated = fields.get("updated")
        if updated is not None:
            updated = datetime.fromisoformat(updated).replace(tzinfo=timezone.utc)
            # updated = datetime.fromtimestamp(updated, timezone.utc)
            member_fields["updated"] = updated

        email = fields.get("email")
        if email is not None:
            member_fields["email"] = email

        stmt = insert(Member).values(
            id=member_id,
            **member_fields
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[Member.id],
            set_=member_fields
        )
        db.session.execute(stmt)
        db.session.commit()
        return "OK"
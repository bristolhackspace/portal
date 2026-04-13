
from datetime import date, datetime, timezone

from flask import Blueprint, request
from sqlalchemy.dialects.postgresql import insert
from werkzeug.exceptions import BadRequest

from portal.extensions import db
from portal.middleware import token_required
from portal.models.member import Member

bp = Blueprint("api", __name__, url_prefix="/api/v1")

bp.before_request(token_required)

@bp.route("/members/<int:member_id>", methods=["GET", "PUT"])
def member(member_id):
    if request.method == "GET":
        member = db.get_or_404(Member, member_id)
        return {
            "display_name": member.display_name,
            "updated": member.updated.timestamp() if member.updated else None,
            "email": member.email,
            "join_date": member.join_date.isoformat() if member.join_date else None,
            "leave_date": member.leave_date.isoformat() if member.leave_date else None,
            "username": member.username,
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

        join_date = fields.get("join_date")
        if join_date is not None:
            member_fields["join_date"] = date.fromisoformat(join_date)

        leave_date = fields.get("leave_date")
        if leave_date is not None:
            member_fields["leave_date"] = date.fromisoformat(leave_date)

        username = fields.get("username")
        if username is not None:
            member_fields["username"] = username

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
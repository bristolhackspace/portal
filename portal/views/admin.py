from functools import partial

from flask_wtf import FlaskForm
import sqlalchemy as sa
from flask import Blueprint, flash, redirect, render_template, url_for
from wtforms import EmailField, SelectMultipleField, StringField
from wtforms.validators import ReadOnly

from portal.extensions import db
from portal.middleware import login_required
from portal.models import Member, RateLimit, Role

bp = Blueprint("admin", __name__, url_prefix="/admin")

bp.before_request(partial(login_required, {"portal:admin"}))


@bp.route("/")
def index():
    return render_template("admin/index.html.j2")


@bp.route("/members")
def members():
    page = db.paginate(db.select(Member).order_by(Member.display_name))
    return render_template("admin/members.html.j2", page=page)


class MemberForm(FlaskForm):
    display_name = StringField("Display name", validators=[ReadOnly()])
    email = EmailField("Email", validators=[ReadOnly()])
    username = StringField("Username", validators=[])
    roles = SelectMultipleField("Roles", coerce=int)


@bp.route("/members/<int:member_id>", methods=["GET", "POST"])
def member(member_id: int):
    member = db.get_or_404(Member, member_id)

    form = MemberForm(
        data={
            "display_name": member.display_name,
            "email": member.email,
            "username": member.username,
            "roles": [role.id for role in member.roles],
        }
    )

    role_query = db.select(Role).order_by(Role.name)
    roles = db.session.execute(role_query).scalars().all()
    form.roles.choices = [(role.id, role.name) for role in roles]

    if form.validate_on_submit():
        member.username = form.username.data
        selected_roles = []
        for role in roles:
            if role.id in form.roles.data:
                selected_roles.append(role)
        member.roles = selected_roles
        db.session.commit()

        return redirect(url_for(".member", member_id=member.id))
    return render_template("admin/member.html.j2", member=member, form=form)


@bp.route("/rate-limits")
def rate_limits():
    page = db.paginate(db.select(RateLimit).order_by(RateLimit.id.desc()))
    return render_template("admin/rate_limits.html.j2", page=page)


@bp.route("/rate-limits/delete/<key>")
def delete_rate_limit(key):
    stmt = sa.delete(RateLimit).where(RateLimit.key == key)
    db.session.execute(stmt)
    db.session.commit()
    flash(f"Rate limit '{key}' deleted")
    return redirect(url_for(".rate_limits"))

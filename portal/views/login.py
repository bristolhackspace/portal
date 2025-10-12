
import typing
from flask import Blueprint, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from wtforms import EmailField
from wtforms.validators import DataRequired

from portal.extensions import authentication, session_manager
from portal.systems.authentication import FlowStep

bp = Blueprint("login", __name__, url_prefix="/login")

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])

@bp.route("/", methods=["GET", "POST"])
def index():
    authentication.load_flow()

    flow = authentication.current_flow

    step = authentication.try_authenticate(session_manager)

    if step == FlowStep.VERIFY_EMAIL:
        login_poll_url = url_for(".poll")
        login_redirect = url_for(".index")
        return render_template("login/pending.html.j2", flow=flow, login_poll_url=login_poll_url, login_redirect=login_redirect)
    elif step == FlowStep.FINISHED:
        return redirect(url_for("main.index"))
    else:
        form = LoginForm()
        if form.validate_on_submit():
            # Validation will ensure email is not None
            email = typing.cast(str, form.email.data)
            flow = authentication.send_magic_email(email)
            return redirect(url_for(".index"))
        return render_template("login/index.html.j2", form=form)

@bp.route("/poll", methods=["GET", "POST"])
def poll():
    authentication.load_flow()
    flow = authentication.current_flow
    if not flow:
        return {}
    if flow.email_verified:
        return {"verified": True}
    return {}

@bp.route("/email-verify", methods=["GET", "POST"])
def email_verify():
    needs_confirmation = request.method == "GET"
    if needs_confirmation:
        flow = authentication.verify_magic_link(request, commit=False)
    else:
        flow = authentication.verify_magic_link(request, commit=True)
    return render_template("login/verify.html.j2", flow=flow, needs_confirmation=needs_confirmation)
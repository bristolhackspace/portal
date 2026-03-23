
import typing
from flask import Blueprint, Response, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from wtforms import EmailField, StringField
from wtforms.validators import DataRequired

from portal.extensions import hs, db
from portal.systems.authentication import FlowStep

bp = Blueprint("login", __name__, url_prefix="/login")

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])

class OtpForm(FlaskForm):
    otp = StringField('Please enter the code sent to your email', validators=[DataRequired()])

@bp.route("/", methods=["GET", "POST"])
def index():
    hs.authentication.load_flow()

    flow = hs.authentication.current_flow

    # If someone opens a login link from another browser then instruct them
    # to manually enter the code instead
    if "flow_id" in request.args:
        if flow is None or flow.id.hex != request.args["flow_id"]:
            return render_template("login/use_code.html.j2")

    step = hs.authentication.flow_next_step()

    if step == FlowStep.FINISHED:
        auth_methods = {}
        if flow.email_verified:
            auth_methods["email"] = flow.email_verified
        if flow.totp_verified:
            auth_methods["totp"] = flow.totp_verified
        hs.session.authenticate_session(flow.member, methods=auth_methods)
        hs.authentication.delete_flow(commit=False)
        db.session.commit()

        return redirect(flow.redirect_uri or "main.index")
    elif step == FlowStep.VERIFY_EMAIL and "flow_id" in request.args:
        if hs.authentication.verify_email_otp(request.args.get("otp", "")):
            return redirect(url_for(".index"))
        return render_template("login/invalid_code.html.j2")
    elif step == FlowStep.VERIFY_EMAIL:
        form = OtpForm()
        if form.validate_on_submit() and hs.authentication.verify_email_otp(form.otp.data):
            return redirect(url_for(".index"))
        return render_template("login/otp.html.j2", flow=flow, form=form)
    elif step == FlowStep.FINISHED:
        return redirect(url_for("main.index"))
    else:
        form = LoginForm()
        if form.validate_on_submit():
            # Validation will ensure email is not None
            email = typing.cast(str, form.email.data)
            flow = hs.authentication.send_magic_email(email, "login.index")
            return redirect(url_for(".index"))
        return render_template("login/index.html.j2", form=form)
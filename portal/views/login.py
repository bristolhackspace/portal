
from datetime import datetime, timezone
import typing
from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from wtforms import EmailField, StringField, ValidationError
from wtforms.validators import DataRequired

from portal.extensions import hs, db
from portal.helpers import timedelta_to_human
from portal.models.authentication import AuthFlow, FlowStep
from portal.systems.authentication import OtpValidationError
from portal.systems.rate_limiter import RateLimitError

bp = Blueprint("login", __name__, url_prefix="/login")

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])

class OtpForm(FlaskForm):
    otp = StringField('Please enter the code sent to your email:', validators=[DataRequired()])

    def __init__(self, flow: AuthFlow, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.flow = flow

    def validate_otp(self, field):
        try:
            hs.authentication.verify_email_otp(field.data, self.flow)
        except OtpValidationError as e:
            raise ValidationError(e.args[0])

@bp.route("/", methods=["GET", "POST"])
def index():
    flow = hs.authentication.load_flow(request)

    # If someone opens a login link from another browser then instruct them
    # to manually enter the code instead
    if "otp" in request.args and flow is None:
        return render_template("login/use_code.html.j2")

    if flow is None or flow.next_step() == FlowStep.NOT_STARTED or "resend_email" in request.args:
        data = {}
        if "resend_email" in request.args and flow and flow.member:
            data["email"] = flow.member.email
        form = LoginForm(data=data)
        if form.validate_on_submit():
            # Validation will ensure email is not None
            email = typing.cast(str, form.email.data)
            try:
                flow = hs.authentication.send_magic_email(email, "login.index", flow)
                return redirect(url_for(".index", flow_id=flow.id.hex))
            except RateLimitError as e:
                now = datetime.now(timezone.utc)
                delta = e.expiry - now
                delta_human = timedelta_to_human(delta)
                if delta.total_seconds() > 60*60:
                    form.email.errors.append("Sorry, you have been rate-limited. Please contact committee if you think this was in error.") # type: ignore
                else:
                    form.email.errors.append(f"Too many emails sent recently. Please wait {delta_human} before sending another.") # type: ignore

        return render_template("login/index.html.j2", form=form)

    step = flow.next_step()

    if step == FlowStep.VERIFY_EMAIL:
        form = OtpForm(flow=flow, otp=request.args.get("otp"))
        if (form.is_submitted() or "otp" in request.args) and form.validate():
            return redirect(url_for(".index", flow_id=flow.id.hex))

        resend_email_url = None
        if form.errors:
            resend_email_url = url_for(".index", flow_id=flow.id.hex, resend_email=1)
        return render_template("login/otp.html.j2", flow=flow, form=form, resend_email_url=resend_email_url)
    elif step == FlowStep.FINISHED:
        auth_methods = {}
        if flow.email_verified:
            auth_methods["email"] = flow.email_verified
        if flow.totp_verified:
            auth_methods["totp"] = flow.totp_verified
        hs.session_manager.authenticate_session(flow.member, methods=auth_methods)
        hs.authentication.delete_flow(flow, commit=False)
        db.session.commit()

        return redirect(flow.redirect_uri or url_for("main.index"))
    else:
        raise RuntimeError("Unrecognised FlowStep")


@bp.route("/logout")
def logout():
    hs.session_manager.logout()
    return redirect(url_for("main.index"))
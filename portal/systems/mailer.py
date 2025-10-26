from abc import ABC, abstractmethod
from dataclasses import dataclass
import smtplib, ssl
from email.utils import formataddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

from flask import Flask, current_app, render_template
from jinja2 import TemplateNotFound

from portal.models import User


class _BaseMailer(ABC):
    def send_email(self, user: User, template: str, subject: str, **kwargs):
        sender_email = current_app.config["SENDER_EMAIL"]

        plain_content = render_template(f"{template}.txt.j2", user=user, **kwargs)
        try:
            html_content = render_template(f"{template}.html.j2", user=user, **kwargs)
        except TemplateNotFound:
            html_content = None

        receiver_email = formataddr((user.display_name, user.email))
        self.raw_send_email(
            sender_email, receiver_email, plain_content, html_content, subject
        )

    @abstractmethod
    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ): ...


class _SmtpMailer(_BaseMailer):
    def __init__(self, app: Flask):
        self.port = app.config.get("SMTP_PORT", 465)
        self.host = app.config["SMTP_HOST"]
        self.username = app.config["SMTP_USERNAME"]
        self.password = app.config["SMTP_PASSWORD"]
        self.extra_headers: dict[str, str] = app.config.get("SMTP_HEADERS", {})

    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        with smtplib.SMTP(self.host, self.port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(self.username, self.password)

            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = sender
            message["To"] = receiver

            for k, v in self.extra_headers.items():
                message[k] = v

            message.attach(MIMEText(text, "plain"))

            if html:
                message.attach(MIMEText(html, "html"))

            server.sendmail(sender, receiver, message.as_string())


class _TestMailer(_BaseMailer):
    @dataclass
    class EmailCapture:
        user: User
        template: str
        subject: str
        kwargs: dict[str, Any]

    def __init__(self, app: Flask):
        self.captured_emails: list[_TestMailer.EmailCapture] = []

    def send_email(self, user: User, template: str, subject: str, **kwargs):
        self.captured_emails.append(
            self.EmailCapture(
                user=user, template=template, subject=subject, kwargs=kwargs
            )
        )

    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ):
        pass


class _LoggingMailer(_BaseMailer):
    def __init__(self, app: Flask):
        pass

    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ):
        current_app.logger.info(
            f"Sending email from {sender} to {receiver}: {subject} \n\n {text}"
        )


class Mailer:
    def __init__(self, app: Flask | None = None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        if app.config.get("SMTP_HOST"):
            state = _SmtpMailer(app)
        elif app.config.get("TEST_MAILER"):
            state = _TestMailer(app)
        else:
            state = _LoggingMailer(app)

        app.extensions["hs.portal.mailer"] = state

    @property
    def _state(self) -> _BaseMailer:
        state = current_app.extensions["hs.portal.mailer"]
        return state

    def send_email(self, user: User, template: str, subject: str, **kwargs):
        self._state.send_email(user, template, subject, **kwargs)

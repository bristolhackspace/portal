from __future__ import annotations

import smtplib
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from typing import Any

from flask import Flask, current_app, render_template
from jinja2 import TemplateNotFound

from portal.models.member import Member


class BaseMailer(ABC):
    def __init__(self, app: Flask):
        self.sender_email = app.config.get("SENDER_EMAIL", "example@example.com")

    def send_email(self, member: Member, template: str, subject: str, **kwargs):
        plain_content = render_template(f"{template}.txt.j2", member=member, **kwargs)
        try:
            html_content = render_template(f"{template}.html.j2", member=member, **kwargs)
        except TemplateNotFound:
            html_content = None

        receiver_email = formataddr((member.display_name, member.email))
        self.raw_send_email(
            self.sender_email, receiver_email, plain_content, html_content, subject
        )

    @abstractmethod
    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ): ...

    @staticmethod
    def build(app: Flask) -> "BaseMailer":
        if app.config.get("SMTP_HOST"):
            return SmtpMailer(app)
        elif app.config.get("TEST_MAILER"):
            return TestMailer(app)
        else:
            return LoggingMailer(app)


class SmtpMailer(BaseMailer):
    def __init__(self, app: Flask):
        super().__init__(app)
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


class TestMailer(BaseMailer):
    @dataclass
    class EmailCapture:
        member: Member
        template: str
        subject: str
        kwargs: dict[str, Any]

    def __init__(self, app: Flask):
        super().__init__(app)
        self.captured_emails: list[TestMailer.EmailCapture] = []

    def send_email(self, member: Member, template: str, subject: str, **kwargs):
        self.captured_emails.append(
            self.EmailCapture(
                member=member, template=template, subject=subject, kwargs=kwargs
            )
        )

    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ):
        pass


class LoggingMailer(BaseMailer):
    def __init__(self, app: Flask):
        super().__init__(app)

    def raw_send_email(
        self, sender: str, receiver: str, text: str, html: str | None, subject: str
    ):
        current_app.logger.info(
            f"Sending email from {sender} to {receiver}: {subject} \n\n {text}"
        )
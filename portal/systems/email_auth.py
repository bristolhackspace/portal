

from flask import Flask, current_app

from portal.systems.mailer import Mailer


class _State:
    def __init__(self, app: Flask):
        pass

class EmailAuth:
    def __init__(self, mailer: Mailer, app:Flask|None=None):
        self.mailer = mailer

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.mail_auth"] = _State(app)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.mail_auth"]
        return state
    
    def send_magic_email(self, email: str):
        pass
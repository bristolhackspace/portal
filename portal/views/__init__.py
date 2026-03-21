from flask import Flask
from . import login, main

def init_app(app: Flask):
    app.register_blueprint(login.bp)
    app.register_blueprint(main.bp)
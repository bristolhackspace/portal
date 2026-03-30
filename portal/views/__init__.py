from flask import Flask
from . import admin, api, login, main, discourse_connect

def init_app(app: Flask):
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(login.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(discourse_connect.bp)
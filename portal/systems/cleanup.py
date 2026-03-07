from collections.abc import Callable
from datetime import timedelta
from flask import Flask, current_app
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from functools import partial

from portal.models.rate_limit import RateLimit

class _State:
    def __init__(self, app: Flask):
        self.callbacks: dict[str, Callable[[], int]] = {}

class Cleanup:
    bp = Blueprint('cleanup', __name__)

    def __init__(self, app: Flask | None = None):
        self.db = db
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.extensions["hs.portal.cleanup"] = _State(app)
        app.register_blueprint(self.bp)

    @property
    def _state(self) -> _State:
        state = current_app.extensions["hs.portal.cleanup"]
        return state

    def register_callback(self, app: Flask, name, fn: Callable[[], int]):
        """Register a cleanup callback. `fn` must return the
        number of items it has cleaned up."""
        if name == 'all':
            raise ValueError("All is a reserved name")
        with app.app_context:
            self._state.callbacks[name] = fn

        @bp.cli.command(name)
        def cleanup_one():
            self.do_cleanup_one(name)
            
    @bp.cli.command('all')
    def cleanup_all(self):
        for cb in self._state.callbacks:
            self.do_cleanup_one(cb)

    def do_cleanup_one(self, name):
        num_items = self._state.callbacks[name]()
        current_app.logger.info(f"Cleaned up {num_items} {name} item(s)")

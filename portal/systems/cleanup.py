from collections.abc import Callable
from flask import Blueprint, Flask, current_app


class Cleanup:
    def __init__(self, app: Flask):
        self.callbacks: dict[str, Callable[[], int]] = {}

        self.bp = Blueprint('cleanup', __name__)

        app.register_blueprint(self.bp)

        @self.bp.cli.command('all')
        def cleanup_all():
            for cb in self.callbacks:
                self.do_cleanup_one(cb)

    def register_callback(self, name, fn: Callable[[], int]):
        """Register a cleanup callback. `fn` must return the
        number of items it has cleaned up."""
        if name == 'all':
            raise ValueError("All is a reserved name")
        self.callbacks[name] = fn

        @self.bp.cli.command(name)
        def cleanup_one():
            self.do_cleanup_one(name)

    def do_cleanup_one(self, name):
        num_items = self.callbacks[name]()
        current_app.logger.info(f"Cleaned up {num_items} {name} item(s)")

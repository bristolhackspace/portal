from collections.abc import Callable

from flask import Blueprint, Flask, current_app
from flask.cli import AppGroup


class Cleanup:
    def __init__(self, app: Flask):
        self.callbacks: dict[str, Callable[[], int]] = {}

        self.cli = AppGroup("cleanup")

        app.cli.add_command(self.cli)

        @self.cli.command('all')
        def cleanup_all():
            for cb in self.callbacks:
                self.do_cleanup_one(cb)

    def register_callback(self, name: str, fn: Callable[[], int]):
        """Register a cleanup callback. `fn` must return the
        number of items it has cleaned up."""
        if name == 'all':
            raise ValueError("All is a reserved name")
        self.callbacks[name] = fn

        @self.cli.command(name)
        def cleanup_one():
            self.do_cleanup_one(name)

    def do_cleanup_one(self, name: str):
        num_items = self.callbacks[name]()
        current_app.logger.info(f"Cleaned up {num_items} {name} item(s)")

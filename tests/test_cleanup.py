import functools
import pytest


@pytest.fixture
def runner(app_context):
    return app_context.test_cli_runner()


def test_do_cleanup_one(cleanup):
    cb_called = False

    def my_callback():
        nonlocal cb_called
        cb_called = True

    cleanup.register_callback("my_callback", my_callback)

    cleanup.do_cleanup_one("my_callback")

    assert cb_called == True


def test_all_reserved_name(cleanup):
    def my_callback():
        pass

    with pytest.raises(ValueError):
        cleanup.register_callback("all", my_callback)


def test_cli_do_cleanup_one(cleanup, runner):
    cb_called = False

    def my_callback():
        nonlocal cb_called
        cb_called = True

    cleanup.register_callback("my_callback", my_callback)

    result = runner.invoke(args=["cleanup", "my_callback"])

    assert cb_called == True


def test_cli_do_cleanup_all(cleanup, runner):
    called = set()

    def my_callback(i):
        called.add(i)

    for i in range(5):
        cleanup.register_callback(f"callback_{i}", functools.partial(my_callback, i))

    result = runner.invoke(args=["cleanup", "all"])

    assert called == {0, 1, 2, 3, 4}

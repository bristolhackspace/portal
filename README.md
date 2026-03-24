# Portal
Membership portal with Single-Sign-On (SSO)

## Getting started

- Create a python virtual environment.
- Inside run `pip install -e .`
- Create an `instance/conftest.toml` to configure the application (TODO list required configuration variables).

## Testing

The tests depend on a PostgreSQL database named `portal_test`. They will create all the required tables
before the tests and destroy them afterwards.

Tests are run with `pytest tests/`.
